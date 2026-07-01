// Command scrubber recursively sanitizes a log bundle: it unpacks archives and
// compressed files, replaces sensitive terms in every text document inside
// (regardless of extension), and repacks everything into its original form.
//
// Safety guarantees:
//   - A bad terms file aborts the run before any data is touched (exit code 2).
//   - A corrupted, encrypted, or otherwise unreadable member is passed through
//     verbatim and flagged in the report, never half-processed.
//   - Every replacement is recorded for transparency.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/howard/scrubber/internal/config"
	"github.com/howard/scrubber/internal/pipeline"
	"github.com/howard/scrubber/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("scrubber", flag.ContinueOnError)
	var (
		termsPath   = fs.String("terms", "", "path to terms JSON file (required)")
		inPath      = fs.String("in", "", "input file or directory (required)")
		outPath     = fs.String("out", "", "output file or directory (required unless --in-place or --dry-run)")
		inPlace     = fs.Bool("in-place", false, "overwrite the input atomically instead of writing to --out")
		reportPath  = fs.String("report", "", "write the JSON run report to this path")
		auditFlag   = fs.String("audit", "full", "report detail level: off | counts | full")
		redact      = fs.Bool("redact-report", false, "store salted hashes instead of cleartext original values in the report")
		salt        = fs.String("salt", "scrubber", "salt used when --redact-report is set")
		dryRun      = fs.Bool("dry-run", false, "analyze and report without writing any output")
		maxDepth    = fs.Int("max-depth", 16, "maximum container nesting depth")
		maxRatio    = fs.Int("max-ratio", 200, "maximum decompression expansion ratio per stream")
		verbose     = fs.Bool("verbose", false, "print the per-rule breakdown to stderr")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *termsPath == "" || *inPath == "" {
		fmt.Fprintln(os.Stderr, "error: --terms and --in are required")
		fs.Usage()
		return 2
	}
	if !*dryRun && !*inPlace && *outPath == "" {
		fmt.Fprintln(os.Stderr, "error: one of --out, --in-place, or --dry-run is required")
		return 2
	}

	// 1. Load + validate config FIRST. Any problem aborts before touching data.
	matcher, err := config.Load(*termsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 2
	}

	audit, err := report.ParseAuditLevel(*auditFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 2
	}

	info, err := os.Stat(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot stat --in: %v\n", err)
		return 1
	}

	outDisplay := *outPath
	if *inPlace {
		outDisplay = *inPath + " (in-place)"
	}
	if *dryRun {
		outDisplay = "(dry-run, no output written)"
	}
	rep := report.New(*inPath, outDisplay, audit, *redact, *salt)

	eng := &pipeline.Engine{
		Matcher: matcher,
		Report:  rep,
		Limits: pipeline.Limits{
			MaxDepth:      *maxDepth,
			MaxRatio:      *maxRatio,
			MaxTotalBytes: 2 << 30,
			MaxMembers:    100000,
		},
	}

	if info.IsDir() {
		err = processDir(eng, *inPath, *outPath, *inPlace, *dryRun)
	} else {
		err = processFile(eng, *inPath, *outPath, info.Mode(), *inPlace, *dryRun)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		return 1
	}

	// Reporting / transparency output.
	if *reportPath != "" {
		if err := rep.WriteJSON(*reportPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write report: %v\n", err)
		}
	}
	fmt.Fprintln(os.Stderr, rep.Banner())
	if *verbose {
		for _, line := range rep.RuleBreakdown() {
			fmt.Fprintln(os.Stderr, line)
		}
	}
	return 0
}

func processFile(eng *pipeline.Engine, in, out string, mode fs.FileMode, inPlace, dryRun bool) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	result := eng.Process(in, data, 0)
	if dryRun {
		return nil
	}
	target := out
	if inPlace {
		target = in
	}
	return atomicWrite(target, result, mode)
}

func processDir(eng *pipeline.Engine, inDir, outDir string, inPlace, dryRun bool) error {
	if !inPlace && !dryRun && outDir == "" {
		return errors.New("directory input requires --out or --in-place")
	}
	return filepath.WalkDir(inDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			// Unreadable file: record and skip rather than aborting the whole run.
			eng.Report.Record(path, report.StatusPassthrough,
				fmt.Sprintf("could not read file: %v", err), 0, 0, nil)
			return nil
		}
		result := eng.Process(path, data, 0)
		if dryRun {
			return nil
		}
		var target string
		if inPlace {
			target = path
		} else {
			rel, relErr := filepath.Rel(inDir, path)
			if relErr != nil {
				return relErr
			}
			target = filepath.Join(outDir, rel)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
		}
		return atomicWrite(target, result, info.Mode())
	})
}

// atomicWrite writes data to a sibling temp file then renames it into place, so a
// crash mid-write can never leave a partially written (corrupt) output.
func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	if mode == 0 {
		mode = 0o644
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".scrubber-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
