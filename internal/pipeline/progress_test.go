package pipeline

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"testing"

	"github.com/howard/scrubber/internal/report"
)

// walkCounts runs a bundle and returns what a progress display would divide: the
// entries actually filed (the numerator the worker counts) and the member total the
// walk announced (the denominator).
func walkCounts(t *testing.T, data []byte) (done, total int) {
	t.Helper()
	rep := report.New("in", "out", report.AuditFull, false, "test")
	rep.OnMembers(func(n int) { total = n })
	rep.OnFile(func(f report.FileEntry) {
		// The worker excludes filename entries from its count for the same reason:
		// a scrubbed name is an annotation on a member, not a member.
		if f.Detail == report.DetailFilenameScrubbed {
			return
		}
		done++
	})
	eng := &Engine{Matcher: testMatcher(t), Report: rep, Limits: DefaultLimits(), ScrubNames: true}
	eng.Process("bundle", data, 0)
	return done, total
}

// zipWithDirs builds a zip that also carries explicit directory entries, which is
// what most real archivers emit.
func zipWithDirs(t *testing.T, files map[string][]byte, dirs []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, d := range dirs {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: d}); err != nil {
			t.Fatalf("zip dir: %v", err)
		}
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		mustWrite(t, w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// tarWithExtras builds a tar carrying a directory and a symlink alongside its files.
func tarWithExtras(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdrs := []*tar.Header{
		{Name: "logs/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "logs/latest.log", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "app-0.log"},
	}
	for _, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("tar header: %v", err)
		}
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644,
			Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		mustWrite(t, tw, body)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// A progress denominator that counts members the walk will never file an entry for
// is a bar that cannot reach the end.
//
// This is the bug that presented as "53 files stuck at 92%" for hours on a bundle
// that was scrubbing perfectly well: the UI draws 60 + (done/total)*35, so five
// nested zips pinned it at 92 and no amount of waiting moved it. Nesting was the
// visible trigger; directory entries do the same thing to a flat archive.
func TestProgressDenominatorMatchesEntriesFiled(t *testing.T) {
	log := []byte("2024-01-01 alice@acme.test hit 10.0.0.1 for AcmeCorp\nsecond line\n")

	files := func(n int, prefix string) map[string][]byte {
		m := map[string][]byte{}
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("%sapp-%03d.log", prefix, i)] = log
		}
		return m
	}

	// Five nested zips holding fifty leaves: the exact shape that stuck at 92%.
	deep := map[string][]byte{}
	leaves := 0
	for g := 0; g < 5; g++ {
		inner := files(10, fmt.Sprintf("g%d/", g))
		leaves += len(inner)
		deep[fmt.Sprintf("group-%d.zip", g)] = zipOf(t, inner)
	}

	cases := []struct {
		name string
		data []byte
		want int
	}{
		{"flat zip", zipOf(t, files(4, "logs/")), 4},
		{"zip in zip", zipOf(t, map[string][]byte{"bundle.zip": zipOf(t, files(4, "logs/"))}), 4},
		{"zip in zip in zip", zipOf(t, map[string][]byte{
			"outer.zip": zipOf(t, map[string][]byte{"bundle.zip": zipOf(t, files(4, "logs/"))})}), 4},
		{"five nested zips", zipOf(t, deep), leaves},
		{"zip with directory entries", zipWithDirs(t, files(3, "logs/"), []string{"logs/", "logs/old/"}), 3},
		{"tar with dir and symlink", tarWithExtras(t, files(3, "logs/")), 3},
		{"tar.gz at the top", gz(t, tarWithExtras(t, files(3, "logs/"))), 3},
		{"tar.gz member inside a zip", zipOf(t, map[string][]byte{
			"bundle.tar.gz": gz(t, tarWithExtras(t, files(3, "logs/")))}), 3},
		{"single file member is a zip", zipOf(t, map[string][]byte{
			"only.zip": zipOf(t, files(1, "logs/"))}), 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done, total := walkCounts(t, tc.data)
			if done != tc.want {
				t.Fatalf("entries filed = %d, want %d", done, tc.want)
			}
			if total != done {
				t.Errorf("files_total = %d but only %d entries are ever filed: "+
					"a bar drawn as done/total tops out at %d%% and never closes",
					total, done, 60+done*35/total)
			}
		})
	}
}

// An empty nested archive removes the member it replaced and adds nothing, so the
// total must fall rather than stay stuck one above the entries that can arrive.
func TestProgressDenominatorEmptyNestedArchive(t *testing.T) {
	log := []byte("alice@acme.test\n")
	data := zipOf(t, map[string][]byte{
		"logs/app.log": log,
		"empty.zip":    zipOf(t, map[string][]byte{}),
	})
	done, total := walkCounts(t, data)
	if done != 1 {
		t.Fatalf("entries filed = %d, want 1", done)
	}
	if total != 1 {
		t.Errorf("files_total = %d, want 1", total)
	}
}
