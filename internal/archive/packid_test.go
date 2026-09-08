package archive

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/spill"
)

// TestPackObjectIDsMatchGit checks the claim the pack report rests on: that the
// object IDs ReadPack computes are the ones git actually stores.
//
// The synthetic pack tests cannot establish this. They build their expected IDs with
// the same "<type> <size>\0<content>" formula the reader uses, so a mistake in the
// formula would satisfy both sides and pass. This is the only check that compares
// against an independent implementation, and it matters because the whole value of
// the pack report is that `git cat-file -p <id>` finds the object named in it. An ID
// that is merely self-consistent sends an operator looking for something that does
// not exist.
//
// Skips when git or a packfile is unavailable, so it is a bonus on a developer
// machine rather than a dependency of the build.
func TestPackObjectIDsMatchGit(t *testing.T) {
	const repo = "../.."
	out, err := exec.Command("git", "-C", repo, "cat-file",
		"--batch-all-objects", "--batch-check=%(objectname) %(objecttype)").Output()
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	known := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			known[f[0]] = f[1]
		}
	}

	entries, err := os.ReadDir(repo + "/.git/objects/pack")
	if err != nil {
		t.Skipf("no pack directory: %v", err)
	}
	checked, deltas := 0, 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pack") {
			continue
		}
		f, err := os.Open(repo + "/.git/objects/pack/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		objs, rerr := ReadPack(f, 1<<30, 0, spill.DefaultPolicy)
		f.Close()
		if rerr != nil {
			ClosePack(objs)
			t.Fatalf("ReadPack(%s): %v", e.Name(), rerr)
		}
		for _, o := range objs {
			if o.Delta {
				deltas++
				continue
			}
			kind, ok := known[o.Name]
			if !ok {
				t.Errorf("computed object ID %s (%s) is not an object git knows about; "+
					"a report naming it would send someone chasing nothing", o.Name, o.Type)
				continue
			}
			if kind != o.Type {
				t.Errorf("object %s: computed type %q, git says %q", o.Name, o.Type, kind)
			}
			checked++
		}
		ClosePack(objs)
	}
	if checked == 0 {
		t.Skip("no whole (non-delta) objects available to verify")
	}
	t.Logf("verified %d object IDs against git, %d deltas skipped", checked, deltas)
}
