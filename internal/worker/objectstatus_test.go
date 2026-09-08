package worker

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/howard/scrubber/internal/metrics"
)

// TestEveryObjectStatusLabelIsDeclared reads the worker's own source for the labels
// it increments and checks each one is declared in metrics.ObjectStatuses.
//
// Written this way because the hand-maintained version did not work. A test that
// names one label -- TestTimeoutIsADeclaredObjectStatus checks "timeout" -- proves
// only that somebody remembered that day, and a later branch adding
// Objects.WithLabelValues("unresolvable") passed the whole suite while emitting a
// series that does not exist until it first fires. An alert on a series that does
// not exist looks exactly like an alert on one that is healthily zero, which is the
// failure ObjectStatuses was declared to prevent in the first place.
func TestEveryObjectStatusLabelIsDeclared(t *testing.T) {
	re := regexp.MustCompile(`Objects\.WithLabelValues\("([a-z_]+)"\)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{} // label -> file it was found in
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = name
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no Objects.WithLabelValues call sites; the pattern this test " +
			"scans for has changed and it is now checking nothing")
	}

	for label, file := range seen {
		if !slices.Contains(metrics.ObjectStatuses, label) {
			t.Errorf("%s increments scrubber_objects_total{status=%q}, which is not in "+
				"metrics.ObjectStatuses. The series is never seeded, so a dashboard shows "+
				"nothing and an alert cannot tell \"healthily zero\" from \"does not exist\".",
				file, label)
		}
	}
	t.Logf("checked %d distinct status labels against ObjectStatuses", len(seen))
}
