package spill

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Reclaim deletes scratch files left behind by a previous process and reports how
// many it removed and how many bytes that freed.
//
// Spilled blobs are removed by Blob.Close, which a SIGKILL — or a SIGTERM that
// outruns the shutdown grace — never gets to run. Everything staged for the object
// in flight is then stranded: the files stay in the scratch volume with no owner
// and nothing to remove them.
//
// That is not a rare path. Rollouts, node drains, liveness blips and OOM kills all
// land mid-object, and in the pod the scratch volume is an emptyDir with a
// sizeLimit. A few interrupted objects fill it, the kubelet evicts the pod for
// ephemeral-storage, the replacement starts on the same volume and is evicted the
// same way. Reclaiming at startup is what stops that becoming a loop.
//
// Safe because the service is single-consumer and single-replica by design (the
// queue is per-pod, which is why the Deployment pins replicas to 1 and uses the
// Recreate strategy): any scratch file present before this process has staged
// anything necessarily belongs to a process that is already gone. Call it once,
// during startup, before the worker runs.
func Reclaim(dir string) (files int, freed int64, err error) {
	if dir == "" {
		dir = os.TempDir()
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("read scratch dir %s: %w", dir, err)
	}
	var firstErr error
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), tempPrefix) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		var size int64
		if info, ierr := e.Info(); ierr == nil {
			size = info.Size()
		}
		if rerr := os.Remove(path); rerr != nil {
			if firstErr == nil && !os.IsNotExist(rerr) {
				firstErr = rerr
			}
			continue
		}
		files++
		freed += size
	}
	return files, freed, firstErr
}
