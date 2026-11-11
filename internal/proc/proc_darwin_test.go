//go:build darwin

package proc_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/kyleking/sys-guardian/internal/proc"
)

func TestList_FindsSelf(t *testing.T) {
	t.Parallel()
	procs, err := proc.List()
	if err != nil {
		t.Fatal(err)
	}
	self := int32(os.Getpid()) //nolint:gosec // G115: pids fit int32
	for _, p := range procs {
		if p.PID != self {
			continue
		}
		ppid := int32(os.Getppid()) //nolint:gosec // G115: pids fit int32
		if p.RSS == 0 || p.PPID != ppid || p.Name == "" {
			t.Errorf("suspicious self snapshot: %+v", p)
		}
		if p.Created.IsZero() {
			t.Error("zero start time")
		}

		return
	}
	t.Errorf("self pid %d not listed among %d procs on %s", self, len(procs), runtime.GOOS)
}
