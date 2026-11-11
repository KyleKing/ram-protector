//go:build darwin

package proc

import (
	"os"
	"runtime"
	"testing"
	"unsafe"
)

func TestTaskInfoLayout(t *testing.T) {
	// proc_pidinfo fills proc_taskinfo by size; a drifted field offsets
	// everything after it.
	if got, want := unsafe.Sizeof(procTaskInfo{}), uintptr(96); got != want {
		t.Fatalf("procTaskInfo size = %d, want %d (XNU struct proc_taskinfo)", got, want)
	}
}

func TestList_FindsSelf(t *testing.T) {
	procs, err := List()
	if err != nil {
		t.Fatal(err)
	}
	self := int32(os.Getpid())
	for _, p := range procs {
		if p.PID != self {
			continue
		}
		if p.RSS == 0 || p.PPID != int32(os.Getppid()) || p.Name == "" {
			t.Errorf("suspicious self snapshot: %+v", p)
		}
		if p.Created.IsZero() {
			t.Error("zero start time")
		}
		return
	}
	t.Errorf("self pid %d not listed among %d procs on %s", self, len(procs), runtime.GOOS)
}
