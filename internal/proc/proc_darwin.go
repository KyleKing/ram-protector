//go:build darwin

package proc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

const (
	libSystemPath   = "/usr/lib/libSystem.B.dylib"
	procPIDTaskInfo = 4 // PROC_PIDTASKINFO
	nsecPerSec      = 1e9
	maxCommLen      = 15 // p_comm truncates past this; extend from argv[0]
)

// procTaskInfo mirrors XNU's struct proc_taskinfo.
type procTaskInfo struct {
	VirtualSize      uint64
	ResidentSize     uint64
	TotalUser        uint64
	TotalSystem      uint64
	ThreadsUser      uint64
	ThreadsSystem    uint64
	Policy           int32
	Faults           int32
	Pageins          int32
	CowFaults        int32
	MessagesSent     int32
	MessagesReceived int32
	SyscallsMach     int32
	SyscallsUnix     int32
	CSW              int32
	Threadnum        int32
	Numrunning       int32
	Priority         int32
}

type timebaseInfo struct {
	number uint32
	denom  uint32
}

// proc_pidinfo writes proc_taskinfo by struct size; a drifted field shifts
// every field after it.
const taskInfoSize = 96

var (
	_ [taskInfoSize - unsafe.Sizeof(procTaskInfo{})]byte
	_ [unsafe.Sizeof(procTaskInfo{}) - taskInfoSize]byte
)

var (
	procPidInfo      func(pid, flavor int32, arg uint64, buf unsafe.Pointer, size int32) int32
	machTimebaseInfo func(info *timebaseInfo) int32
	timescale        float64
	bindOnce         sync.Once
	errBind          error
)

func bind() error {
	bindOnce.Do(func() {
		h, err := purego.Dlopen(libSystemPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			errBind = fmt.Errorf("dlopen libSystem: %w", err)

			return
		}
		purego.RegisterLibFunc(&procPidInfo, h, "proc_pidinfo")
		purego.RegisterLibFunc(&machTimebaseInfo, h, "mach_timebase_info")
		var tb timebaseInfo
		machTimebaseInfo(&tb)
		timescale = float64(tb.number) / float64(tb.denom) / nsecPerSec
	})

	return errBind
}

// List snapshots all visible processes. Each process costs one proc_pidinfo
// and one kern.procargs2 sysctl; names, PPIDs, and start times come from the
// single kern.proc.all bulk read. Processes that exit or refuse inspection
// mid-scan are skipped.
func List() ([]Proc, error) {
	if err := bind(); err != nil {
		return nil, err
	}
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}

	out := make([]Proc, 0, len(kprocs))
	for i := range kprocs {
		if p, ok := read(&kprocs[i]); ok {
			out = append(out, p)
		}
	}

	return out, nil
}

func read(k *unix.KinfoProc) (Proc, bool) {
	pid := k.Proc.P_pid
	if pid == 0 {
		return Proc{}, false
	}
	var ti procTaskInfo
	//nolint:gosec // G103: proc_pidinfo writes into ti by address, its ABI
	ret := procPidInfo(pid, procPIDTaskInfo, 0, unsafe.Pointer(&ti), int32(unsafe.Sizeof(ti)))
	if ret <= 0 {
		return Proc{}, false
	}

	name := unix.ByteSliceToString(k.Proc.P_comm[:])
	args := argsOf(pid)
	if len(name) >= maxCommLen && len(args) > 0 {
		if base := filepath.Base(args[0]); strings.HasPrefix(base, name) {
			name = base
		}
	}
	cmdline := strings.Join(args, " ")
	if cmdline == "" {
		cmdline = name
	}

	return Proc{
		PID:      pid,
		PPID:     k.Eproc.Ppid,
		Name:     name,
		Cmdline:  cmdline,
		RSS:      ti.ResidentSize,
		CPUTotal: float64(ti.TotalUser+ti.TotalSystem) * timescale,
		Created: time.Unix(k.Proc.P_starttime.Sec,
			int64(k.Proc.P_starttime.Usec)*int64(time.Microsecond)),
	}, true
}

// argsOf reads argv via kern.procargs2. Layout: nargs int32, exec_path,
// padding NULs, argv[0..nargs-1], then envp — the argv loop stops at nargs so
// environment values never leak into Cmdline.
func argsOf(pid int32) []string {
	raw, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(raw) <= 4 {
		return nil
	}
	nargs := int(binary.LittleEndian.Uint32(raw[:4]))
	chunks := bytes.Split(raw[4:], []byte{0})
	i := 1
	for i < len(chunks) && len(chunks[i]) == 0 {
		i++
	}
	if nargs > len(chunks)-i {
		nargs = len(chunks) - i
	}
	args := make([]string, 0, max(nargs, 0))
	for ; nargs > 0; nargs-- {
		args = append(args, string(chunks[i]))
		i++
	}

	return args
}
