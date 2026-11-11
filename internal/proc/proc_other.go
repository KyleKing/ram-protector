//go:build !darwin

package proc

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

const msecPerSec = 1000

// List snapshots all visible processes. Processes that exit or refuse
// inspection mid-scan are skipped.
func List() ([]Proc, error) {
	raw, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}

	out := make([]Proc, 0, len(raw))
	for _, p := range raw {
		snap, err := read(p)
		if err != nil {
			continue
		}
		out = append(out, snap)
	}

	return out, nil
}

func read(p *process.Process) (Proc, error) {
	ppid, err := p.Ppid()
	if err != nil {
		return Proc{}, fmt.Errorf("ppid for %d: %w", p.Pid, err)
	}
	name, err := p.Name()
	if err != nil {
		return Proc{}, fmt.Errorf("name for %d: %w", p.Pid, err)
	}
	minfo, err := p.MemoryInfo()
	if err != nil {
		return Proc{}, fmt.Errorf("memory for %d: %w", p.Pid, err)
	}
	times, err := p.Times()
	if err != nil {
		return Proc{}, fmt.Errorf("times for %d: %w", p.Pid, err)
	}
	created, err := p.CreateTime()
	if err != nil {
		return Proc{}, fmt.Errorf("created for %d: %w", p.Pid, err)
	}
	cmdline, err := p.Cmdline()
	if err != nil {
		cmdline = name
	}

	return Proc{
		PID:      p.Pid,
		PPID:     ppid,
		Name:     name,
		Cmdline:  cmdline,
		RSS:      minfo.RSS,
		CPUTotal: times.User + times.System,
		Created:  time.Unix(created/msecPerSec, 0),
	}, nil
}
