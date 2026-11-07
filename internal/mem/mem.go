// Package mem reports system-wide memory pressure on macOS.
package mem

import (
	"fmt"

	gopsmem "github.com/shirou/gopsutil/v4/mem"
	"golang.org/x/sys/unix"
)

// Status describes system memory pressure at a moment in time.
type Status struct {
	// Level is the percent of physical memory currently available (0-100),
	// from kern.memorystatus_level. Lower means more pressure.
	Level int
	// SwapUsed and SwapTotal are bytes of swap.
	SwapUsed  uint64
	SwapTotal uint64
	// PhysTotal is installed physical memory in bytes.
	PhysTotal uint64
}

// Read samples the current system memory status.
func Read() (Status, error) {
	level, err := unix.SysctlUint32("kern.memorystatus_level")
	if err != nil {
		return Status{}, fmt.Errorf("reading kern.memorystatus_level: %w", err)
	}
	vmem, err := gopsmem.VirtualMemory()
	if err != nil {
		return Status{}, fmt.Errorf("reading virtual memory: %w", err)
	}
	swap, err := gopsmem.SwapMemory()
	if err != nil {
		return Status{}, fmt.Errorf("reading swap usage: %w", err)
	}

	return Status{
		Level:     int(level),
		SwapUsed:  swap.Used,
		SwapTotal: swap.Total,
		PhysTotal: vmem.Total,
	}, nil
}
