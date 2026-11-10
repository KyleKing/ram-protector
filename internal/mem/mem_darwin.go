//go:build darwin

package mem

import (
	"fmt"

	gopsmem "github.com/shirou/gopsutil/v4/mem"
	"golang.org/x/sys/unix"
)

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
