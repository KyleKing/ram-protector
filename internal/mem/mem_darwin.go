//go:build darwin

package mem

import (
	"fmt"

	"github.com/shirou/gopsutil/v4/load"
	gopsmem "github.com/shirou/gopsutil/v4/mem"
	"golang.org/x/sys/unix"
)

// Read samples the current system memory status.
func Read() (Status, error) {
	level, err := unix.SysctlUint32("kern.memorystatus_level")
	if err != nil {
		return Status{}, fmt.Errorf("reading kern.memorystatus_level: %w", err)
	}
	swap, err := gopsmem.SwapMemory()
	if err != nil {
		return Status{}, fmt.Errorf("reading swap usage: %w", err)
	}
	avg, err := load.Avg()
	if err != nil {
		return Status{}, fmt.Errorf("reading load average: %w", err)
	}

	return Status{
		Level:     int(level),
		SwapUsed:  swap.Used,
		SwapTotal: swap.Total,
		Load1:     avg.Load1,
		Load5:     avg.Load5,
		Load15:    avg.Load15,
	}, nil
}
