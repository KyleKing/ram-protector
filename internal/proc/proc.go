// Package proc enumerates running processes with memory and CPU counters.
package proc

import "time"

// Proc is a point-in-time snapshot of one process.
type Proc struct {
	Created  time.Time
	Name     string
	Cmdline  string
	RSS      uint64
	CPUTotal float64
	PID      int32
	PPID     int32
}
