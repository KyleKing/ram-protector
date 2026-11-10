// Package mem reports system-wide memory pressure on macOS.
package mem

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
