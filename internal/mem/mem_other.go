//go:build !darwin

package mem

import "errors"

// errUnsupported is returned on non-macOS platforms, which have neither
// kern.memorystatus_level nor the pressure model the guard assumes.
var errUnsupported = errors.New("mem: unsupported platform")

// Read always fails off macOS; sys-guardian only supports darwin.
func Read() (Status, error) {
	return Status{}, errUnsupported
}
