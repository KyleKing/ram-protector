// Package journal appends intervention events to a JSONL log and reads them back.
package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Candidate describes one scored process in a decision event.
type Candidate struct {
	Name   string  `json:"name"`
	Reason string  `json:"reason"`
	RSS    uint64  `json:"rss"`
	Score  float64 `json:"score"`
	PID    int32   `json:"pid"`
	CPU    float64 `json:"cpu,omitempty"`
}

// Event kinds.
const (
	KindAction   = "action"
	KindDecision = "decision"
	KindResume   = "resume"
	KindSnapshot = "snapshot"
)

// Event is one JSONL record.
type Event struct {
	Time   time.Time   `json:"time"`
	Kind   string      `json:"kind"`
	Action string      `json:"action,omitempty"`
	Name   string      `json:"name,omitempty"`
	Msg    string      `json:"msg,omitempty"`
	Top    []Candidate `json:"top,omitempty"`
	// TopCPU is the top processes by recent CPU since the previous snapshot.
	TopCPU []Candidate `json:"top_cpu,omitempty"`
	Level  int         `json:"level,omitempty"`
	Load1  float64     `json:"load1,omitempty"`
	Load5  float64     `json:"load5,omitempty"`
	Load15 float64     `json:"load15,omitempty"`
	RSS    uint64      `json:"rss,omitempty"`
	// SwapDelta is bytes of swap growth since the previous snapshot.
	SwapDelta uint64 `json:"swap_delta,omitempty"`
	PID       int32  `json:"pid,omitempty"`
	Dry       bool   `json:"dry,omitempty"`
}

const (
	dirPerm  = 0o750
	filePerm = 0o600
)

// Writer appends events to a single JSONL file.
type Writer struct {
	f  *os.File
	mu sync.Mutex
}

// New opens path for appending, creating parent directories.
func New(path string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("creating journal dir: %w", err)
	}
	//nolint:gosec // G304: path is the operator-owned log file
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return nil, fmt.Errorf("opening journal %s: %w", path, err)
	}

	return &Writer{f: f}, nil
}

// Write appends one event.
func (w *Writer) Write(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshaling event: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing journal: %w", err)
	}

	return nil
}

// Log wraps Write so callers can report failures without cluttering control flow.
func (w *Writer) Log(e Event) {
	if err := w.Write(e); err != nil {
		fmt.Fprintf(os.Stderr, "sys-guardian: journal write failed: %v\n", err)
	}
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("closing journal: %w", err)
	}

	return nil
}

// Tail returns the last n events in path, oldest first.
func Tail(path string, n int) ([]Event, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-owned log file
	if err != nil {
		return nil, fmt.Errorf("reading journal %s: %w", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	events := make([]Event, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		events = append(events, e)
	}

	return events, nil
}
