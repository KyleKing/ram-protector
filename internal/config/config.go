// Package config loads the optional TOML config and supplies defaults.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Mode selects whether interventions are performed or only recorded.
type Mode string

// Supported modes.
const (
	ModeObserve Mode = "observe"
	ModeProtect Mode = "protect"
)

// Duration is a TOML string like "30s" decoded into a time.Duration.
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", string(text), err)
	}
	d.Duration = v

	return nil
}

// Config holds every tunable. All fields have usable defaults; the TOML file
// only overrides the keys it sets.
type Config struct {
	Mode          Mode     `toml:"mode"`
	LogDir        string   `toml:"log_dir"`
	Never         []string `toml:"extra_never"`
	LastResort    []string `toml:"extra_last_resort"`
	Disposable    []string `toml:"extra_disposable"`
	PollWarn      Duration `toml:"poll_warn"`
	ResumeTicks   int      `toml:"resume_ticks"`
	PollHealthy   Duration `toml:"poll_healthy"`
	ResumeLevel   int      `toml:"resume_level"`
	PollCritical  Duration `toml:"poll_critical"`
	TermAfter     Duration `toml:"term_after"`
	KillAfter     Duration `toml:"kill_after"`
	MemFloorMB    int      `toml:"mem_floor_mb"`
	CriticalLevel int      `toml:"critical_level"`
	WarnLevel     int      `toml:"warn_level"`
	Notify        bool     `toml:"notify"`
}

var (
	errMode   = errors.New("mode must be \"observe\" or \"protect\"")
	errLevels = errors.New("levels must satisfy 0 < critical_level < warn_level < resume_level <= 100")
)

// Default threshold and timing values, documented in README.
const (
	defaultWarnLevel     = 20
	defaultCriticalLevel = 8
	defaultResumeLevel   = 30
	defaultResumeTicks   = 2
	defaultMemFloorMB    = 512
)

// Default returns the zero-config configuration: observe mode, journal and
// notifications on, thresholds tuned for a laptop with headroom.
func Default() Config {
	return Config{
		Mode:          ModeObserve,
		Notify:        true,
		LogDir:        filepath.Join(home(), "Library", "Logs", "ram-protector"),
		WarnLevel:     defaultWarnLevel,
		CriticalLevel: defaultCriticalLevel,
		ResumeLevel:   defaultResumeLevel,
		ResumeTicks:   defaultResumeTicks,
		PollHealthy:   Duration{30 * time.Second},
		PollWarn:      Duration{5 * time.Second},
		PollCritical:  Duration{1 * time.Second},
		TermAfter:     Duration{45 * time.Second},
		KillAfter:     Duration{10 * time.Second},
		MemFloorMB:    defaultMemFloorMB,
	}
}

// Path is the default config file location.
func Path() string {
	return filepath.Join(home(), ".config", "ram-protector", "config.toml")
}

// Load reads path if it exists and overlays it on the defaults.
func Load(path string) (Config, error) {
	cfg := Default()

	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator's own --config flag
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validating %s: %w", path, err)
	}

	return cfg, nil
}

// Validate checks the invariants the guard relies on.
func (c Config) Validate() error {
	if c.Mode != ModeObserve && c.Mode != ModeProtect {
		return errMode
	}
	if 0 >= c.CriticalLevel || c.CriticalLevel >= c.WarnLevel ||
		c.WarnLevel >= c.ResumeLevel || c.ResumeLevel > 100 {
		return errLevels
	}

	return nil
}

func home() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}

	return dir
}
