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
	HogMB         int      `toml:"hog_mb"`
	CriticalLevel int      `toml:"critical_level"`
	WarnLevel     int      `toml:"warn_level"`
	SwapSpikeMB   int      `toml:"swap_spike_mb"`
	SwapGrowthMB  int      `toml:"swap_growth_mb"`
	SpikeHold     Duration `toml:"spike_hold"`
	MinPause      Duration `toml:"min_pause"`
	StableAge     Duration `toml:"stable_age"`
	CPUBurnPct    int      `toml:"cpu_burn_pct"`
	CPUBurnFor    Duration `toml:"cpu_burn_for"`
	LoadFor       Duration `toml:"load_for"`
	LoadPerCore   float64  `toml:"load_per_core"`
	LoadResume    float64  `toml:"load_resume_per_core"`
	Notify        bool     `toml:"notify"`
}

var (
	errMode   = errors.New("mode must be \"observe\" or \"protect\"")
	errLevels = errors.New("levels must satisfy 0 < critical_level < warn_level < resume_level <= 100")
)

// Default threshold and timing values, documented in README.
const (
	defaultWarnLevel     = 35
	defaultCriticalLevel = 30
	defaultResumeLevel   = 55
	defaultResumeTicks   = 2
	defaultMemFloorMB    = 512
	defaultSwapSpikeMB   = 1024
	defaultSwapGrowthMB  = 128
	defaultHogMB         = 12288
	defaultCPUBurnPct    = 150
	defaultLoadPerCore   = 1.5
	defaultLoadResume    = 0.8
)

// Default returns the zero-config configuration: observe mode, journal and
// notifications on, thresholds tuned for a laptop with headroom.
func Default() Config {
	return Config{
		Mode:          ModeObserve,
		Notify:        true,
		LogDir:        filepath.Join(home(), "Library", "Logs", "sys-guardian"),
		WarnLevel:     defaultWarnLevel,
		CriticalLevel: defaultCriticalLevel,
		ResumeLevel:   defaultResumeLevel,
		ResumeTicks:   defaultResumeTicks,
		PollHealthy:   Duration{30 * time.Second},
		PollWarn:      Duration{5 * time.Second},
		PollCritical:  Duration{1 * time.Second},
		TermAfter:     Duration{2 * time.Minute},
		KillAfter:     Duration{30 * time.Second},
		MemFloorMB:    defaultMemFloorMB,
		HogMB:         defaultHogMB,
		SwapSpikeMB:   defaultSwapSpikeMB,
		SwapGrowthMB:  defaultSwapGrowthMB,
		SpikeHold:     Duration{2 * time.Minute},
		MinPause:      Duration{2 * time.Minute},
		StableAge:     Duration{30 * time.Minute},
		CPUBurnPct:    defaultCPUBurnPct,
		CPUBurnFor:    Duration{2 * time.Minute},
		LoadPerCore:   defaultLoadPerCore,
		LoadResume:    defaultLoadResume,
		LoadFor:       Duration{90 * time.Second},
	}
}

// Path is the default config file location.
func Path() string {
	return filepath.Join(home(), ".config", "sys-guardian", "config.toml")
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

// MemFloorBytes is mem_floor_mb in bytes.
func (c Config) MemFloorBytes() uint64 { return mbToBytes(c.MemFloorMB) }

// HogBytes is hog_mb in bytes.
func (c Config) HogBytes() uint64 { return mbToBytes(c.HogMB) }

// SwapSpikeBytes is swap_spike_mb in bytes.
func (c Config) SwapSpikeBytes() uint64 { return mbToBytes(c.SwapSpikeMB) }

// SwapGrowthBytes is swap_growth_mb in bytes.
func (c Config) SwapGrowthBytes() uint64 { return mbToBytes(c.SwapGrowthMB) }

const mbShift = 20

func mbToBytes(n int) uint64 {
	if n < 0 {
		n = 0
	}

	return uint64(n) << mbShift
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
