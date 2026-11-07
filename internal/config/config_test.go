package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kyleking/ram-protector/internal/config"
)

func TestDefault_Validates(t *testing.T) {
	t.Parallel()
	if err := config.Default().Validate(); err != nil {
		t.Errorf("default config invalid: %v", err)
	}
}

func TestLoad_MissingFileReturnsDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if cfg.Mode != config.ModeObserve {
		t.Errorf("mode = %q, want observe", cfg.Mode)
	}
}

func TestLoad_Overlay(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.toml")
	raw := []byte(`mode = "protect"
warn_level = 25
poll_healthy = "10s"
extra_disposable = ["my-helper"]
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Mode != config.ModeProtect || cfg.WarnLevel != 25 ||
		cfg.PollHealthy.Seconds() != 10 || len(cfg.Disposable) != 1 {
		t.Errorf("overlay not applied: %+v", cfg)
	}
}

func TestLoad_Invalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		toml string
	}{
		{"bad mode", `mode = "yeet"`},
		{"inverted levels", `warn_level = 5`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.toml), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := config.Load(path); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}
