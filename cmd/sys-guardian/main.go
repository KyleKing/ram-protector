// Package main implements sys-guardian: Prevents CPU- and memory-hungry processes from crashing a Mac
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kyleking/sys-guardian/internal/config"
	"github.com/kyleking/sys-guardian/internal/guard"
	"github.com/kyleking/sys-guardian/internal/journal"
	"github.com/kyleking/sys-guardian/internal/mem"
	"github.com/kyleking/sys-guardian/internal/notify"
	"github.com/kyleking/sys-guardian/internal/proc"
	"github.com/kyleking/sys-guardian/internal/report"
	"github.com/kyleking/sys-guardian/internal/score"
	"github.com/kyleking/sys-guardian/internal/service"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	defaultTail = 20
	notifyTTL   = 10 * time.Second
)

var (
	errUsage  = errors.New("unknown command")
	errDarwin = errors.New("sys-guardian supports macOS only")
)

type sys struct{}

func (sys) Memory() (mem.Status, error) {
	st, err := mem.Read()
	if err != nil {
		return mem.Status{}, fmt.Errorf("memory: %w", err)
	}

	return st, nil
}

func (sys) Processes() ([]proc.Proc, error) {
	procs, err := proc.List()
	if err != nil {
		return nil, fmt.Errorf("processes: %w", err)
	}

	return procs, nil
}

func (sys) Signal(pid int32, sig syscall.Signal) error {
	if err := unix.Kill(int(pid), sig); err != nil {
		return fmt.Errorf("signal %d to %d: %w", sig, pid, err)
	}

	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "daemon"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("sys-guardian", flag.ContinueOnError)
	cfgPath := fs.String("config", config.Path(), "config file path")
	tail := fs.Int("n", defaultTail, "events to show")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parsing flags: %w", err)
	}

	switch cmd {
	case "-v", "--version", "version":
		fmt.Printf("sys-guardian %s (commit: %s, built: %s)\n", version, commit, date)
		return nil
	case "-h", "--help", "help":
		printHelp()
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	eventsPath := filepath.Join(cfg.LogDir, "events.jsonl")

	switch cmd {
	case "check":
		err = report.Check(cfg)
	case "status":
		err = report.Status(eventsPath, *tail)
	case "log":
		err = report.Log(eventsPath, *tail)
	case "install":
		return doInstall(cfg)
	case "uninstall":
		return doUninstall()
	case "daemon":
		return runDaemon(cfg, eventsPath)
	default:
		printHelp()
		return fmt.Errorf("%w %q", errUsage, cmd)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}

	return nil
}

func wrapRun(err error) error {
	if err != nil {
		return fmt.Errorf("guard: %w", err)
	}

	return nil
}

func runDaemon(cfg config.Config, eventsPath string) error {
	if runtime.GOOS != "darwin" {
		return errDarwin
	}
	jw, err := journal.New(eventsPath)
	if err != nil {
		return fmt.Errorf("opening journal: %w", err)
	}
	defer func() {
		if cerr := jw.Close(); cerr != nil {
			slog.Warn("journal close", "err", cerr)
		}
	}()

	g := guard.New(guardConfig(cfg), sys{},
		score.New(cfg.Disposable, cfg.LastResort, cfg.Never,
			score.WithStableAge(cfg.StableAge.Duration)), jw,
		notifier(cfg), alerter(cfg))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	slog.Info("sys-guardian starting", "mode", string(cfg.Mode), "log", eventsPath)

	return wrapRun(g.Run(ctx))
}

func doInstall(cfg config.Config) error {
	plist, err := service.Install(context.Background(), cfg.LogDir)
	if err != nil {
		return fmt.Errorf("installing agent: %w", err)
	}
	fmt.Printf("installed and started %s\n  plist: %s\n  mode:  %s\n", service.Label, plist, cfg.Mode)

	return nil
}

func doUninstall() error {
	if err := service.Uninstall(context.Background()); err != nil {
		return fmt.Errorf("uninstalling agent: %w", err)
	}
	fmt.Println("removed " + service.Label)

	return nil
}

func guardConfig(cfg config.Config) guard.Config {
	return guard.Config{
		Mode:              cfg.Mode,
		WarnLevel:         cfg.WarnLevel,
		CriticalLevel:     cfg.CriticalLevel,
		ResumeLevel:       cfg.ResumeLevel,
		ResumeTicks:       cfg.ResumeTicks,
		TermAfter:         cfg.TermAfter.Duration,
		KillAfter:         cfg.KillAfter.Duration,
		MemFloorBytes:     cfg.MemFloorBytes(),
		HogBytes:          cfg.HogBytes(),
		SwapSpikeBytes:    cfg.SwapSpikeBytes(),
		SwapGrowthBytes:   cfg.SwapGrowthBytes(),
		SpikeHold:         cfg.SpikeHold.Duration,
		MinPause:          cfg.MinPause.Duration,
		CPUBurnPct:        float64(cfg.CPUBurnPct),
		CPUBurnFor:        cfg.CPUBurnFor.Duration,
		LoadPerCore:       cfg.LoadPerCore,
		LoadFor:           cfg.LoadFor.Duration,
		LoadResumePerCore: cfg.LoadResume,
		PollHealthy:       cfg.PollHealthy.Duration,
		PollWarn:          cfg.PollWarn.Duration,
		PollCritical:      cfg.PollCritical.Duration,
		PausedFile:        filepath.Join(cfg.LogDir, "paused.json"),
	}
}

func notifier(cfg config.Config) func(title, sub, body string) {
	return func(title, sub, body string) {
		if !cfg.Notify || cfg.Mode == config.ModeObserve {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), notifyTTL)
			defer cancel()
			if err := notify.Send(ctx, title, sub, body); err != nil {
				slog.Warn("notification failed", "err", err)
			}
		}()
	}
}

// alertOpen keeps sticky alerts to one dialog at a time so a kill storm
// cannot pile up windows; skipped alerts are still journaled.
var alertOpen atomic.Bool

func alerter(cfg config.Config) func(title, body string) {
	return func(title, body string) {
		if !cfg.Notify || cfg.Mode == config.ModeObserve {
			return
		}
		if !alertOpen.CompareAndSwap(false, true) {
			slog.Info("alert dialog already open, skipped", "title", title)
			return
		}
		go func() {
			defer alertOpen.Store(false)
			if err := notify.Alert(title, body); err != nil {
				slog.Warn("alert failed", "err", err)
			}
		}()
	}
}

func printHelp() {
	fmt.Printf(`sys-guardian - Prevents CPU- and memory-hungry processes from crashing a Mac

Usage:
  sys-guardian [command] [options]

Commands:
  daemon      Run the monitor loop (default; launchd runs this)
  check       Print memory level and the current victim ranking, then exit
  status      Print level, agent state, and recent events
  log         Print recent journal events (-n to change count)
  install     Write and bootstrap the LaunchAgent (%s)
  uninstall   Bootout and remove the LaunchAgent

Options:
  --config    Config file path (default %s)
  -n          Event count for status/log (default %d)
  -h, --help  Show this help message
  -v, --version  Show version information

Modes (config mode = ...):
  observe     Score and journal what it WOULD do; no signals sent (default)
  protect     Pause under pressure, escalate to TERM/KILL, resume on recovery
`, service.Label, config.Path(), defaultTail)
}
