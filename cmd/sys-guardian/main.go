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
	"slices"
	"strings"
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
	mbShift     = 20
	bytesPerGiB = 1 << 30
	notifyTTL   = 10 * time.Second
	showTop     = 10
)

var errUsage = errors.New("unknown command")

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
		return printCheck(cfg)
	case "status":
		return printStatus(eventsPath, *tail)
	case "log":
		return printLog(eventsPath, *tail)
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
}

func runDaemon(cfg config.Config, eventsPath string) error {
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
		score.New(cfg.Disposable, cfg.LastResort, cfg.Never), jw,
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

func mbBytes(n int) uint64 {
	if n < 0 {
		n = 0
	}

	return uint64(n) << mbShift
}

func wrapRun(err error) error {
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}

	return nil
}

func guardConfig(cfg config.Config) guard.Config {
	return guard.Config{
		Mode:            cfg.Mode,
		WarnLevel:       cfg.WarnLevel,
		CriticalLevel:   cfg.CriticalLevel,
		ResumeLevel:     cfg.ResumeLevel,
		ResumeTicks:     cfg.ResumeTicks,
		TermAfter:       cfg.TermAfter.Duration,
		KillAfter:       cfg.KillAfter.Duration,
		MemFloorBytes:   mbBytes(cfg.MemFloorMB),
		HogBytes:        mbBytes(cfg.HogMB),
		SwapSpikeBytes:  mbBytes(cfg.SwapSpikeMB),
		SwapGrowthBytes: mbBytes(cfg.SwapGrowthMB),
		SpikeHold:       cfg.SpikeHold.Duration,
		MinPause:        cfg.MinPause.Duration,
		CPUBurnPct:      float64(cfg.CPUBurnPct),
		CPUBurnFor:      cfg.CPUBurnFor.Duration,
		PollHealthy:     cfg.PollHealthy.Duration,
		PollWarn:        cfg.PollWarn.Duration,
		PollCritical:    cfg.PollCritical.Duration,
		PausedFile:      filepath.Join(cfg.LogDir, "paused.json"),
	}
}

func notifier(cfg config.Config) func(title, body string) {
	return func(title, body string) {
		if !cfg.Notify || cfg.Mode == config.ModeObserve {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), notifyTTL)
			defer cancel()
			if err := notify.Send(ctx, title, body); err != nil {
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

type ranked struct {
	r []string
	p proc.Proc
	s float64
}

func printCheck(cfg config.Config) error {
	st, err := mem.Read()
	if err != nil {
		return fmt.Errorf("reading memory: %w", err)
	}
	procs, err := proc.List()
	if err != nil {
		return fmt.Errorf("listing processes: %w", err)
	}
	sc := score.New(cfg.Disposable, cfg.LastResort, cfg.Never)
	now := time.Now()

	rows := make([]ranked, 0, showTop)
	for _, p := range procs {
		s, reasons := sc.Score(p, now)
		if s <= 0 || p.RSS < mbBytes(cfg.MemFloorMB) {
			continue
		}
		rows = append(rows, ranked{p: p, s: s, r: reasons})
	}
	slices.SortFunc(rows, func(a, b ranked) int { return cmpFloat(b.s, a.s) })

	fmt.Printf("memory available: %d%%   swap: %.1f/%.1f GB   warn<%d crit<%d hog>%dGB\n",
		st.Level, float64(st.SwapUsed)/bytesPerGiB, float64(st.SwapTotal)/bytesPerGiB,
		cfg.WarnLevel, cfg.CriticalLevel, mbBytes(cfg.HogMB)/bytesPerGiB)
	fmt.Println("top victims by score:")
	for i, rw := range rows {
		if i >= showTop {
			break
		}
		fmt.Printf("  %6.2f  %-24s pid=%-6d rss=%.1fGB  %s\n",
			rw.s, rw.p.Name, rw.p.PID, float64(rw.p.RSS)/bytesPerGiB, strings.Join(rw.r, " "))
	}

	return nil
}

func printLog(path string, n int) error {
	events, err := journal.Tail(path, n)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no journal yet at " + path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading journal: %w", err)
	}
	for i := range events {
		fmt.Println(formatEvent(events[i]))
	}

	return nil
}

func printStatus(path string, n int) error {
	st, err := mem.Read()
	if err != nil {
		return fmt.Errorf("reading memory: %w", err)
	}
	fmt.Printf("memory available: %d%%   swap: %.1f/%.1f GB   agent running: %v\n",
		st.Level, float64(st.SwapUsed)/bytesPerGiB, float64(st.SwapTotal)/bytesPerGiB,
		service.Running(context.Background()))

	return printLog(path, n)
}

func formatEvent(e journal.Event) string {
	ts := e.Time.Format("15:04:05")
	dry := ""
	if e.Dry {
		dry = " [dry]"
	}
	switch e.Kind {
	case "decision", "action":
		return fmt.Sprintf("%s %-8s %-12s pid=%-6d %-20s lvl=%d%%%s %s",
			ts, e.Kind, e.Action, e.PID, e.Name, e.Level, dry, e.Msg)
	case "resume":
		return fmt.Sprintf("%s %-8s %s%s", ts, e.Kind, e.Msg, dry)
	default:
		dswap := ""
		if e.SwapDelta > 0 {
			dswap = fmt.Sprintf(" dswap=+%.1fGB", float64(e.SwapDelta)/bytesPerGiB)
		}

		return fmt.Sprintf("%s %-8s lvl=%d%% %s%s%s", ts, e.Kind, e.Level, e.Msg, dswap, dry)
	}
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
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
