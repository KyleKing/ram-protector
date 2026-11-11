// Package score ranks processes as intervention victims.
package score

import (
	"strconv"
	"strings"
	"time"

	"github.com/kyleking/sys-guardian/internal/proc"
)

// Tier is a disposability class: how safe a process is to pause or kill.
type Tier int

// Tier values, ordered by eligibility to be targeted.
const (
	TierNever      Tier = iota // never targeted, whatever the pressure
	TierLastResort             // targeted only at critical pressure
	TierNeutral                // default tier
	TierDisposable             // restart-safe tools: watchers, LSPs, helpers
)

// Multipliers applied to a process's RSS in GiB.
const (
	multDisposable = 2.0
	multLastResort = 0.15

	multAgeFresh    = 1.4 // under 5 min
	multAgeRecent   = 1.0 // under 1 h
	multAgeSettled  = 0.8 // under 24 h
	multAgeVeteran  = 0.6
	ageFreshCutoff  = 5 * time.Minute
	ageRecentCutoff = time.Hour
	ageSettleCutoff = 24 * time.Hour

	multGrewFast  = 1.5
	multGrew      = 1.2
	multShrank    = 0.7
	grewFastBytes = 512 << 20
	grewBytes     = 128 << 20
	shrankBytes   = 128 << 20
	multNoPrev    = 1.05 // unseen process: could be the fresh runaway

	multCPUBurning = 1.3 // >150% recent CPU
	multCPUBusy    = 1.15
	multCPUIdle    = 0.9 // <2%: a big sleeper still holds RAM
	cpuBurning     = 150.0
	cpuBusy        = 80.0
	cpuIdle        = 2.0
	percent        = 100.0
)

const (
	bytesPerGiB = 1 << 30
	mbShift     = 20
)

// Built-in substrings matched case-insensitively against name and command
// line. Disposable processes are safe to stop: they respawn or lose nothing.
var (
	builtinNever = []string{
		"sys-guardian", "sys-guardian", "launchd", "kernel_task", "windowserver", "loginwindow",
		"cfprefsd", "distnoted", "usernoted", "opendirectoryd", "diskarbitrationd",
		"notifyd", "powerd", "systemstats",
		// A stopped VM frees nothing and trips Docker's watchdog — pause is a
		// kill with extra delay.
		"com.apple.virtualization",
	}
	builtinDisposable = []string{
		"tsc", "tsserver", "eslint", "prettier", "biome", "jest", "vitest",
		"webpack", "vite", "esbuild", "swc", "rollup", "parcel", "watchman",
		"nodemon", "tsx", "ts-node", "turbo", "rust-analyzer", "gopls",
		"pyright", "clangd", "sourcekit-lsp", "typescript-language-server",
		"deno", "rustc", "cargo", "clang", "swift-frontend",
		" helper", "--type=renderer", "--type=gpu",
	}
	builtinLastResort = []string{
		"claude", "codex", "devin", "aider", "gemini",
		"wezterm", "iterm", "terminal", "ghostty", "kitty", "alacritty",
		"tmux", "screen", "code", "cursor", "zed", "sublime", "emacs",
		"nvim", "vim", "google chrome", "safari", "firefox", "arc",
		"brave", "edge", "finder", "dock", "systemuiserver", "controlcenter",
		"slack", "discord", "zoom", "spotify", "signal", "messages", "mail",
	}
)

// platformPrefixes mark Apple platform binaries (by argv[0] path) as
// last-resort: pausing a system daemon buys little, but at critical pressure
// nothing is off-limits. Prefixes, not substrings, so user paths such as
// /opt/homebrew/sbin stay neutral.
var platformPrefixes = []string{
	"/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/",
}

type sample struct {
	at  time.Time
	rss uint64
	cpu float64
}

// Scorer keeps the current and previous snapshot per PID so Score can see
// growth and recent CPU since the last tick.
type Scorer struct {
	cur        map[int32]sample
	prev       map[int32]sample
	disposable []string
	lastResort []string
	never      []string
	stableAge  time.Duration
}

// Option configures a Scorer.
type Option func(*Scorer)

// WithStableAge treats processes older than d as established: they are
// last-resort victims whatever their pattern tier. Zero disables.
func WithStableAge(d time.Duration) Option {
	return func(s *Scorer) { s.stableAge = d }
}

// New merges the built-in tier lists with user extras.
func New(extraDisposable, extraLastResort, extraNever []string, opts ...Option) *Scorer {
	lower := func(in []string) []string {
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = strings.ToLower(s)
		}

		return out
	}

	sc := &Scorer{
		disposable: append(lower(builtinDisposable), lower(extraDisposable)...),
		lastResort: append(lower(builtinLastResort), lower(extraLastResort)...),
		never:      append(lower(builtinNever), lower(extraNever)...),
		cur:        make(map[int32]sample),
		prev:       make(map[int32]sample),
	}
	for _, opt := range opts {
		opt(sc)
	}

	return sc
}

// TierOf classifies a process. Narrower guarantees win: never beats
// disposable beats last-resort.
func (s *Scorer) TierOf(p proc.Proc) Tier {
	text := strings.ToLower(p.Name + " " + p.Cmdline)
	if matches(s.never, text) {
		return TierNever
	}
	if isAppBundle(p) || s.isStable(p) {
		return TierLastResort
	}
	if matches(s.disposable, text) {
		return TierDisposable
	}
	if matches(s.lastResort, text) || isPlatform(p) {
		return TierLastResort
	}

	return TierNeutral
}

// A paused app-bundle process dies to its parent's watchdog or beachballs the
// GUI, so a stop is a kill — app processes are only victims at critical.
func isAppBundle(p proc.Proc) bool {
	return strings.Contains(p.Cmdline, ".app/")
}

// An established process holds state a respawn cannot restore, so it only
// becomes a victim at critical pressure.
func (s *Scorer) isStable(p proc.Proc) bool {
	return s.stableAge > 0 && !p.Created.IsZero() && time.Since(p.Created) >= s.stableAge
}

func isPlatform(p proc.Proc) bool {
	for _, prefix := range platformPrefixes {
		if strings.HasPrefix(p.Cmdline, prefix) {
			return true
		}
	}

	return false
}

// Observe records this snapshot for growth and CPU deltas, pruning stale PIDs.
// The prior snapshot is kept so Score compares one tick back, never a sample
// to itself.
func (s *Scorer) Observe(procs []proc.Proc, now time.Time) {
	seen := make(map[int32]struct{}, len(procs))
	for _, p := range procs {
		seen[p.PID] = struct{}{}
		if c, ok := s.cur[p.PID]; ok {
			s.prev[p.PID] = c
		}
		s.cur[p.PID] = sample{rss: p.RSS, cpu: p.CPUTotal, at: now}
	}
	for pid := range s.cur {
		if _, ok := seen[pid]; !ok {
			delete(s.cur, pid)
			delete(s.prev, pid)
		}
	}
}

// Score ranks p as a victim: bigger, fresher, faster-growing, CPU-burning,
// disposable processes score highest. TierNever returns a negative score.
// The reasons describe every multiplier applied, for the journal.
func (s *Scorer) Score(p proc.Proc, now time.Time) (float64, []string) {
	tier := s.TierOf(p)
	if tier == TierNever {
		return -1, []string{"tier=never"}
	}

	score := float64(p.RSS) / bytesPerGiB
	reasons := make([]string, 0, 4)

	switch tier {
	case TierDisposable:
		score *= multDisposable
		reasons = append(reasons, "tier=disposable")
	case TierLastResort:
		score *= multLastResort
		reasons = append(reasons, "tier=last_resort")
	case TierNeutral, TierNever:
	}

	mult, reason := ageFactor(now.Sub(p.Created))
	score *= mult
	reasons = append(reasons, reason)

	mult, reason = s.growthFactor(p, now)
	score *= mult
	reasons = append(reasons, reason)

	return score, reasons
}

func ageFactor(age time.Duration) (float64, string) {
	switch {
	case age < ageFreshCutoff:
		return multAgeFresh, "age<5m"
	case age < ageRecentCutoff:
		return multAgeRecent, "age<1h"
	case age < ageSettleCutoff:
		return multAgeSettled, "age<24h"
	default:
		return multAgeVeteran, "age>=24h"
	}
}

// RecentCPU reports p's CPU usage between the previous and current
// snapshots, or false until a second observation exists.
func (s *Scorer) RecentCPU(p proc.Proc, now time.Time) (float64, bool) {
	prev, ok := s.prev[p.PID]
	if !ok || !prev.at.Before(now) {
		return 0, false
	}
	elapsed := now.Sub(prev.at).Seconds()
	if elapsed <= 0 {
		return 0, false
	}

	return (p.CPUTotal - prev.cpu) / elapsed * percent, true
}

func (s *Scorer) growthFactor(p proc.Proc, now time.Time) (float64, string) {
	prev, ok := s.prev[p.PID]
	if !ok || !prev.at.Before(now) {
		return multNoPrev, "no_prev"
	}

	delta, grew := rssDelta(p.RSS, prev.rss)
	mult, reason := growthMult(delta, grew), growthReason(delta, grew)

	if recentCPU, ok := s.RecentCPU(p, now); ok {
		switch {
		case recentCPU > cpuBurning:
			mult *= multCPUBurning
		case recentCPU > cpuBusy:
			mult *= multCPUBusy
		case recentCPU < cpuIdle:
			mult *= multCPUIdle
		}
		reason += " cpu=" + strconv.Itoa(int(recentCPU)) + "%"
	}

	return mult, reason
}

// rssDelta returns the absolute RSS change and whether it grew.
func rssDelta(cur, prev uint64) (uint64, bool) {
	if cur >= prev {
		return cur - prev, true
	}

	return prev - cur, false
}

func growthMult(delta uint64, grew bool) float64 {
	switch {
	case grew && delta > grewFastBytes:
		return multGrewFast
	case grew && delta > grewBytes:
		return multGrew
	case !grew && delta > shrankBytes:
		return multShrank
	default:
		return 1.0
	}
}

func growthReason(delta uint64, grew bool) string {
	if delta <= grewBytes {
		return "steady"
	}
	if !grew {
		return "d_rss=-" + strconv.FormatUint(delta>>mbShift, 10) + "MB"
	}

	return "d_rss=" + strconv.FormatUint(delta>>mbShift, 10) + "MB"
}

func matches(list []string, text string) bool {
	for _, pat := range list {
		if strings.Contains(text, pat) {
			return true
		}
	}

	return false
}
