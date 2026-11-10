// Package guard evaluates memory pressure each tick and pauses, resumes, or
// kills the worst offender before the machine wedges.
package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/kyleking/sys-guardian/internal/config"
	"github.com/kyleking/sys-guardian/internal/journal"
	"github.com/kyleking/sys-guardian/internal/mem"
	"github.com/kyleking/sys-guardian/internal/proc"
	"github.com/kyleking/sys-guardian/internal/score"
)

const (
	topN           = 5
	kindAction     = "action"
	kindDecision   = "decision"
	verbStop       = "stop"
	verbWouldStop  = "would_stop"
	dirPerm        = 0o750
	filePerm       = 0o600
	gibShift       = 30
	killedCooldown = 2 * time.Minute
)

// Sys is the boundary the guard acts through; tests substitute a fake.
type Sys interface {
	Memory() (mem.Status, error)
	Processes() ([]proc.Proc, error)
	Signal(pid int32, sig syscall.Signal) error
}

// Config tunes the intervention ladder.
type Config struct {
	Mode          config.Mode
	PausedFile    string
	WarnLevel     int
	CriticalLevel int
	ResumeLevel   int
	ResumeTicks   int
	TermAfter     time.Duration
	KillAfter     time.Duration
	MemFloorBytes uint64
	// SwapSpikeBytes treats swap growing this much between ticks as warn-level
	// pressure; memorystatus_level lags fast leaks on macOS. Zero disables it.
	SwapSpikeBytes uint64
	// SwapGrowthBytes is the per-tick swap growth that counts as the storm
	// still running; spike-held victims escalate only while it holds.
	// Zero disables it.
	SwapGrowthBytes uint64
	// SpikeHold keeps a swap spike counting as pressure for this long after
	// the last spike (renewed by continued growth), so its victims are not
	// resumed mid-storm. Zero disables it.
	SpikeHold time.Duration
	// HogBytes pauses a disposable process over this RSS even when the system
	// is healthy; a slow leak otherwise never trips the pressure triggers.
	// Zero disables it.
	HogBytes uint64
	// CPUBurnPct and CPUBurnFor pause a disposable process sustaining more
	// than this %CPU for this long even when memory is healthy.
	// Either zero disables it.
	CPUBurnPct float64
	CPUBurnFor time.Duration
	// MinPause is the shortest time a victim stays stopped; a recovery faster
	// than this reads as flapping, not relief. Zero disables it.
	MinPause     time.Duration
	PollHealthy  time.Duration
	PollWarn     time.Duration
	PollCritical time.Duration
}

type held struct {
	created   time.Time
	stoppedAt time.Time
	termAt    time.Time
	name      string
	parent    string
	cmdline   string
	tree      []int32
	rss       uint64
	hog       bool
}

type pausedRecord struct {
	Created   time.Time `json:"created"`
	StoppedAt time.Time `json:"stopped_at"`
	Name      string    `json:"name"`
	Parent    string    `json:"parent,omitempty"`
	Cmdline   string    `json:"cmdline,omitempty"`
	RSS       uint64    `json:"rss"`
	PID       int32     `json:"pid"`
	Hog       bool      `json:"hog,omitempty"`
}

// Option customizes a Guard; tests use these to inject a clock.
type Option func(*Guard)

// WithNow overrides the wall clock.
func WithNow(now func() time.Time) Option {
	return func(g *Guard) { g.now = now }
}

// Guard runs the evaluate/act loop.
type Guard struct {
	sys       Sys
	scorer    *score.Scorer
	journal   *journal.Writer
	notify    func(title, body string)
	alert     func(title, body string)
	held      map[int32]*held
	blocked   map[int32]bool
	killed    map[int32]time.Time
	burnSince map[int32]time.Time
	now       func() time.Time
	lastSpike time.Time
	cfg       Config
	healthy   int
	prevSwap  uint64
}

// New builds a guard and, in protect mode, re-adopts processes a previous run
// paused but never resumed.
func New(cfg Config, sys Sys, sc *score.Scorer, jw *journal.Writer, notify, alert func(title, body string),
	opts ...Option,
) *Guard {
	if notify == nil {
		notify = func(string, string) {}
	}
	if alert == nil {
		alert = notify
	}
	g := &Guard{
		cfg:       cfg,
		sys:       sys,
		scorer:    sc,
		journal:   jw,
		notify:    notify,
		alert:     alert,
		held:      map[int32]*held{},
		blocked:   map[int32]bool{},
		killed:    map[int32]time.Time{},
		burnSince: map[int32]time.Time{},
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(g)
	}
	g.adopt()

	return g
}

// Run ticks until ctx is canceled, adapting the poll interval to pressure.
// On exit it resumes everything it paused: a frozen process outliving the
// daemon is a worse outcome than the leak it was stopped for.
func (g *Guard) Run(ctx context.Context) error {
	defer g.resumeAll(nil)

	interval := g.cfg.PollHealthy
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
		interval = g.Tick()
	}
}

// Held names the victims currently paused, keyed by PID.
func (g *Guard) Held() map[int32]string {
	out := make(map[int32]string, len(g.held))
	for pid, h := range g.held {
		out[pid] = h.name
	}

	return out
}

// Tick runs one evaluate/act pass and returns the next poll interval.
func (g *Guard) Tick() time.Duration {
	st, err := g.sys.Memory()
	if err != nil {
		slog.Warn("memory read failed", "err", err)
		return g.cfg.PollWarn
	}
	procs, err := g.sys.Processes()
	if err != nil {
		slog.Warn("process list failed", "err", err)
		return g.cfg.PollWarn
	}
	now := g.now()
	for pid, t := range g.killed {
		if now.Sub(t) >= killedCooldown {
			delete(g.killed, pid)
		}
	}
	g.scorer.Observe(procs, now)
	g.trackBurn(procs, now)
	g.dropDead(procs)

	var swapDelta uint64
	if g.prevSwap > 0 && st.SwapUsed > g.prevSwap {
		swapDelta = st.SwapUsed - g.prevSwap
	}
	g.prevSwap = st.SwapUsed
	spikeNow, growing := g.swapSignals(swapDelta, now)
	low := st.Level < g.cfg.WarnLevel
	pressured := low || g.inSpikeWindow(now)
	g.journalSnapshot(st, procs, now, swapDelta)
	g.maybeResume(st, procs, now, pressured)

	g.escalate(now, procs, low, growing && pressured)
	if low || spikeNow {
		g.maybePause(st, procs, now, spikeNow)
	} else if !g.maybePauseHog(st, procs, now) {
		g.maybePauseBurn(st, procs, now)
	}

	return g.intervalFor(st, pressured)
}

func (g *Guard) intervalFor(st mem.Status, pressured bool) time.Duration {
	switch {
	case st.Level < g.cfg.CriticalLevel:
		return g.cfg.PollCritical
	case len(g.held) > 0 || pressured:
		return g.cfg.PollWarn
	default:
		return g.cfg.PollHealthy
	}
}

// swapSignals classifies this tick's swap delta. A spike opens (or renews)
// the pressure window; growth renews it only while one is already open.
func (g *Guard) swapSignals(swapDelta uint64, now time.Time) (bool, bool) {
	spikeNow := g.cfg.SwapSpikeBytes > 0 && swapDelta >= g.cfg.SwapSpikeBytes
	growing := g.cfg.SwapGrowthBytes > 0 && swapDelta >= g.cfg.SwapGrowthBytes
	if spikeNow || (growing && g.inSpikeWindow(now)) {
		g.lastSpike = now
	}

	return spikeNow, growing
}

// maybeResume counts unpressured healthy reads and releases held victims
// once enough land in a row.
func (g *Guard) maybeResume(st mem.Status, procs []proc.Proc, now time.Time, pressured bool) {
	if st.Level >= g.cfg.ResumeLevel && !pressured {
		g.healthy++
	} else {
		g.healthy = 0
	}
	if len(g.held) > 0 && g.healthy >= g.cfg.ResumeTicks {
		g.resumeAll(g.keepPaused(procs, now))
	}
}

// inSpikeWindow reports whether a swap spike (or the growth continuing one)
// is still fresh enough to count as pressure.
func (g *Guard) inSpikeWindow(now time.Time) bool {
	return g.cfg.SpikeHold > 0 && now.Sub(g.lastSpike) < g.cfg.SpikeHold
}

// keepPaused returns held victims that must stay stopped on a resume pass:
// hogs still over their ceiling plus anything younger than MinPause.
func (g *Guard) keepPaused(procs []proc.Proc, now time.Time) map[int32]bool {
	keep := g.stillOverCap(procs)
	for pid, h := range g.held {
		if now.Sub(h.stoppedAt) < g.cfg.MinPause {
			if keep == nil {
				keep = map[int32]bool{}
			}
			keep[pid] = true
		}
	}

	return keep
}

// trackBurn maintains when each process first crossed the CPU burn
// threshold; the timer resets the tick a process cools off or exits.
func (g *Guard) trackBurn(procs []proc.Proc, now time.Time) {
	if g.cfg.CPUBurnPct <= 0 {
		return
	}
	burning := make(map[int32]bool, len(g.burnSince))
	for _, p := range procs {
		if cpu, ok := g.scorer.RecentCPU(p, now); ok && cpu > g.cfg.CPUBurnPct {
			burning[p.PID] = true
			if _, seen := g.burnSince[p.PID]; !seen {
				g.burnSince[p.PID] = now
			}
		}
	}
	for pid := range g.burnSince {
		if !burning[pid] {
			delete(g.burnSince, pid)
		}
	}
}

// escalate advances held victims along pause -> TERM -> KILL while pressure
// persists: a low memory level, or swap still growing inside a spike window.
// Between warn and resume they stay paused, untouched — except hogs, which
// advance while they remain over the ceiling: a paused process frees almost
// nothing, so holding it forever protects nothing.
func (g *Guard) escalate(now time.Time, procs []proc.Proc, low, growing bool) {
	overCap := g.stillOverCap(procs)
	for pid, h := range g.held {
		if h.hog {
			if !overCap[pid] {
				continue
			}
		} else if !low && !growing {
			continue
		}
		if now.Sub(h.stoppedAt) < g.cfg.TermAfter {
			continue
		}
		reason := "pressure stayed below warn"
		switch {
		case h.hog:
			reason = "stayed over the process ceiling"
		case !low:
			reason = "swap kept growing"
		}
		if h.termAt.IsZero() {
			h.termAt = now
			g.signalTree(h, syscall.SIGTERM, "term")
			g.journal.Log(journal.Event{
				Time: now, Kind: kindAction, Action: "term",
				PID: pid, Name: h.name, RSS: h.rss, Msg: h.detail(reason, now),
			})

			continue
		}
		if now.Sub(h.termAt) >= g.cfg.KillAfter {
			g.signalTree(h, syscall.SIGKILL, "kill")
			detail := h.detail(reason, now)
			g.journal.Log(journal.Event{
				Time: now, Kind: kindAction, Action: "kill",
				PID: pid, Name: h.name, RSS: h.rss, Msg: detail,
			})
			g.alert("sys-guardian", fmt.Sprintf("killed %s (%s) — %s", h.name, gib(h.rss), detail))
			for _, tpid := range h.tree {
				g.killed[tpid] = now
			}
			delete(g.held, pid)
		}
	}
	g.savePaused()
}

// stillOverCap returns held hogs whose RSS still exceeds the ceiling; they
// stay paused through recovery and keep escalating.
func (g *Guard) stillOverCap(procs []proc.Proc) map[int32]bool {
	if len(g.held) == 0 || g.cfg.HogBytes == 0 {
		return nil
	}
	rss := make(map[int32]uint64, len(procs))
	for _, p := range procs {
		rss[p.PID] = p.RSS
	}
	keep := map[int32]bool{}
	for pid, h := range g.held {
		if h.hog && rss[pid] >= g.cfg.HogBytes {
			keep[pid] = true
		}
	}

	return keep
}

// dryVerb renders the action journal verb for the current mode.
func (g *Guard) dryVerb() (string, bool) {
	if g.cfg.Mode == config.ModeObserve {
		return verbWouldStop, true
	}

	return verbStop, false
}

// maybePause picks the single worst offender and SIGSTOPs it with its tree.
func (g *Guard) maybePause(st mem.Status, procs []proc.Proc, now time.Time, spikeNow bool) {
	victim, top := g.pickVictim(st, procs)
	verb, dry := g.dryVerb()
	ev := journal.Event{Time: now, Kind: kindDecision, Level: st.Level, Dry: dry, Top: top}
	if spikeNow && st.Level >= g.cfg.WarnLevel {
		ev.Msg = "trigger=swap_spike"
	}
	if victim != nil {
		ev.Action = verb
		ev.PID = victim.p.PID
		ev.Name = victim.p.Name
		ev.RSS = victim.p.RSS
	}
	g.journal.Log(ev)

	if victim == nil {
		return
	}
	msg := fmt.Sprintf("paused %s (%s), %d%% memory free. Will resume when clear.",
		victim.p.Name, gib(victim.p.RSS), st.Level)
	g.pauseTree(victim, procs, now, false, msg)
}

// maybePauseHog freezes a disposable process over the RSS ceiling while the
// system is otherwise healthy. Reports whether a victim was paused.
func (g *Guard) maybePauseHog(st mem.Status, procs []proc.Proc, now time.Time) bool {
	if g.cfg.HogBytes == 0 {
		return false
	}
	victim, top := g.pickDisposable(procs, now, func(p proc.Proc) bool {
		return p.RSS >= g.cfg.HogBytes
	})
	if victim == nil {
		return false
	}
	verb, dry := g.dryVerb()
	g.journal.Log(journal.Event{
		Time: now, Kind: kindDecision, Level: st.Level, Dry: dry, Top: top,
		Action: verb, PID: victim.p.PID, Name: victim.p.Name, RSS: victim.p.RSS,
		Msg: "trigger=hog_ceiling",
	})
	msg := fmt.Sprintf("paused %s (%s) — over the process ceiling.",
		victim.p.Name, gib(victim.p.RSS))
	g.pauseTree(victim, procs, now, true, msg)

	return true
}

// maybePauseBurn freezes a disposable process that has sustained the CPU
// burn threshold for CPUBurnFor while the system is otherwise healthy.
// Reports whether a victim was paused.
func (g *Guard) maybePauseBurn(st mem.Status, procs []proc.Proc, now time.Time) bool {
	if g.cfg.CPUBurnPct <= 0 || g.cfg.CPUBurnFor <= 0 {
		return false
	}
	victim, top := g.pickDisposable(procs, now, func(p proc.Proc) bool {
		since, ok := g.burnSince[p.PID]
		return ok && now.Sub(since) >= g.cfg.CPUBurnFor
	})
	if victim == nil {
		return false
	}
	verb, dry := g.dryVerb()
	cpu, _ := g.scorer.RecentCPU(victim.p, now)
	g.journal.Log(journal.Event{
		Time: now, Kind: kindDecision, Level: st.Level, Dry: dry, Top: top,
		Action: verb, PID: victim.p.PID, Name: victim.p.Name, RSS: victim.p.RSS,
		Msg: fmt.Sprintf("trigger=cpu_burn cpu=%d%%", int(cpu)),
	})
	msg := fmt.Sprintf("paused %s — burning %.0f%% CPU for %s.",
		victim.p.Name, cpu, g.cfg.CPUBurnFor)
	g.pauseTree(victim, procs, now, false, msg)

	return true
}

// pauseTree holds the victim, SIGSTOPs its tree, notifies, and persists.
// A victim whose stop failed is dropped rather than tracked as held.
func (g *Guard) pauseTree(victim *scored, procs []proc.Proc, now time.Time, hog bool, msg string) {
	h := &held{
		name: victim.p.Name, rss: victim.p.RSS, created: victim.p.Created,
		parent: parentName(victim.p.PPID, procs), cmdline: victim.p.Cmdline,
		stoppedAt: now, tree: treeOf(victim.p.PID, procs), hog: hog,
	}
	g.held[victim.p.PID] = h
	g.signalTree(h, syscall.SIGSTOP, "stop")
	if g.blocked[victim.p.PID] {
		delete(g.held, victim.p.PID)
		return
	}
	g.notify("sys-guardian", msg)
	g.savePaused()
}

type scored struct {
	reasons []string
	p       proc.Proc
	score   float64
}

// detail renders the diagnostic line shared by the journal and kill alerts:
// trigger reason, what spawned the process, its age, and the command tail.
func (h *held) detail(reason string, now time.Time) string {
	d := reason
	if h.parent != "" {
		d += "; parent=" + h.parent
	}
	if !h.created.IsZero() {
		d += "; age=" + now.Sub(h.created).Truncate(time.Second).String()
	}
	if h.cmdline != "" {
		d += "; cmd=" + tailOf(h.cmdline)
	}

	return d
}

func parentName(ppid int32, procs []proc.Proc) string {
	for _, p := range procs {
		if p.PID == ppid {
			return p.Name
		}
	}

	return ""
}

const cmdTail = 140

// tailOf keeps the end of a command line: the script path and project args
// that identify which job it was, not the leading interpreter boilerplate.
func tailOf(cmdline string) string {
	if len(cmdline) <= cmdTail {
		return cmdline
	}

	return "…" + cmdline[len(cmdline)-cmdTail:]
}

func (g *Guard) heldPIDs() map[int32]bool {
	heldSet := map[int32]bool{}
	for _, h := range g.held {
		for _, pid := range h.tree {
			heldSet[pid] = true
		}
	}

	return heldSet
}

func topCandidates(cands []scored) []journal.Candidate {
	top := make([]journal.Candidate, 0, topN)
	for i, c := range cands {
		if i >= topN {
			break
		}
		top = append(top, journal.Candidate{
			PID: c.p.PID, Name: c.p.Name,
			RSS: c.p.RSS, Score: c.score, Reason: strings.Join(c.reasons, " "),
		})
	}

	return top
}

// pickVictim scores eligible processes and returns the best plus the top-N
// leaderboard for the journal.
func (g *Guard) pickVictim(st mem.Status, procs []proc.Proc) (*scored, []journal.Candidate) {
	heldSet := g.heldPIDs()
	cands := make([]scored, 0, len(procs))
	now := g.now()
	for _, p := range procs {
		if heldSet[p.PID] || g.blocked[p.PID] || !g.killed[p.PID].IsZero() ||
			p.RSS < g.cfg.MemFloorBytes {
			continue
		}
		s, reasons := g.scorer.Score(p, now)
		tier := g.scorer.TierOf(p)
		if s < 0 || (tier == score.TierLastResort && st.Level >= g.cfg.CriticalLevel) {
			continue
		}
		cands = append(cands, scored{p: p, score: s, reasons: reasons})
	}
	slices.SortFunc(cands, func(a, b scored) int {
		return cmpFloat(b.score, a.score)
	})

	top := topCandidates(cands)
	if len(cands) == 0 {
		return nil, top
	}

	return &cands[0], top
}

// pickDisposable scores disposable processes that satisfy eligible; only
// they are eligible while the system is healthy.
func (g *Guard) pickDisposable(procs []proc.Proc, now time.Time,
	eligible func(proc.Proc) bool,
) (*scored, []journal.Candidate) {
	heldSet := g.heldPIDs()
	cands := make([]scored, 0, len(procs))
	for _, p := range procs {
		if heldSet[p.PID] || g.blocked[p.PID] || !g.killed[p.PID].IsZero() ||
			p.RSS < g.cfg.MemFloorBytes || !eligible(p) {
			continue
		}
		if g.scorer.TierOf(p) != score.TierDisposable {
			continue
		}
		s, reasons := g.scorer.Score(p, now)
		if s < 0 {
			continue
		}
		cands = append(cands, scored{p: p, score: s, reasons: reasons})
	}
	slices.SortFunc(cands, func(a, b scored) int {
		return cmpFloat(b.score, a.score)
	})

	top := topCandidates(cands)
	if len(cands) == 0 {
		return nil, top
	}

	return &cands[0], top
}

// signal sends sig, or only records it in observe mode. EPERM marks the PID
// unkillable for the rest of the run.
func (g *Guard) signal(pid int32, sig syscall.Signal, act, name string) {
	if g.cfg.Mode == config.ModeObserve {
		g.journal.Log(journal.Event{Time: g.now(), Kind: kindAction, Action: act, PID: pid, Name: name, Dry: true})

		return
	}
	if err := g.sys.Signal(pid, sig); err != nil {
		if errors.Is(err, syscall.EPERM) {
			g.blocked[pid] = true
		}
		if !errors.Is(err, syscall.ESRCH) {
			g.journal.Log(journal.Event{
				Time: g.now(), Kind: kindAction, Action: act,
				PID: pid, Name: name, Msg: err.Error(),
			})
		}

		return
	}
	g.journal.Log(journal.Event{Time: g.now(), Kind: kindAction, Action: act, PID: pid, Name: name})
}

// signalTree stops parent-first so it cannot fork during the walk, but terms
// and kills deepest-first so children are not orphaned into launchd.
func (g *Guard) signalTree(h *held, sig syscall.Signal, act string) {
	order := h.tree
	if sig != syscall.SIGSTOP {
		order = slices.Clone(h.tree)
		slices.Reverse(order)
	}
	for _, pid := range order {
		g.signal(pid, sig, act, h.name)
	}
}

// resumeAll SIGCONTs every held tree except those in keep and clears their
// state. Run passes nil: nothing stays frozen when the daemon exits.
func (g *Guard) resumeAll(keep map[int32]bool) {
	if len(g.held) == 0 {
		return
	}
	names := make([]string, 0, len(g.held))
	for pid, h := range g.held {
		if keep[pid] {
			continue
		}
		for _, tpid := range h.tree {
			g.signal(tpid, syscall.SIGCONT, "cont", h.name)
		}
		names = append(names, fmt.Sprintf("%s(%d)", h.name, pid))
		delete(g.held, pid)
	}
	if len(names) == 0 {
		return
	}
	g.healthy = 0
	g.journal.Log(journal.Event{Time: g.now(), Kind: "resume", Msg: strings.Join(names, ", ")})
	g.notify("sys-guardian", "resumed "+strings.Join(names, ", "))
	g.savePaused()
}

// dropDead forgets held entries whose whole tree has exited.
func (g *Guard) dropDead(procs []proc.Proc) {
	alive := make(map[int32]bool, len(procs))
	for _, p := range procs {
		alive[p.PID] = true
	}
	for pid, h := range g.held {
		if alive[pid] {
			continue
		}
		someAlive := false
		for _, t := range h.tree {
			if alive[t] {
				someAlive = true
				break
			}
		}
		if !someAlive {
			g.journal.Log(journal.Event{
				Time: g.now(), Kind: kindAction, Action: "exited",
				PID: pid, Name: h.name,
			})
			delete(g.held, pid)
		}
	}
}

// journalSnapshot records pressure and the largest processes every tick, so
// observe mode accumulates real data for tuning.
func (g *Guard) journalSnapshot(st mem.Status, procs []proc.Proc, now time.Time, swapDelta uint64) {
	sorted := slices.Clone(procs)
	slices.SortFunc(sorted, func(a, b proc.Proc) int {
		return cmpUint64(b.RSS, a.RSS)
	})
	top := make([]journal.Candidate, 0, topN)
	for i, p := range sorted {
		if i >= topN {
			break
		}
		top = append(top, journal.Candidate{PID: p.PID, Name: p.Name, RSS: p.RSS})
	}
	g.journal.Log(journal.Event{
		Time: now, Kind: "snapshot", Level: st.Level,
		Top: top, SwapDelta: swapDelta, Msg: "swap=" + gib(st.SwapUsed),
	})
}

// savePaused persists the held set so a restart can re-adopt it.
func (g *Guard) savePaused() {
	if g.cfg.PausedFile == "" || g.cfg.Mode != config.ModeProtect {
		return
	}
	recs := make([]pausedRecord, 0, len(g.held))
	for pid, h := range g.held {
		recs = append(recs, pausedRecord{
			PID: pid, Name: h.name, RSS: h.rss,
			Parent: h.parent, Cmdline: h.cmdline,
			Created: h.created, StoppedAt: h.stoppedAt, Hog: h.hog,
		})
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		slog.Warn("paused state marshal failed", "err", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(g.cfg.PausedFile), dirPerm); err != nil {
		slog.Warn("paused state dir failed", "err", err)
		return
	}
	if err := os.WriteFile(g.cfg.PausedFile, raw, filePerm); err != nil {
		slog.Warn("paused state write failed", "err", err)
	}
}

// adopt re-tracks victims from a previous run whose PID and start time still
// match. A mismatched PID belongs to a new process and is left alone.
func (g *Guard) adopt() {
	if g.cfg.PausedFile == "" || g.cfg.Mode != config.ModeProtect {
		return
	}
	raw, err := os.ReadFile(g.cfg.PausedFile)
	if err != nil {
		return
	}
	var recs []pausedRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		return
	}
	procs, err := g.sys.Processes()
	if err != nil {
		return
	}
	byPID := make(map[int32]proc.Proc, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	for _, r := range recs {
		p, ok := byPID[r.PID]
		if !ok || !p.Created.Equal(r.Created) {
			continue
		}
		g.held[r.PID] = &held{
			name: r.Name, rss: r.RSS, created: r.Created,
			parent: r.Parent, cmdline: r.Cmdline,
			stoppedAt: r.StoppedAt, tree: treeOf(r.PID, procs), hog: r.Hog,
		}
	}
}

// treeOf returns root plus all descendants, breadth-first (parent first).
func treeOf(root int32, procs []proc.Proc) []int32 {
	kids := make(map[int32][]int32)
	for _, p := range procs {
		kids[p.PPID] = append(kids[p.PPID], p.PID)
	}
	tree := []int32{root}
	for i := 0; i < len(tree); i++ {
		tree = append(tree, kids[tree[i]]...)
	}

	return tree
}

func gib(b uint64) string {
	return fmt.Sprintf("%.1f GB", float64(b)/float64(uint64(1)<<gibShift))
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

func cmpUint64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
