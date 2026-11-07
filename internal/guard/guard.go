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

	"github.com/kyleking/ram-protector/internal/config"
	"github.com/kyleking/ram-protector/internal/journal"
	"github.com/kyleking/ram-protector/internal/mem"
	"github.com/kyleking/ram-protector/internal/proc"
	"github.com/kyleking/ram-protector/internal/score"
)

const (
	topN       = 5
	kindAction = "action"
	dirPerm    = 0o750
	filePerm   = 0o600
	gibShift   = 30
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
	PollHealthy   time.Duration
	PollWarn      time.Duration
	PollCritical  time.Duration
}

type held struct {
	created   time.Time
	stoppedAt time.Time
	termAt    time.Time
	name      string
	tree      []int32
	rss       uint64
}

type pausedRecord struct {
	Created   time.Time `json:"created"`
	StoppedAt time.Time `json:"stopped_at"`
	Name      string    `json:"name"`
	RSS       uint64    `json:"rss"`
	PID       int32     `json:"pid"`
}

// Option customizes a Guard; tests use these to inject a clock.
type Option func(*Guard)

// WithNow overrides the wall clock.
func WithNow(now func() time.Time) Option {
	return func(g *Guard) { g.now = now }
}

// Guard runs the evaluate/act loop.
type Guard struct {
	sys     Sys
	scorer  *score.Scorer
	journal *journal.Writer
	notify  func(title, body string)
	held    map[int32]*held
	blocked map[int32]bool
	now     func() time.Time
	cfg     Config
	healthy int
}

// New builds a guard and, in protect mode, re-adopts processes a previous run
// paused but never resumed.
func New(cfg Config, sys Sys, sc *score.Scorer, jw *journal.Writer, notify func(title, body string),
	opts ...Option,
) *Guard {
	if notify == nil {
		notify = func(string, string) {}
	}
	g := &Guard{
		cfg:     cfg,
		sys:     sys,
		scorer:  sc,
		journal: jw,
		notify:  notify,
		held:    map[int32]*held{},
		blocked: map[int32]bool{},
		now:     time.Now,
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
	defer g.resumeAll()

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
	g.scorer.Observe(procs, now)
	g.dropDead(procs)
	g.journalSnapshot(st, procs, now)

	if st.Level >= g.cfg.ResumeLevel {
		g.healthy++
	} else {
		g.healthy = 0
	}
	if len(g.held) > 0 && g.healthy >= g.cfg.ResumeTicks {
		g.resumeAll()
	}
	if st.Level >= g.cfg.WarnLevel {
		return g.cfg.PollHealthy
	}

	g.escalate(now)
	g.maybePause(st, procs, now)

	return g.intervalFor(st)
}

func (g *Guard) intervalFor(st mem.Status) time.Duration {
	switch {
	case st.Level < g.cfg.CriticalLevel:
		return g.cfg.PollCritical
	case len(g.held) > 0:
		return g.cfg.PollWarn
	default:
		return g.cfg.PollHealthy
	}
}

// escalate advances held victims along pause -> TERM -> KILL while pressure
// stays below warn. Between warn and resume they stay paused, untouched.
func (g *Guard) escalate(now time.Time) {
	for pid, h := range g.held {
		if now.Sub(h.stoppedAt) < g.cfg.TermAfter {
			continue
		}
		if h.termAt.IsZero() {
			h.termAt = now
			g.signalTree(h, syscall.SIGTERM, "term")
			g.journal.Log(journal.Event{
				Time: now, Kind: kindAction, Action: "term",
				PID: pid, Name: h.name, RSS: h.rss, Msg: "pressure stayed below warn",
			})

			continue
		}
		if now.Sub(h.termAt) >= g.cfg.KillAfter {
			g.signalTree(h, syscall.SIGKILL, "kill")
			g.journal.Log(journal.Event{
				Time: now, Kind: kindAction, Action: "kill",
				PID: pid, Name: h.name, RSS: h.rss,
			})
			g.notify("ram-protector", fmt.Sprintf("killed %s (%s) — memory stayed critical", h.name, gib(h.rss)))
			delete(g.held, pid)
		}
	}
	g.savePaused()
}

// maybePause picks the single worst offender and SIGSTOPs it with its tree.
func (g *Guard) maybePause(st mem.Status, procs []proc.Proc, now time.Time) {
	victim, top := g.pickVictim(st, procs)
	dry := g.cfg.Mode == config.ModeObserve

	verb := "stop"
	if dry {
		verb = "would_stop"
	}
	ev := journal.Event{Time: now, Kind: "decision", Level: st.Level, Dry: dry, Top: top}
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
	h := &held{
		name: victim.p.Name, rss: victim.p.RSS, created: victim.p.Created,
		stoppedAt: now, tree: treeOf(victim.p.PID, procs),
	}
	g.held[victim.p.PID] = h
	g.signalTree(h, syscall.SIGSTOP, "stop")
	if g.blocked[victim.p.PID] {
		delete(g.held, victim.p.PID)
		return
	}
	msg := fmt.Sprintf("paused %s (%s), %d%% memory free. Will resume when clear.", h.name, gib(h.rss), st.Level)
	g.notify("ram-protector", msg)
	g.savePaused()
}

type scored struct {
	reasons []string
	p       proc.Proc
	score   float64
}

// pickVictim scores eligible processes and returns the best plus the top-N
// leaderboard for the journal.
func (g *Guard) pickVictim(st mem.Status, procs []proc.Proc) (*scored, []journal.Candidate) {
	heldSet := map[int32]bool{}
	for _, h := range g.held {
		for _, pid := range h.tree {
			heldSet[pid] = true
		}
	}

	cands := make([]scored, 0, len(procs))
	now := g.now()
	for _, p := range procs {
		if heldSet[p.PID] || g.blocked[p.PID] || p.RSS < g.cfg.MemFloorBytes {
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
	if len(cands) == 0 {
		return nil, top
	}

	return &cands[0], top
}

// signal sends sig, or only records it in observe mode. EPERM marks the PID
// unkillable for the rest of the run.
func (g *Guard) signal(pid int32, sig syscall.Signal, act string) {
	if g.cfg.Mode == config.ModeObserve {
		g.journal.Log(journal.Event{Time: g.now(), Kind: kindAction, Action: act, PID: pid, Dry: true})

		return
	}
	if err := g.sys.Signal(pid, sig); err != nil {
		if errors.Is(err, syscall.EPERM) {
			g.blocked[pid] = true
		}
		if !errors.Is(err, syscall.ESRCH) {
			g.journal.Log(journal.Event{Time: g.now(), Kind: kindAction, Action: act, PID: pid, Msg: err.Error()})
		}

		return
	}
	g.journal.Log(journal.Event{Time: g.now(), Kind: kindAction, Action: act, PID: pid})
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
		g.signal(pid, sig, act)
	}
}

// resumeAll SIGCONTs every held tree and clears state.
func (g *Guard) resumeAll() {
	if len(g.held) == 0 {
		return
	}
	names := make([]string, 0, len(g.held))
	for pid, h := range g.held {
		for _, tpid := range h.tree {
			g.signal(tpid, syscall.SIGCONT, "cont")
		}
		names = append(names, fmt.Sprintf("%s(%d)", h.name, pid))
		delete(g.held, pid)
	}
	g.healthy = 0
	g.journal.Log(journal.Event{Time: g.now(), Kind: "resume", Msg: strings.Join(names, ", ")})
	g.notify("ram-protector", "resumed "+strings.Join(names, ", "))
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
func (g *Guard) journalSnapshot(st mem.Status, procs []proc.Proc, now time.Time) {
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
		Top: top, Msg: "swap=" + gib(st.SwapUsed),
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
			Created: h.created, StoppedAt: h.stoppedAt,
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
			stoppedAt: r.StoppedAt, tree: treeOf(r.PID, procs),
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
