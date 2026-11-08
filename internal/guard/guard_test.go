package guard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kyleking/ram-protector/internal/config"
	"github.com/kyleking/ram-protector/internal/guard"
	"github.com/kyleking/ram-protector/internal/journal"
	"github.com/kyleking/ram-protector/internal/mem"
	"github.com/kyleking/ram-protector/internal/proc"
	"github.com/kyleking/ram-protector/internal/score"
)

const gib = 1 << 30

type call struct {
	pid int32
	sig syscall.Signal
}

type fakeSys struct {
	deny     map[int32]bool
	procs    []proc.Proc
	calls    []call
	level    int
	swapUsed uint64
}

func (f *fakeSys) Memory() (mem.Status, error) {
	return mem.Status{Level: f.level, SwapUsed: f.swapUsed}, nil
}
func (f *fakeSys) Processes() ([]proc.Proc, error) { return f.procs, nil }
func (f *fakeSys) Signal(pid int32, sig syscall.Signal) error {
	f.calls = append(f.calls, call{pid: pid, sig: sig})
	if f.deny[pid] {
		return syscall.EPERM
	}

	return nil
}

func hasCall(calls []call, sig syscall.Signal, pid int32) bool {
	for _, c := range calls {
		if c.sig == sig && c.pid == pid {
			return true
		}
	}

	return false
}

func countSig(calls []call, sig syscall.Signal) int {
	n := 0
	for _, c := range calls {
		if c.sig == sig {
			n++
		}
	}

	return n
}

type harness struct {
	sys   *fakeSys
	guard *guard.Guard
	now   *time.Time
}

func newHarness(t *testing.T, procs []proc.Proc, level int) *harness {
	t.Helper()
	dir := t.TempDir()
	jw, err := journal.New(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	fs := &fakeSys{level: level, procs: procs, deny: map[int32]bool{}}
	now := time.Now()
	g := guard.New(guard.Config{
		Mode:           config.ModeProtect,
		WarnLevel:      20,
		CriticalLevel:  8,
		ResumeLevel:    30,
		ResumeTicks:    2,
		TermAfter:      time.Minute,
		KillAfter:      10 * time.Second,
		MemFloorBytes:  1 << 20,
		HogBytes:       6 * gib,
		SwapSpikeBytes: gib,
		PollHealthy:    time.Minute,
		PollWarn:       time.Second,
		PollCritical:   time.Millisecond,
		PausedFile:     filepath.Join(dir, "paused.json"),
	}, fs, score.New(nil, nil, nil), jw, nil, guard.WithNow(func() time.Time { return now }))

	return &harness{sys: fs, guard: g, now: &now}
}

func tscTree() []proc.Proc {
	now := time.Now()

	return []proc.Proc{
		{PID: 100, PPID: 1, Name: "node", Cmdline: "node tsc --watch", RSS: 4 * gib, Created: now},
		{PID: 101, PPID: 100, Name: "node", Cmdline: "node tsc-worker", RSS: gib, Created: now},
		{PID: 50, PPID: 1, Name: "app", Cmdline: "app", RSS: 5 * gib, Created: now},
	}
}

func TestHealthy_NoAction(t *testing.T) {
	t.Parallel()
	h := newHarness(t, tscTree(), 50)
	if got := h.guard.Tick(); got != time.Minute {
		t.Errorf("interval = %v, want healthy %v", got, time.Minute)
	}
	if len(h.sys.calls) != 0 {
		t.Errorf("signaled %d times at healthy level", len(h.sys.calls))
	}
}

func TestSwapSpike_PausesDespiteHealthyLevel(t *testing.T) {
	t.Parallel()
	h := newHarness(t, tscTree(), 70)
	h.sys.swapUsed = 5 * gib
	if got := h.guard.Tick(); got != time.Minute {
		t.Fatalf("first sample must not read as a spike: interval = %v", got)
	}
	h.sys.swapUsed += 2 * gib
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 100) {
		t.Errorf("swap spike at healthy level paused no victim: %+v", h.sys.calls)
	}
}

func hogProcs() []proc.Proc {
	now := time.Now()

	return []proc.Proc{
		{PID: 200, PPID: 1, Name: "node", Cmdline: "node tsc --watch", RSS: 7 * gib, Created: now},
		{PID: 300, PPID: 1, Name: "app", Cmdline: "app", RSS: 8 * gib, Created: now},
	}
}

func TestHog_PausesDisposableOverCeilingWhileHealthy(t *testing.T) {
	t.Parallel()
	h := newHarness(t, hogProcs(), 70)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 200) {
		t.Errorf("disposable hog not stopped: %+v", h.sys.calls)
	}
	if hasCall(h.sys.calls, syscall.SIGSTOP, 300) {
		t.Error("neutral process over ceiling was stopped")
	}
}

func TestHog_EscalatesWhileOverCap(t *testing.T) {
	t.Parallel()
	h := newHarness(t, hogProcs(), 70)
	h.guard.Tick()
	*h.now = h.now.Add(2 * time.Minute)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGTERM, 200) {
		t.Fatalf("over-cap hog never termed: %+v", h.sys.calls)
	}
	*h.now = h.now.Add(20 * time.Second)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGKILL, 200) {
		t.Fatalf("over-cap hog never killed: %+v", h.sys.calls)
	}
}

func TestHog_ResumedWhenBackUnderCap(t *testing.T) {
	t.Parallel()
	h := newHarness(t, hogProcs(), 70)
	h.guard.Tick()
	h.sys.procs[0].RSS = 3 * gib
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGCONT, 200) {
		t.Errorf("hog under cap not resumed: %+v", h.sys.calls)
	}
}

func TestWarn_PausesTreeParentFirst(t *testing.T) {
	t.Parallel()
	h := newHarness(t, tscTree(), 15)
	h.guard.Tick()

	if len(h.sys.calls) < 2 || h.sys.calls[0].pid != 100 || h.sys.calls[1].pid != 101 {
		t.Fatalf("expected STOP 100 then 101, got %+v", h.sys.calls)
	}
	for _, c := range h.sys.calls[:2] {
		if c.sig != syscall.SIGSTOP {
			t.Errorf("expected SIGSTOP, got %v", c.sig)
		}
	}
	if h.guard.Held()[100] != "node" {
		t.Errorf("victim 100 not held: %v", h.guard.Held())
	}
}

func TestEscalatesToTermThenKill(t *testing.T) {
	t.Parallel()
	h := newHarness(t, tscTree(), 15)
	h.guard.Tick()
	*h.now = h.now.Add(2 * time.Minute) // past TermAfter
	h.sys.level = 15
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGTERM, 100) {
		t.Fatalf("no SIGTERM after grace: %+v", h.sys.calls)
	}
	*h.now = h.now.Add(20 * time.Second) // past KillAfter
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGKILL, 100) {
		t.Fatalf("no SIGKILL after term grace: %+v", h.sys.calls)
	}
}

func TestResumesWhenPressureClears(t *testing.T) {
	t.Parallel()
	h := newHarness(t, tscTree(), 15)
	h.guard.Tick()
	h.sys.level = 35
	h.guard.Tick()
	if countSig(h.sys.calls, syscall.SIGCONT) != 0 {
		t.Fatal("resumed before ResumeTicks consecutive healthy reads")
	}
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGCONT, 100) || !hasCall(h.sys.calls, syscall.SIGCONT, 101) {
		t.Fatalf("no SIGCONT after sustained recovery: %+v", h.sys.calls)
	}
	if len(h.guard.Held()) != 0 {
		t.Errorf("held set not cleared: %v", h.guard.Held())
	}
}

func TestObserve_SignalsNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	jw, err := journal.New(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	fs := &fakeSys{level: 15, procs: tscTree(), deny: map[int32]bool{}}
	g := guard.New(guard.Config{
		Mode: config.ModeObserve, WarnLevel: 20, CriticalLevel: 8, ResumeLevel: 30,
		ResumeTicks: 2, MemFloorBytes: 1 << 20, PollHealthy: time.Minute,
	}, fs, score.New(nil, nil, nil), jw, nil)
	g.Tick()
	if len(fs.calls) != 0 {
		t.Errorf("observe mode signaled %d times", len(fs.calls))
	}
	if err := jw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	events, err := journal.Tail(filepath.Join(dir, "events.jsonl"), 50)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	dry := false
	for i := range events {
		if events[i].Kind == "action" && events[i].Dry {
			dry = true
		}
	}
	if !dry {
		t.Error("observe mode recorded no dry-run actions")
	}
}

func TestEPERM_VictimDroppedAndNextPicked(t *testing.T) {
	t.Parallel()
	h := newHarness(t, tscTree(), 15)
	h.sys.deny[100] = true
	h.guard.Tick()
	if len(h.guard.Held()) != 0 {
		t.Fatalf("unsignalable victim stayed held: %v", h.guard.Held())
	}
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 50) {
		t.Errorf("next candidate 50 never stopped: %+v", h.sys.calls)
	}
}

func TestLastResort_OnlyAtCritical(t *testing.T) {
	t.Parallel()
	procs := []proc.Proc{
		{PID: 70, PPID: 1, Name: "wezterm-gui", Cmdline: "wezterm-gui", RSS: 4 * gib, Created: time.Now()},
	}
	h := newHarness(t, procs, 15)
	h.guard.Tick()
	if len(h.sys.calls) != 0 {
		t.Error("last-resort process signaled at warn level")
	}
	h.sys.level = 5
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 70) {
		t.Error("last-resort process not signaled at critical level")
	}
}

func TestAdopt_RestoresPausedState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	created := time.Now().Truncate(time.Second)
	recs := []map[string]any{
		{"pid": 100, "name": "node", "rss": 4 * gib, "created": created, "stopped_at": created},
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pausedFile := filepath.Join(dir, "paused.json")
	if err := os.WriteFile(pausedFile, raw, 0o600); err != nil {
		t.Fatalf("write paused: %v", err)
	}
	jw, err := journal.New(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	procs := []proc.Proc{
		{PID: 100, PPID: 1, Name: "node", Cmdline: "node tsc", RSS: 4 * gib, Created: created},
	}
	fs := &fakeSys{level: 50, procs: procs, deny: map[int32]bool{}}
	g := guard.New(guard.Config{
		Mode: config.ModeProtect, WarnLevel: 20, CriticalLevel: 8, ResumeLevel: 30,
		ResumeTicks: 2, MemFloorBytes: 1 << 20, PollHealthy: time.Minute, PausedFile: pausedFile,
	}, fs, score.New(nil, nil, nil), jw, nil)
	if g.Held()[100] != "node" {
		t.Errorf("paused victim not adopted: %v", g.Held())
	}
}
