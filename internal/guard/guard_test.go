package guard_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kyleking/sys-guardian/internal/config"
	"github.com/kyleking/sys-guardian/internal/guard"
	"github.com/kyleking/sys-guardian/internal/journal"
	"github.com/kyleking/sys-guardian/internal/mem"
	"github.com/kyleking/sys-guardian/internal/proc"
	"github.com/kyleking/sys-guardian/internal/score"
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
	load1    float64
}

func (f *fakeSys) Memory() (mem.Status, error) {
	return mem.Status{Level: f.level, SwapUsed: f.swapUsed, Load1: f.load1}, nil
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

	return newHarnessCfg(t, procs, level, nil)
}

func newHarnessCfg(t *testing.T, procs []proc.Proc, level int, tweak func(*guard.Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	jw, err := journal.New(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	fs := &fakeSys{level: level, procs: procs, deny: map[int32]bool{}}
	now := time.Now()
	cfg := guard.Config{
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
	}
	if tweak != nil {
		tweak(&cfg)
	}
	g := guard.New(cfg, fs, score.New(nil, nil, nil), jw, nil, nil,
		guard.WithNow(func() time.Time { return now }))

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

func spikeHarness(t *testing.T, procs []proc.Proc) *harness {
	t.Helper()

	return newHarnessCfg(t, procs, 70, func(c *guard.Config) {
		c.SpikeHold = 2 * time.Minute
		c.SwapGrowthBytes = 128 << 20
	})
}

func TestSwapSpike_HeldThroughWindowThenResumed(t *testing.T) {
	t.Parallel()
	h := spikeHarness(t, tscTree())
	h.sys.swapUsed = 5 * gib
	h.guard.Tick()
	h.sys.swapUsed += 2 * gib
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 100) {
		t.Fatalf("spike paused no victim: %+v", h.sys.calls)
	}
	h.guard.Tick()
	h.guard.Tick()
	if hasCall(h.sys.calls, syscall.SIGCONT, 100) {
		t.Error("resumed during the spike window while swap pressure stood")
	}
	*h.now = h.now.Add(3 * time.Minute)
	h.guard.Tick()
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGCONT, 100) {
		t.Error("not resumed after the window closed on healthy reads")
	}
}

func TestSwapSpike_EscalatesOnlyWhileSwapGrows(t *testing.T) {
	t.Parallel()
	h := spikeHarness(t, tscTree())
	h.sys.swapUsed = 5 * gib
	h.guard.Tick()
	h.sys.swapUsed += 2 * gib
	h.guard.Tick()

	// Swap flat inside the window: past TermAfter but no growth, so no TERM.
	*h.now = h.now.Add(90 * time.Second)
	h.guard.Tick()
	if hasCall(h.sys.calls, syscall.SIGTERM, 100) {
		t.Fatal("escalated on a flat swap tail; only growth should keep the ladder live")
	}

	// Growth resumes inside the window: the ladder is live again.
	h.sys.swapUsed += 256 << 20
	*h.now = h.now.Add(10 * time.Second)
	h.guard.Tick()
	h.sys.swapUsed += 256 << 20
	*h.now = h.now.Add(20 * time.Second)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGTERM, 100) {
		t.Fatalf("no TERM while swap kept growing: %+v", h.sys.calls)
	}
	h.sys.swapUsed += 256 << 20
	*h.now = h.now.Add(20 * time.Second)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGKILL, 100) {
		t.Fatalf("no KILL while swap kept growing: %+v", h.sys.calls)
	}
}

func TestMinPause_SurvivesImmediateRecovery(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, tscTree(), 15, func(c *guard.Config) {
		c.MinPause = 2 * time.Minute
	})
	h.guard.Tick()
	h.sys.level = 35
	h.guard.Tick()
	h.guard.Tick()
	if hasCall(h.sys.calls, syscall.SIGCONT, 100) {
		t.Error("resumed inside MinPause on the first healthy reads")
	}
	*h.now = h.now.Add(3 * time.Minute)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGCONT, 100) {
		t.Error("not resumed once MinPause elapsed on healthy reads")
	}
}

func burnProcs() []proc.Proc {
	now := time.Now()

	return []proc.Proc{
		{PID: 100, PPID: 1, Name: "node", Cmdline: "node tsc --watch", RSS: 4 * gib, Created: now},
		{PID: 300, PPID: 1, Name: "app", Cmdline: "app", RSS: 5 * gib, Created: now},
	}
}

func burnHarness(t *testing.T) *harness {
	t.Helper()

	return newHarnessCfg(t, burnProcs(), 70, func(c *guard.Config) {
		c.CPUBurnPct = 150
		c.CPUBurnFor = time.Minute
	})
}

// burnTick advances the clock and feeds each process cpuSec of CPU time.
func burnTick(h *harness, cpuSec float64) {
	*h.now = h.now.Add(30 * time.Second)
	for i := range h.sys.procs {
		h.sys.procs[i].CPUTotal += cpuSec
	}
	h.guard.Tick()
}

func TestCPUBurn_PausesDisposableSustainedBurner(t *testing.T) {
	t.Parallel()
	h := burnHarness(t)
	h.guard.Tick()
	burnTick(h, 90) // 300% CPU: burn timer starts
	burnTick(h, 90) // 30s sustained: under the threshold duration
	if hasCall(h.sys.calls, syscall.SIGSTOP, 100) {
		t.Fatal("stopped before the burn duration elapsed")
	}
	burnTick(h, 90) // 60s sustained: over the threshold duration
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 100) {
		t.Errorf("sustained disposable burner not stopped: %+v", h.sys.calls)
	}
	if hasCall(h.sys.calls, syscall.SIGSTOP, 300) {
		t.Error("non-disposable burner was stopped")
	}
}

func TestCPUBurn_ShortBurstIgnored(t *testing.T) {
	t.Parallel()
	h := burnHarness(t)
	h.guard.Tick()
	burnTick(h, 90)
	burnTick(h, 0) // cooled off: the burn timer must reset
	burnTick(h, 90)
	burnTick(h, 90) // only 30s of continuous burn since the reset
	if hasCall(h.sys.calls, syscall.SIGSTOP, 100) {
		t.Error("stopped on a short burst; the cool-off did not reset the timer")
	}
	burnTick(h, 90) // 60s continuous now: the pause is due
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 100) {
		t.Error("sustained burner never stopped after the reset")
	}
}

func loadProcs() []proc.Proc {
	now := time.Now()

	return []proc.Proc{
		{PID: 400, PPID: 1, Name: "python3.12", Cmdline: "python -u -c worker", RSS: 200 << 20, Created: now},
		{PID: 401, PPID: 1, Name: "python3.12", Cmdline: "python -u -c worker", RSS: 180 << 20, Created: now},
		{PID: 70, PPID: 1, Name: "wezterm-gui", Cmdline: "wezterm-gui", RSS: gib, Created: now},
	}
}

func loadHarness(t *testing.T) *harness {
	t.Helper()

	return newHarnessCfg(t, loadProcs(), 70, func(c *guard.Config) {
		c.LoadPerCore = 1.5
		c.LoadResumePerCore = 0.8
		c.LoadFor = time.Minute
		c.NumCores = 10
	})
}

// feedCPU advances the clock and credits each process with cpu seconds so the
// scorer sees differential burn between ticks.
func feedCPU(h *harness, cpuByPID map[int32]float64) {
	*h.now = h.now.Add(30 * time.Second)
	for i := range h.sys.procs {
		h.sys.procs[i].CPUTotal += cpuByPID[h.sys.procs[i].PID]
	}
}

func TestLoad_PausesTopCPUConsumerAfterSustained(t *testing.T) {
	t.Parallel()
	h := loadHarness(t)
	h.sys.load1 = 30 // 3.0 per core, over the 1.5 trigger
	h.guard.Tick()   // establishes the previous CPU sample
	feedCPU(h, map[int32]float64{400: 60, 401: 9, 70: 90})
	h.guard.Tick() // 30s sustained: under LoadFor
	if len(h.sys.calls) != 0 {
		t.Fatalf("stopped during the burn-in window: %+v", h.sys.calls)
	}
	feedCPU(h, map[int32]float64{400: 60, 401: 9, 70: 90})
	h.guard.Tick() // 60s sustained: storm is active
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 400) {
		t.Errorf("top CPU consumer not stopped under load: %+v", h.sys.calls)
	}
	if hasCall(h.sys.calls, syscall.SIGSTOP, 70) {
		t.Error("last-resort process was stopped; interactive tiers must stay protected")
	}
}

func TestLoad_ResumesWhenLoadClears(t *testing.T) {
	t.Parallel()
	h := loadHarness(t)
	h.sys.load1 = 30
	h.guard.Tick()
	feedCPU(h, map[int32]float64{400: 60, 70: 90})
	h.guard.Tick()
	feedCPU(h, map[int32]float64{400: 60, 70: 90})
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 400) {
		t.Fatalf("load storm paused no victim: %+v", h.sys.calls)
	}
	h.sys.load1 = 4 // 0.4 per core: under the resume threshold
	h.guard.Tick()
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGCONT, 400) {
		t.Error("victim not resumed once the storm cleared")
	}
}

func TestLoad_PausesStormSpawnPoint(t *testing.T) {
	t.Parallel()
	now := time.Now()
	h := newHarnessCfg(t, []proc.Proc{
		{PID: 90, PPID: 1, Name: "zsh", Cmdline: "zsh", RSS: 50 << 20, Created: now},
		{PID: 400, PPID: 90, Name: "python3.12", Cmdline: "python -u -c bot", RSS: 200 << 20, Created: now},
		{PID: 401, PPID: 400, Name: "git", Cmdline: "git grep x", RSS: 100 << 20, Created: now},
		{PID: 402, PPID: 400, Name: "git", Cmdline: "git grep y", RSS: 100 << 20, Created: now},
		{PID: 403, PPID: 400, Name: "git", Cmdline: "git grep z", RSS: 100 << 20, Created: now},
		{PID: 500, PPID: 1, Name: "node", Cmdline: "npm exec mcp", RSS: 150 << 20, Created: now},
	}, 70, func(c *guard.Config) {
		c.LoadPerCore = 1.5
		c.LoadResumePerCore = 0.8
		c.LoadFor = time.Minute
		c.NumCores = 10
	})
	h.sys.load1 = 30
	h.guard.Tick()
	feed := func() {
		feedCPU(h, map[int32]float64{401: 20, 402: 20, 403: 20, 500: 4})
		h.guard.Tick()
	}
	feed() // 30s sustained: under LoadFor
	if len(h.sys.calls) != 0 {
		t.Fatalf("stopped during the burn-in window: %+v", h.sys.calls)
	}
	feed() // 60s sustained: storm is active
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 400) {
		t.Fatalf("storm spawner not stopped: %+v", h.sys.calls)
	}
	if hasCall(h.sys.calls, syscall.SIGSTOP, 90) {
		t.Error("shell above the spawner was stopped; the victim must be the deepest spawn point")
	}
	if hasCall(h.sys.calls, syscall.SIGSTOP, 500) {
		t.Error("bystander under the storm floor was stopped")
	}
}

func TestLoad_BurstDoesNotTrigger(t *testing.T) {
	t.Parallel()
	h := loadHarness(t)
	h.guard.Tick()
	h.sys.load1 = 30
	feedCPU(h, map[int32]float64{400: 60})
	h.guard.Tick()
	h.sys.load1 = 10 // dips below trigger: the sustained timer must reset
	feedCPU(h, map[int32]float64{400: 60})
	h.guard.Tick()
	h.sys.load1 = 30
	feedCPU(h, map[int32]float64{400: 60})
	h.guard.Tick()
	if hasCall(h.sys.calls, syscall.SIGSTOP, 400) {
		t.Error("stopped on a load burst; the dip should have reset the timer")
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

func TestHog_FrozenWhileHealthy_EscalatesUnderPressure(t *testing.T) {
	t.Parallel()
	h := newHarness(t, hogProcs(), 70)
	h.guard.Tick()
	*h.now = h.now.Add(2 * time.Minute) // past TermAfter with no pressure
	h.guard.Tick()
	if hasCall(h.sys.calls, syscall.SIGTERM, 200) {
		t.Fatalf("hog escalated while the system was healthy: %+v", h.sys.calls)
	}
	h.sys.level = 15 // real pressure arrives: the frozen hog dies first
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGTERM, 200) {
		t.Fatalf("hog not termed under pressure: %+v", h.sys.calls)
	}
	*h.now = h.now.Add(20 * time.Second)
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGKILL, 200) {
		t.Fatalf("hog not killed under pressure: %+v", h.sys.calls)
	}
}

func TestKilled_NotRepickedImmediately(t *testing.T) {
	t.Parallel()
	procs := []proc.Proc{
		{PID: 200, PPID: 1, Name: "node", Cmdline: "node tsc --watch", RSS: 7 * gib, Created: time.Now()},
	}
	h := newHarness(t, procs, 15)
	h.guard.Tick()
	*h.now = h.now.Add(2 * time.Minute)
	h.guard.Tick()
	*h.now = h.now.Add(20 * time.Second)
	h.guard.Tick()
	h.guard.Tick() // the corpse still lists in procs; it must not be re-stopped
	if got := countSig(h.sys.calls, syscall.SIGSTOP); got != 1 {
		t.Fatalf("SIGSTOP sent %d times, killed pid was re-picked: %+v", got, h.sys.calls)
	}
	// A respawn has a new PID but the same name and command line: the
	// identity cooldown still blocks it.
	h.sys.procs[0].PID = 900
	h.guard.Tick()
	if got := countSig(h.sys.calls, syscall.SIGSTOP); got != 1 {
		t.Fatalf("respawned victim re-picked inside the cooldown: %+v", h.sys.calls)
	}
	*h.now = h.now.Add(6 * time.Minute) // past the kill cooldown
	h.guard.Tick()
	if !hasCall(h.sys.calls, syscall.SIGSTOP, 900) {
		t.Errorf("victim not re-picked after the cooldown lapsed: %+v", h.sys.calls)
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
	}, fs, score.New(nil, nil, nil), jw, nil, nil)
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
	}, fs, score.New(nil, nil, nil), jw, nil, nil)
	if g.Held()[100] != "node" {
		t.Errorf("paused victim not adopted: %v", g.Held())
	}
}
