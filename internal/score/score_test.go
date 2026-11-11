package score_test

import (
	"strings"
	"testing"
	"time"

	"github.com/kyleking/sys-guardian/internal/proc"
	"github.com/kyleking/sys-guardian/internal/score"
)

const gib = 1 << 30

func mkProc(pid int32, name, cmd string) proc.Proc {
	return proc.Proc{PID: pid, Name: name, Cmdline: cmd, RSS: gib, Created: time.Now()}
}

func TestTierOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		proc proc.Proc
		want score.Tier
	}{
		{
			name: "tsc watcher", proc: mkProc(1, "node", "node /x/typescript/bin/tsc --watch"),
			want: score.TierDisposable,
		},
		{
			proc: mkProc(2, "Google Chrome", "/x/Google Chrome.app/Contents/MacOS/Google Chrome"),
			want: score.TierLastResort, name: "chrome main",
		},
		{
			proc: mkProc(3, "Chrome Helper", "/x/Helpers/Google Chrome Helper --type=renderer"),
			want: score.TierDisposable, name: "chrome helper",
		},
		{name: "wezterm", proc: mkProc(4, "wezterm-gui", "wezterm-gui"), want: score.TierLastResort},
		{name: "launchd", proc: mkProc(5, "launchd", "/sbin/launchd"), want: score.TierNever},
		{name: "windowserver", proc: mkProc(6, "WindowServer", "/x/WindowServer -daemon"), want: score.TierNever},
		{name: "self", proc: mkProc(7, "sys-guardian", "sys-guardian daemon"), want: score.TierNever},
		{name: "mystery", proc: mkProc(8, "mystery", "mystery --flag"), want: score.TierNeutral},
		{
			proc: mkProc(9, "mediaanalysisd", "/usr/libexec/mediaanalysisd"),
			want: score.TierLastResort, name: "platform daemon",
		},
		{
			proc: mkProc(10, "helpd", "/System/Library/x.framework/helpd"),
			want: score.TierLastResort, name: "system framework",
		},
		{
			proc: mkProc(11, "com.apple.Virtualization.VirtualMachine", "com.apple.Virtualization.VirtualMachine"),
			want: score.TierNever, name: "virtual machine",
		},
		{name: "homebrew sbin", proc: mkProc(12, "mtr", "/opt/homebrew/sbin/mtr"), want: score.TierNeutral},
	}
	sc := score.New(nil, nil, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sc.TierOf(tt.proc); got != tt.want {
				t.Errorf("TierOf(%s) = %d, want %d", tt.proc.Name, got, tt.want)
			}
		})
	}
}

func TestTierOf_UserNeverOverridesDisposable(t *testing.T) {
	t.Parallel()
	sc := score.New(nil, nil, []string{"tsc"})
	p := mkProc(1, "node", "node tsc --watch")
	if got := sc.TierOf(p); got != score.TierNever {
		t.Errorf("TierOf = %d, want TierNever (user protect list wins)", got)
	}
}

func TestScore(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tests := []struct {
		name  string
		procs []proc.Proc
		want  int32 // PID expected to score highest
	}{
		{
			"disposable beats larger neutral",
			[]proc.Proc{
				{PID: 1, Name: "node", Cmdline: "node tsc --watch", RSS: 4 * gib, Created: now},
				{PID: 2, Name: "app", Cmdline: "app", RSS: 5 * gib, Created: now},
			},
			1,
		},
		{
			"neutral beats larger last-resort",
			[]proc.Proc{
				{PID: 1, Name: "app", Cmdline: "app", RSS: 3 * gib, Created: now},
				{PID: 2, Name: "wezterm-gui", Cmdline: "wezterm-gui", RSS: 6 * gib, Created: now},
			},
			1,
		},
		{
			"never is negative",
			[]proc.Proc{
				{PID: 1, Name: "launchd", Cmdline: "/sbin/launchd", RSS: 9 * gib, Created: now},
				{PID: 2, Name: "app", Cmdline: "app", RSS: 1 * gib, Created: now},
			},
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sc := score.New(nil, nil, nil)
			var best int32
			bestScore := -1.0
			for _, p := range tt.procs {
				s, _ := sc.Score(p, now)
				if s > bestScore {
					bestScore, best = s, p.PID
				}
			}
			if best != tt.want {
				t.Errorf("best victim = pid %d, want %d", best, tt.want)
			}
		})
	}
}

func TestScore_GrowthAndCPURecorded(t *testing.T) {
	t.Parallel()
	sc := score.New(nil, nil, nil)
	t0 := time.Now()
	p := proc.Proc{PID: 7, Name: "node", Cmdline: "node tsc --watch", RSS: 2 * gib, Created: t0}
	sc.Observe([]proc.Proc{p}, t0)

	t1 := t0.Add(10 * time.Second)
	p.RSS = 3 * gib // +1 GiB in 10s
	p.CPUTotal = 20 // 200% recent CPU
	sc.Observe([]proc.Proc{p}, t1)

	s, reasons := sc.Score(p, t1)
	joined := strings.Join(reasons, " ")
	if s <= float64(p.RSS)/gib {
		t.Errorf("score %f should exceed bare RSS for a fast-growing disposable", s)
	}
	if want := "d_rss=1024MB"; !strings.Contains(joined, want) {
		t.Errorf("reasons %q missing %q", joined, want)
	}
}
