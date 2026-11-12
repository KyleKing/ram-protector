// Package report renders sys-guardian's inspect commands: the victim
// ranking, the journal tail, and live pressure state.
package report

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/kyleking/sys-guardian/internal/config"
	"github.com/kyleking/sys-guardian/internal/journal"
	"github.com/kyleking/sys-guardian/internal/mem"
	"github.com/kyleking/sys-guardian/internal/proc"
	"github.com/kyleking/sys-guardian/internal/score"
	"github.com/kyleking/sys-guardian/internal/service"
)

const (
	showTop     = 10
	bytesPerGiB = 1 << 30
)

type ranked struct {
	r []string
	p proc.Proc
	s float64
}

// Check prints memory level and the current victim ranking.
func Check(cfg config.Config) error {
	st, err := mem.Read()
	if err != nil {
		return fmt.Errorf("reading memory: %w", err)
	}
	procs, err := proc.List()
	if err != nil {
		return fmt.Errorf("listing processes: %w", err)
	}
	sc := score.New(cfg.Disposable, cfg.LastResort, cfg.Never,
		score.WithStableAge(cfg.StableAge.Duration))
	now := time.Now()

	rows := make([]ranked, 0, showTop)
	for _, p := range procs {
		s, reasons := sc.Score(p, now)
		if s <= 0 || p.RSS < cfg.MemFloorBytes() {
			continue
		}
		rows = append(rows, ranked{p: p, s: s, r: reasons})
	}
	slices.SortFunc(rows, func(a, b ranked) int { return cmp.Compare(b.s, a.s) })

	fmt.Printf("memory available: %d%%   swap: %.1f/%.1f GB   warn<%d crit<%d hog>%dGB\n",
		st.Level, float64(st.SwapUsed)/bytesPerGiB, float64(st.SwapTotal)/bytesPerGiB,
		cfg.WarnLevel, cfg.CriticalLevel, cfg.HogBytes()/bytesPerGiB)
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

// Status prints the live pressure line, agent state, and the journal tail.
func Status(eventsPath string, n int) error {
	st, err := mem.Read()
	if err != nil {
		return fmt.Errorf("reading memory: %w", err)
	}
	fmt.Printf("memory available: %d%%   swap: %.1f/%.1f GB   agent running: %v\n",
		st.Level, float64(st.SwapUsed)/bytesPerGiB, float64(st.SwapTotal)/bytesPerGiB,
		service.Running(context.Background()))

	return Log(eventsPath, n)
}

// Log prints the last n journal events.
func Log(eventsPath string, n int) error {
	events, err := journal.Tail(eventsPath, n)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no journal yet at " + eventsPath)
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

func formatEvent(e journal.Event) string {
	ts := e.Time.Format("15:04:05")
	dry := ""
	if e.Dry {
		dry = " [dry]"
	}
	switch e.Kind {
	case journal.KindDecision, journal.KindAction:
		return fmt.Sprintf("%s %-8s %-12s pid=%-6d %-20s lvl=%d%%%s %s",
			ts, e.Kind, e.Action, e.PID, e.Name, e.Level, dry, e.Msg)
	case journal.KindResume:
		return fmt.Sprintf("%s %-8s %s%s", ts, e.Kind, e.Msg, dry)
	default:
		dswap := ""
		if e.SwapDelta > 0 {
			dswap = fmt.Sprintf(" dswap=+%.1fGB", float64(e.SwapDelta)/bytesPerGiB)
		}
		load := ""
		if e.Load1 > 0 {
			load = fmt.Sprintf(" load1=%.1f", e.Load1)
		}

		return fmt.Sprintf("%s %-8s lvl=%d%%%s %s%s%s", ts, e.Kind, e.Level, load, e.Msg, dswap, dry)
	}
}
