# Design

## Architecture

`cmd/ram-protector` is a thin dispatcher over `internal/` packages:

- `internal/mem` — `kern.memorystatus_level` (% physical memory available) +
  swap/phys totals via gopsutil
- `internal/proc` — process snapshot (pid, ppid, name, cmdline, RSS, CPU time,
  start time) via gopsutil
- `internal/score` — victim ranking: RSS_GiB × tier × age × growth × cpu, with a
  human-readable reason per factor for the journal. Tiers: `never` >
  `disposable` > `last_resort` > `neutral`, matched as substrings over name +
  cmdline. Only the previous snapshot per PID is kept.
- `internal/guard` — the state machine. One victim per tick:
  SIGSTOP the tree (parent first, so it can't re-fork) → TERM deepest-first
  after `term_after` if pressure stays below warn → SIGKILL after `kill_after`.
  Resume (SIGCONT) after `resume_ticks` consecutive reads ≥ `resume_level`.
  `paused.json` persists held victims so a restart re-adopts them (matched by
  PID + start time); `Run` resumes everything it paused on exit.
- `internal/journal` — append-only JSONL at `~/Library/Logs/ram-protector/
  events.jsonl`: `snapshot` every tick, `decision` (top-5 scored candidates +
  chosen action), `action`, `resume`. This doubles as the tuning dataset for
  observe mode.
- `internal/notify` — Notification Center via `/usr/bin/osascript`
- `internal/service` — `~/Library/LaunchAgents/com.kyleking.ram-protector.plist`
  (KeepAlive, ProcessType=Background, LowPriorityIO)
- `internal/config` — TOML at `~/.config/ram-protector/config.toml`; all fields
  optional

## Key decisions

- **Pause first, kill as fallback.** SIGSTOP is reversible and stops growth +
  CPU burn immediately, but frees almost nothing (~0.03 GiB reclaimable vs
  ~0.6 GiB for kill) — so it is the first rung, never the last. Escalation
  runs only while pressure stays below `warn_level`; between warn and resume
  the victim stays paused indefinitely.
- **Kill the tree, not the pid.** Children reparent to launchd and survive a
  lone-parent kill; the guard SIGSTOPs the whole tree first, then signals
  deepest-first.
- **Adaptive polling.** ~30s when healthy, ~5s under warn, ~1s under critical —
  near-zero cost idle, seconds of reaction time at the cliff.
- **Two pressure signals.** `kern.memorystatus_level` lags fast leaks because
  macOS absorbs them by swapping first (observed: +6 GB swap in 90s while level
  stayed ≥34). Swap growth between ticks past `swap_spike_mb` therefore counts
  as warn-level pressure; `swap_delta` is journaled per snapshot for tuning.
- **Hog ceiling for slow leaks.** A leak creeping a few MB per minute trips
  neither signal, so a disposable process over `hog_mb` is stopped even when
  the system is healthy. Because a paused process frees almost nothing, hogs
  keep escalating while over the cap instead of holding RAM frozen forever.
- **Observe is the default mode.** The same code path logs every decision it
  *would* take; no signal is ever sent. Data collected there tunes the tiers
  and thresholds before `protect` is enabled.
- **LaunchAgent, not daemon.** Victims are user-owned dev tools; root is
  unnecessary and unwarranted exposure.

## Testing

`internal/guard` acts through the `Sys` interface (memory, processes, signal),
so tests drive the full ladder against a fake with an injected clock — no
sleeps, no real signals. `internal/score` and `internal/config` are table
tests.
