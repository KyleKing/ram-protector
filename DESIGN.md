# Design

## Architecture

`cmd/sys-guardian` is a thin dispatcher over `internal/` packages:

- `internal/mem` — `kern.memorystatus_level` (% physical memory available),
  load1/5/15, and swap/phys totals via gopsutil. The implementation is
  build-tagged darwin with an erroring stub on other OSes, so Linux CI still
  compiles and lints the package
- `internal/proc` — process snapshot (pid, ppid, name, cmdline, RSS, CPU time,
  start time) via one bulk `kern.proc.all` read plus one `proc_pidinfo` per
  process; gopsutil supplies the non-darwin fallback
- `internal/score` — victim ranking: RSS_GiB × tier × age × growth × cpu, with a
  human-readable reason per factor for the journal. Tiers: `never` >
  `disposable` > `last_resort` > `neutral`, matched as substrings over name +
  cmdline; Apple platform binaries (argv[0] under `/System`, `/usr/libexec`,
  `/usr/sbin`, `/sbin`) land in `last_resort`. Only the previous snapshot per
  PID is kept.
- `internal/guard` — the state machine. One victim per tick:
  SIGSTOP the tree (parent first, so it can't re-fork) → TERM deepest-first
  after `term_after` if pressure persists → SIGKILL after `kill_after`.
  Resume (SIGCONT) after `resume_ticks` consecutive reads ≥ `resume_level`
  with no pressure, and never before `min_pause` has elapsed — a faster
  recovery reads as flapping, not relief.
  `paused.json` persists held victims so a restart re-adopts them (matched by
  PID + start time); `Run` resumes everything it paused on exit.
- `internal/journal` — append-only JSONL at `~/Library/Logs/sys-guardian/
  events.jsonl`: `snapshot` every tick (level, swap, load averages, top-5 by
  RSS and by recent CPU), `decision` (top-5 scored candidates + chosen
  action), `action`, `resume`. This doubles as the tuning dataset for
  observe mode.
- `internal/notify` — transient banners for pause/resume, sticky `display
  alert` dialogs for TERM/KILL, one open at a time
- `internal/service` — `~/Library/LaunchAgents/com.kyleking.sys-guardian.plist`
  (KeepAlive, ProcessType=Interactive so launchd sheds the daemon last)
- `internal/config` — TOML at `~/.config/sys-guardian/config.toml`; all fields
  optional

## Key decisions

- **Pause first, kill as fallback.** SIGSTOP is reversible and stops growth +
  CPU burn immediately, but frees almost nothing (~0.03 GiB reclaimable vs
  ~0.6 GiB for kill) — so it is the first rung, never the last. Escalation
  runs only while pressure persists (below `warn_level`, or swap still growing
  inside a spike window); between warn and resume the victim stays paused
  indefinitely. A killed victim's name + cmdline enters a cooldown keyed by
  identity, not PID, so a supervisor respawn is not churn-killed.
- **Kill the tree, not the pid.** Children reparent to launchd and survive a
  lone-parent kill; the guard SIGSTOPs the whole tree first, then signals
  deepest-first.
- **Adaptive polling.** ~30s when healthy, ~5s under warn, ~1s under critical —
  near-zero cost idle, seconds of reaction time at the cliff.
- **Two pressure signals.** `kern.memorystatus_level` lags fast leaks because
  macOS absorbs them by swapping first (observed: +6 GB swap in 90s while level
  stayed ≥34). Swap growth between ticks past `swap_spike_mb` therefore counts
  as warn-level pressure; `swap_delta` is journaled per snapshot for tuning.
  A spike stays pressure for `spike_hold` (renewed while swap keeps growing
  past `swap_growth_mb`), which both blocks resume mid-storm and keeps the
  TERM/KILL ladder reachable — spike victims escalate only while swap still
  grows, so a single spike that goes flat only holds, never kills.
- **CPU burn trigger.** A disposable process sustaining more than
  `cpu_burn_pct` for `cpu_burn_for` is paused even at healthy memory; the
  timer resets the tick it cools off, and after resume it must burn the full
  duration again before it is re-paused.
- **System load trigger.** A single runaway trips `cpu_burn`, but a
  distributed storm — N workers at ~25% each — never does. When load1 per
  core sustains over `load_per_core` for `load_for`, the biggest CPU
  consumer in the disposable or neutral tier is paused once per tick;
  SIGSTOP alone relieves it, so no escalation ladder runs. The storm keeps
  counting as pressure (blocking resume) until load1 per core drops under
  `load_resume_per_core`. `kern.memorystatus_level` stayed at 40–75%
  throughout a real storm that crashed three apps and got the daemon itself
  reaped by launchd — memory signals alone could not see it.
- **Hog ceiling for slow leaks.** A leak creeping a few MB per minute trips
  neither signal, so a disposable process over `hog_mb` is stopped even when
  the system is healthy. A paused process frees almost nothing, but freezing
  already stops the growth — so hogs stay frozen while over the cap and
  escalate only under real pressure, like every held victim.
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
