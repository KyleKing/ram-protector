# sys-guardian

Prevents CPU- and memory-hungry processes from crashing a Mac

**macOS only.** The pressure signal is `kern.memorystatus_level`, victims are
handled with POSIX signals, and the agent is a launchd LaunchAgent — none of
which exist elsewhere. Other OSes compile (CI runs on Linux) but the daemon
refuses to run, and Windows does not build at all.

macOS never kills a runaway userspace process — it compresses memory, then
grows swap until the VM deadlocks and the machine beach-balls or panics.
sys-guardian is a lightweight LaunchAgent that watches `kern.memorystatus_level`
and intervenes before that cliff: it **pauses** (SIGSTOP) the worst offender,
**resumes** it if pressure clears, and escalates to **SIGTERM → SIGKILL** if it
doesn't. Victim ranking prefers restart-safe processes (tsc, language servers,
Electron helpers) over interactive ones (terminals, editors, browsers) — but at
critical pressure nothing is off-limits.

## Installation

### GH CLI Extension

> **Note:** Requires a [GitHub Release](https://github.com/kyleking/sys-guardian/releases) with precompiled binaries. See [CONTRIBUTING.md](CONTRIBUTING.md#releases) for creating the first release.

```bash
gh extension install kyleking/sys-guardian
```

### Homebrew

goreleaser publishes a cask to [`kyleking/homebrew-tap`](https://github.com/kyleking/homebrew-tap) with each release, so the install needs `--cask`:

```bash
brew install --cask kyleking/tap/sys-guardian
```

### Go Install

```bash
go install github.com/kyleking/sys-guardian/cmd/sys-guardian@latest
```

## Usage

```bash
sys-guardian check       # memory level + current victim ranking
sys-guardian install     # write + bootstrap the LaunchAgent (runs daemon)
sys-guardian status      # level, agent state, recent journal events
sys-guardian log -n 50   # journal tail
sys-guardian uninstall   # bootout + remove the agent
```

Default mode is **`observe`**: full scoring and decision logging, zero signals
sent — run it for a while, review `~/Library/Logs/sys-guardian/events.jsonl`,
then flip to `protect`:

```toml
# ~/.config/sys-guardian/config.toml
mode = "protect"

# All optional — defaults shown:
# warn_level = 35        # act below this % memory available
# critical_level = 30    # last-resort tier eligible below this
# resume_level = 55      # SIGCONT held processes above this
# term_after = "2m"      # paused this long under pressure → SIGTERM
# kill_after = "30s"     # SIGTERM → SIGKILL grace
# mem_floor_mb = 512     # ignore smaller processes
# hog_mb = 12288         # disposable over this is frozen even when healthy; killed only under pressure
# swap_spike_mb = 1024   # swap growing this fast per tick counts as warn-level pressure
# swap_growth_mb = 128   # swap still growing past this keeps spike victims escalating
# spike_hold = "2m"      # a spike stays pressure for this long (blocks resume)
# min_pause = "2m"       # a stopped victim is never resumed sooner than this
# cpu_burn_pct = 150     # disposable process over this %CPU sustained for...
# cpu_burn_for = "2m"    #   ...this long is paused even when memory is healthy
# load_per_core = 1.5    # load1/core above this for load_for is a CPU storm
# load_for = "90s"       #   sustained this long before pausing top CPU consumers
# load_resume_per_core = 0.8  # storm clears below this; held processes resume
# extra_disposable = ["my-tool"]
# extra_never = ["do-not-touch"]   # extra_* lists override built-ins by tier
```

## Development

```bash
mise install && hk install --mise
mise run ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development workflow.
