# ram-protector

Prevents multiple high-RAM processes from crashing a Mac

macOS never kills a runaway userspace process — it compresses memory, then
grows swap until the VM deadlocks and the machine beach-balls or panics.
ram-protector is a lightweight LaunchAgent that watches `kern.memorystatus_level`
and intervenes before that cliff: it **pauses** (SIGSTOP) the worst offender,
**resumes** it if pressure clears, and escalates to **SIGTERM → SIGKILL** if it
doesn't. Victim ranking prefers restart-safe processes (tsc, language servers,
Electron helpers) over interactive ones (terminals, editors, browsers) — but at
critical pressure nothing is off-limits.

## Installation

### GH CLI Extension

> **Note:** Requires a [GitHub Release](https://github.com/kyleking/ram-protector/releases) with precompiled binaries. See [CONTRIBUTING.md](CONTRIBUTING.md#releases) for creating the first release.

```bash
gh extension install kyleking/ram-protector
```

### Homebrew

goreleaser publishes a cask to [`kyleking/homebrew-tap`](https://github.com/kyleking/homebrew-tap) with each release, so the install needs `--cask`:

```bash
brew install --cask kyleking/tap/ram-protector
```

### Go Install

```bash
go install github.com/kyleking/ram-protector/cmd/ram-protector@latest
```

## Usage

```bash
ram-protector check       # memory level + current victim ranking
ram-protector install     # write + bootstrap the LaunchAgent (runs daemon)
ram-protector status      # level, agent state, recent journal events
ram-protector log -n 50   # journal tail
ram-protector uninstall   # bootout + remove the agent
```

Default mode is **`observe`**: full scoring and decision logging, zero signals
sent — run it for a while, review `~/Library/Logs/ram-protector/events.jsonl`,
then flip to `protect`:

```toml
# ~/.config/ram-protector/config.toml
mode = "protect"

# All optional — defaults shown:
# warn_level = 20        # act below this % memory available
# critical_level = 8     # last-resort tier eligible below this
# resume_level = 30      # SIGCONT held processes above this
# term_after = "45s"     # paused this long under pressure → SIGTERM
# kill_after = "10s"     # SIGTERM → SIGKILL grace
# mem_floor_mb = 512     # ignore smaller processes
# swap_spike_mb = 1024   # swap growing this fast counts as warn-level pressure
# extra_disposable = ["my-tool"]
# extra_never = ["do-not-touch"]   # extra_* lists override built-ins by tier
```

## Development

```bash
mise install && hk install --mise
mise run ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development workflow.
