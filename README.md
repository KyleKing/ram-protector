# ram-protector

Prevents multiple high-RAM processes from crashing a Mac

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


## Development

```bash
mise install && hk install --mise
mise run ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development workflow.
