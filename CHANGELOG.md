## v1.0.1 (2026-11-10)

### Fix

- compile on non-darwin so CI and goreleaser pass

## v1.0.0 (2026-11-10)

### Feat

- rename ram-protector to sys-guardian
- hold victims through swap storms and pause sustained cpu burners

## v0.4.0 (2026-11-09)

### Feat

- alert on kill only, with parent, age, and cmdline diagnostics
- sticky alert dialogs for term/kill; tombstone killed pids

### Fix

- use display alert message parameter for sticky dialogs
- show hog ceiling in check output

## v0.3.0 (2026-11-08)

### Feat

- stop disposable hogs over an RSS ceiling even when healthy
- trigger on swap growth, not only memorystatus level

### Fix

- record victim name on signal events in the journal
- class interactive agent CLIs as last-resort victims

## v0.2.0 (2026-11-07)

### Feat

- add pause-first guard state machine and launchd agent
- add victim scoring, journal, and notifications
- add config, memory, and process sampling

## v0.1.0 (2026-11-07)

### Feat

- Initialize from my_go_template
