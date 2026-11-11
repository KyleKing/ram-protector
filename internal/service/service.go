// Package service installs and removes the launchd LaunchAgent that keeps
// the daemon running.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Label is the launchd job label.
const Label = "com.kyleking.sys-guardian"

const (
	dirPerm  = 0o750
	filePerm = 0o600
)

// ProcessType=Interactive keeps app-level resource limits: Background-class
// jobs are what launchd sheds first as "inefficient" under load.
const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>%s</string>
	<key>ProgramArguments</key>
	<array><string>%s</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>10</integer>
	<key>ProcessType</key><string>Interactive</string>
	<key>StandardOutPath</key><string>%s/daemon.log</string>
	<key>StandardErrorPath</key><string>%s/daemon.log</string>
</dict>
</plist>
`

// PlistPath is where the agent definition lives.
func PlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home: %w", err)
	}

	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

// Install writes the plist for the current executable and bootstraps it.
func Install(ctx context.Context, logDir string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolving executable: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if err := os.MkdirAll(logDir, dirPerm); err != nil {
		return "", fmt.Errorf("creating log dir: %w", err)
	}

	plist, err := PlistPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(plist), dirPerm); err != nil {
		return "", fmt.Errorf("creating LaunchAgents dir: %w", err)
	}
	body := fmt.Sprintf(plistTemplate, Label, exe, logDir, logDir)
	if err := os.WriteFile(plist, []byte(body), filePerm); err != nil {
		return "", fmt.Errorf("writing plist: %w", err)
	}

	domain := "gui/" + strconv.Itoa(os.Getuid())
	if Running(ctx) {
		//nolint:gosec // G204: fixed binary, constant label
		if out, err := exec.CommandContext(ctx, "launchctl", "bootout", domain+"/"+Label).CombinedOutput(); err != nil {
			return plist, fmt.Errorf("launchctl bootout: %w: %s", err, string(out))
		}
	}
	//nolint:gosec // G204: fixed binary, operator-owned paths
	if out, err := exec.CommandContext(ctx, "launchctl", "bootstrap", domain, plist).CombinedOutput(); err != nil {
		return plist, fmt.Errorf("launchctl bootstrap: %w: %s", err, string(out))
	}

	return plist, nil
}

// Uninstall bootouts the agent and deletes its plist.
func Uninstall(ctx context.Context) error {
	plist, err := PlistPath()
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	//nolint:gosec // G204: fixed binary, constant label
	bootout := exec.CommandContext(ctx, "launchctl", "bootout", domain+"/"+Label).Run()
	rmErr := os.Remove(plist)
	if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("removing plist: %w", rmErr)
	}
	if bootout != nil && errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("launchctl bootout: %w", bootout)
	}

	return nil
}

// Running reports whether the agent is currently bootstrapped.
func Running(ctx context.Context) bool {
	domain := "gui/" + strconv.Itoa(os.Getuid())

	//nolint:gosec // G204: fixed binary, constant label
	return exec.CommandContext(ctx, "launchctl", "print", domain+"/"+Label).Run() == nil
}
