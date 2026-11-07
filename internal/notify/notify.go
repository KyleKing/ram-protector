// Package notify posts macOS Notification Center notifications via osascript.
package notify

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const osascript = "/usr/bin/osascript"

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ")

// Send posts a notification. Launchd agents have a minimal PATH, so the
// osascript path is absolute.
func Send(ctx context.Context, title, body string) error {
	script := `display notification "` + escaper.Replace(body) +
		`" with title "` + escaper.Replace(title) + `"`
	//nolint:gosec // G204: fixed binary, operator-owned strings
	if err := exec.CommandContext(ctx, osascript, "-e", script).Run(); err != nil {
		return fmt.Errorf("osascript: %w", err)
	}

	return nil
}
