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

// Alert shows a dialog that stays on screen until dismissed; it blocks until
// the user clicks OK, so callers run it in a goroutine. Unlike a notification
// banner there is no timeout: the process lives as long as the dialog does.
func Alert(title, body string) error {
	script := `display alert "` + escaper.Replace(title) +
		`" message "` + escaper.Replace(body) + `"`
	//nolint:gosec,noctx // fixed binary; dialog intentionally outlives caller context
	if err := exec.Command(osascript, "-e", script).Run(); err != nil {
		return fmt.Errorf("osascript alert: %w", err)
	}

	return nil
}
