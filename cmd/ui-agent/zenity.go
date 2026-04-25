package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type touchDialog struct {
	cmd   *exec.Cmd
	stdin io.Closer
}

// startTouchDialog launches a non-blocking zenity progress dialog prompting a touch.
// Zenity reads from stdin; keeping the pipe open holds the dialog until close() is called.
func startTouchDialog(operation, rpID string) *touchDialog {
	cmd := exec.Command("zenity",
		"--progress",
		"--pulsate",
		"--no-cancel",
		"--title=Touch your authenticator",
		fmt.Sprintf("--text=Operation: %s\nSite: %s\n\nTouch your key now.", operation, rpID),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return &touchDialog{cmd: cmd}
	}
	cmd.Start() //nolint best-effort
	return &touchDialog{cmd: cmd, stdin: stdin}
}

func (td *touchDialog) close() {
	if td.stdin != nil {
		td.stdin.Close()
	}
	if td.cmd.Process != nil {
		td.cmd.Process.Kill()
	}
}

// selectAuthenticator shows a zenity radiolist for authenticator selection.
// labels is a slice of display strings. Returns selected index or -1 if cancelled.
func selectAuthenticator(operation, rpID string, labels []string) (int, error) {
	if len(labels) == 0 {
		return -1, nil
	}

	args := []string{
		"--list", "--radiolist",
		"--title=Select Authenticator",
		fmt.Sprintf("--text=Operation: %s\nSite: %s", operation, rpID),
		"--column=", "--column=Authenticator",
	}
	for i, label := range labels {
		toggle := "FALSE"
		if i == 0 {
			toggle = "TRUE"
		}
		args = append(args, toggle, label)
	}

	out, err := exec.Command("zenity", args...).Output()
	if err != nil {
		// exit code 1 = user cancelled
		return -1, nil
	}
	selected := strings.TrimRight(string(out), "\n")
	if selected == "" {
		return -1, nil
	}
	for i, label := range labels {
		if label == selected {
			return i, nil
		}
	}
	return -1, fmt.Errorf("zenity: selected label %q not in list", selected)
}

// confirmReset shows a zenity warning dialog for a destructive reset operation.
// Returns true if user confirmed.
func confirmReset(tokenName string) bool {
	text := fmt.Sprintf(
		"This will permanently erase ALL credentials on:\n\n    %s\n\n"+
			"The device must have been physically removed and reinserted "+
			"immediately before confirming.\n\nThis action cannot be undone.",
		tokenName,
	)
	err := exec.Command("zenity",
		"--question",
		"--title=Reset Authenticator?",
		"--text="+text,
		"--ok-label=Reset",
		"--cancel-label=Cancel",
		"--default-cancel",
	).Run()
	return err == nil
}

// notifyOperation sends a desktop notification (best-effort).
func notifyOperation(operation, rpID, status string) {
	var summary, body string
	switch status {
	case "success":
		summary = "Passkey operation succeeded"
		body = fmt.Sprintf("%s — %s", operation, rpID)
	case "failed":
		summary = "Passkey operation failed"
		body = fmt.Sprintf("%s — %s", operation, rpID)
	case "cancelled":
		summary = "Passkey operation cancelled"
		body = fmt.Sprintf("%s — %s", operation, rpID)
	default:
		return // skip "started" and unknown statuses
	}
	exec.Command("notify-send", "--urgency=low", summary, body).Run() //nolint best-effort
}
