package main

import (
	"fmt"
	"os/exec"
	"strings"
)

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
		"--column=", "--column=Authenticator", "--column=Index",
		"--hide-column=3",
		"--print-column=3",
	}
	for i, label := range labels {
		toggle := "FALSE"
		if i == 0 {
			toggle = "TRUE"
		}
		args = append(args, toggle, label, fmt.Sprintf("%d", i))
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
	// Parse the index from hidden column output
	var idx int
	if _, err := fmt.Sscanf(selected, "%d", &idx); err != nil {
		return -1, fmt.Errorf("zenity: parse index %q: %w", selected, err)
	}
	if idx < 0 || idx >= len(labels) {
		return -1, fmt.Errorf("zenity: index %d out of range", idx)
	}
	return idx, nil
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
	case "waiting_for_touch":
		summary = "Touch your authenticator"
		body = fmt.Sprintf("%s — %s", operation, rpID)
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
