package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

type pinentryClient struct {
	cmd    *exec.Cmd
	reader *bufio.Reader
	writer *bufio.Writer
}

func newPinentry() (*pinentryClient, error) {
	cmd := exec.Command("pinentry")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("pinentry: %w", err)
	}
	p := &pinentryClient{
		cmd:    cmd,
		reader: bufio.NewReader(stdout),
		writer: bufio.NewWriter(stdin),
	}
	line, err := p.readline()
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("pinentry: read greeting: %w", err)
	}
	if !strings.HasPrefix(line, "OK") {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, fmt.Errorf("pinentry: unexpected greeting: %s", line)
	}
	return p, nil
}

func (p *pinentryClient) readline() (string, error) {
	line, err := p.reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// send sends a command and reads a response line.
func (p *pinentryClient) send(cmd string) (string, error) {
	if _, err := fmt.Fprintf(p.writer, "%s\n", cmd); err != nil {
		return "", err
	}
	if err := p.writer.Flush(); err != nil {
		return "", err
	}
	return p.readline()
}

// sendOK sends a command and expects OK.
func (p *pinentryClient) sendOK(cmd string) error {
	resp, err := p.send(cmd)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("pinentry: %s -> %s", cmd, resp)
	}
	return nil
}

func (p *pinentryClient) close() {
	p.send("BYE") //nolint
	p.cmd.Wait()
}

// percentEncode encodes a pinentry description string (newlines as %0A).
func percentEncode(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// getPin runs GETPIN and returns the entered PIN, or "" if cancelled.
func (p *pinentryClient) getPin() (string, error) {
	resp, err := p.send("GETPIN")
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(resp, "D ") {
		pin := resp[2:]
		// consume trailing OK
		p.readline()
		return pin, nil
	}
	if strings.HasPrefix(resp, "ERR") {
		return "", nil // cancelled or error treated as cancel
	}
	return "", fmt.Errorf("pinentry: GETPIN unexpected response: %s", resp)
}

// collectPIN opens pinentry to collect an existing PIN.
// Returns "" if user cancels.
func collectPIN(providerID string, attemptsLeft int32) (string, error) {
	p, err := newPinentry()
	if err != nil {
		return "", err
	}
	defer p.close()

	desc := fmt.Sprintf("Enter PIN for %s", providerID)
	if attemptsLeft >= 0 {
		desc += fmt.Sprintf("\n%d attempt(s) remaining", attemptsLeft)
	}
	if err := p.sendOK("SETDESC " + percentEncode(desc)); err != nil {
		return "", err
	}
	if err := p.sendOK("SETPROMPT PIN:"); err != nil {
		return "", err
	}
	return p.getPin()
}

// collectNewPIN opens pinentry to collect and confirm a new PIN.
// Returns "" if user cancels.
func collectNewPIN(tokenName string, minLength int32) (string, error) {
	p, err := newPinentry()
	if err != nil {
		return "", err
	}
	defer p.close()

	desc := fmt.Sprintf("Set new PIN for %s", tokenName)
	if minLength > 0 {
		desc += fmt.Sprintf("\nMinimum length: %d characters", minLength)
	}
	if err := p.sendOK("SETDESC " + percentEncode(desc)); err != nil {
		return "", err
	}
	if err := p.sendOK("SETPROMPT New PIN:"); err != nil {
		return "", err
	}
	if err := p.sendOK("SETREPEAT Confirm PIN:"); err != nil {
		return "", err
	}
	if err := p.sendOK("SETREPEATERROR PINs do not match"); err != nil {
		return "", err
	}
	if minLength > 0 {
		p.sendOK("SETQUALITYBAR") //nolint best-effort
	}
	return p.getPin()
}
