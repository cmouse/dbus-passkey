package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

const agentIface = "org.freedesktop.PasskeyBroker.UIAgent"

type agentService struct {
	mu            sync.Mutex // serialise concurrent broker calls
	touchDialogMu sync.Mutex
	touchDialogs  map[dbus.ObjectPath]*touchDialog
}

// varStr extracts a string from a candidate variant map.
func varStr(m map[string]dbus.Variant, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.Value().(string)
	return s
}

// varStrSlice extracts a []string from a candidate variant map.
func varStrSlice(m map[string]dbus.Variant, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	ss, _ := v.Value().([]string)
	return ss
}

// candidateLabel builds a human-readable label for a candidate map.
func candidateLabel(c map[string]dbus.Variant) string {
	name := varStr(c, "provider_name")
	ptype := varStr(c, "provider_type")
	transports := varStrSlice(c, "transports")
	parts := append([]string{}, transports...)
	if ptype != "" {
		parts = append(parts, ptype)
	}
	if len(parts) > 0 {
		return fmt.Sprintf("%s [%s]", name, strings.Join(parts, ", "))
	}
	return name
}

func decodeCandidates(raw []map[string]dbus.Variant) []map[string]dbus.Variant {
	return raw
}

func (a *agentService) SelectAuthenticator(
	rh dbus.ObjectPath,
	operation, rpID string,
	rawCandidates []map[string]dbus.Variant,
) (int32, *dbus.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	candidates := decodeCandidates(rawCandidates)
	labels := make([]string, len(candidates))
	for i, c := range candidates {
		labels[i] = candidateLabel(c)
	}

	idx, err := selectAuthenticator(operation, rpID, labels)
	if err != nil {
		return -1, dbus.MakeFailedError(err)
	}
	return int32(idx), nil
}

func (a *agentService) CollectPIN(
	rh dbus.ObjectPath,
	rpID, providerID string,
	attemptsLeft int32,
) (string, *dbus.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pin, err := collectPIN(providerID, attemptsLeft)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return pin, nil
}

func (a *agentService) CollectNewPIN(
	rh dbus.ObjectPath,
	tokenID, tokenName string,
	minLength int32,
) (string, *dbus.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pin, err := collectNewPIN(tokenName, minLength)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return pin, nil
}

func (a *agentService) ConfirmReset(
	rh dbus.ObjectPath,
	tokenID, tokenName string,
) (bool, *dbus.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return confirmReset(tokenName), nil
}

func (a *agentService) NotifyOperation(
	rh dbus.ObjectPath,
	operation, rpID, status string,
) *dbus.Error {
	switch status {
	case "waiting_for_touch":
		td := startTouchDialog(operation, rpID)
		a.touchDialogMu.Lock()
		if a.touchDialogs == nil {
			a.touchDialogs = make(map[dbus.ObjectPath]*touchDialog)
		}
		a.touchDialogs[rh] = td
		a.touchDialogMu.Unlock()
	case "success", "failed", "cancelled":
		a.touchDialogMu.Lock()
		td := a.touchDialogs[rh]
		delete(a.touchDialogs, rh)
		a.touchDialogMu.Unlock()
		if td != nil {
			td.close()
		}
	}
	return nil
}
