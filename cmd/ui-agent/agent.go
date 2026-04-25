package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

const agentIface = "org.freedesktop.PasskeyBroker.UIAgent"

type agentService struct {
	mu sync.Mutex // serialise concurrent broker calls
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

// decodeCandidates handles the godbus aa{sv} decode ambiguity.
func decodeCandidates(raw interface{}) []map[string]dbus.Variant {
	switch t := raw.(type) {
	case []map[string]dbus.Variant:
		return t
	case []interface{}:
		out := make([]map[string]dbus.Variant, 0, len(t))
		for _, elem := range t {
			if m, ok := elem.(map[string]dbus.Variant); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func (a *agentService) SelectAuthenticator(
	rh dbus.ObjectPath,
	operation, rpID string,
	rawCandidates interface{},
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
	go notifyOperation(operation, rpID, status)
	return nil
}
