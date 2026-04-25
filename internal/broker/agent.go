package broker

import (
	"log"
	"sync"
	"time"

	"github.com/cmouse/dbus-passkey/internal/types"
	"github.com/godbus/dbus/v5"
)

const uiAgentIface = "org.freedesktop.PasskeyBroker.UIAgent"

// agentRegistry holds the currently registered UI agent (last-write-wins).
type agentRegistry struct {
	mu        sync.RWMutex
	path      dbus.ObjectPath
	senderBus string // unique bus name of registering client
}

func (ar *agentRegistry) set(path dbus.ObjectPath, sender string) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	ar.path = path
	ar.senderBus = sender
	log.Printf("ui agent registered: %s (sender %s)", path, sender)
}

func (ar *agentRegistry) clear(sender string) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	if ar.senderBus == sender {
		log.Printf("ui agent unregistered: %s", ar.path)
		ar.path = ""
		ar.senderBus = ""
	}
}

// get returns path and sender atomically under read lock.
func (ar *agentRegistry) get() (dbus.ObjectPath, string) {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return ar.path, ar.senderBus
}

// selectAuthenticator calls SelectAuthenticator on the UI agent.
// Returns selected index (-1 = cancelled) and any error.
func (b *Broker) selectAuthenticator(
	conn *dbus.Conn,
	requestPath dbus.ObjectPath,
	operation string,
	rpID string,
	candidates []types.Candidate,
	timeout time.Duration,
) (int, error) {
	agentPath, agentSender := b.agent.get()
	if agentPath == "" {
		return 0, nil // auto-pick first
	}

	dbusCandidate := make([]map[string]dbus.Variant, len(candidates))
	for i, c := range candidates {
		dbusCandidate[i] = map[string]dbus.Variant{
			"provider_id":       dbus.MakeVariant(c.ProviderID),
			"provider_name":     dbus.MakeVariant(c.ProviderName),
			"provider_type":     dbus.MakeVariant(c.ProviderType),
			"transports":        dbus.MakeVariant(c.Transports),
			"credential_id":     dbus.MakeVariant(c.CredentialID),
			"user_name":         dbus.MakeVariant(c.UserName),
			"user_display_name": dbus.MakeVariant(c.UserDisplayName),
		}
	}

	obj := conn.Object(agentSender, agentPath)

	type result struct {
		idx int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var idx int32
		call := obj.Call(uiAgentIface+".SelectAuthenticator", 0,
			requestPath, operation, rpID, dbusCandidate)
		if call.Err != nil {
			ch <- result{err: call.Err}
			return
		}
		if err := call.Store(&idx); err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{idx: int(idx)}
	}()

	select {
	case r := <-ch:
		return r.idx, r.err
	case <-time.After(timeout):
		return -1, nil // treat timeout as interaction-ended
	}
}

// collectPIN calls CollectPIN on the UI agent.
// Returns PIN bytes (caller must clear after use) or nil if cancelled.
func (b *Broker) collectPIN(
	conn *dbus.Conn,
	requestPath dbus.ObjectPath,
	rpID string,
	providerID string,
	attemptsLeft int,
	timeout time.Duration,
) ([]byte, error) {
	agentPath, agentSender := b.agent.get()
	if agentPath == "" {
		return nil, nil
	}

	obj := conn.Object(agentSender, agentPath)

	type result struct {
		pin string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var pin string
		call := obj.Call(uiAgentIface+".CollectPIN", 0,
			requestPath, rpID, providerID, int32(attemptsLeft))
		if call.Err != nil {
			ch <- result{err: call.Err}
			return
		}
		if err := call.Store(&pin); err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{pin: pin}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if r.pin == "" {
			return nil, nil
		}
		return []byte(r.pin), nil
	case <-time.After(timeout):
		return nil, nil
	}
}

// notifyOperation calls NotifyOperation on the UI agent (best-effort, no error returned).
func (b *Broker) notifyOperation(
	conn *dbus.Conn,
	requestPath dbus.ObjectPath,
	operation string,
	rpID string,
	status string,
) {
	agentPath, agentSender := b.agent.get()
	if agentPath == "" {
		return
	}
	obj := conn.Object(agentSender, agentPath)
	go obj.Call(uiAgentIface+".NotifyOperation", dbus.FlagNoReplyExpected,
		requestPath, operation, rpID, status)
}
