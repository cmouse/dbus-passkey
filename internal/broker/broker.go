package broker

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cmouse/dbus-passkey/internal/fido2"
	"github.com/cmouse/dbus-passkey/internal/provider"
	"github.com/cmouse/dbus-passkey/internal/types"
	"github.com/godbus/dbus/v5"
)

const (
	brokerIface      = "org.freedesktop.PasskeyBroker"
	brokerPath       = "/org/freedesktop/PasskeyBroker"
	defaultTimeoutMS = 30000
)

// Broker is the core D-Bus service object.
type Broker struct {
	conn     *dbus.Conn
	registry *provider.Registry
	agent    agentRegistry

	mu       sync.Mutex
	requests map[dbus.ObjectPath]*Request
	reqCount atomic.Uint64
}

// New creates and exports a Broker on conn.
func New(conn *dbus.Conn, reg *provider.Registry) (*Broker, error) {
	b := &Broker{
		conn:     conn,
		registry: reg,
		requests: make(map[dbus.ObjectPath]*Request),
	}
	if err := conn.Export(b, brokerPath, brokerIface); err != nil {
		return nil, fmt.Errorf("export broker: %w", err)
	}
	if err := conn.Export(b.introspector(), brokerPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return nil, fmt.Errorf("export introspectable: %w", err)
	}

	// Watch for client disconnects to auto-cancel requests and auto-unregister agent.
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
	); err != nil {
		return nil, fmt.Errorf("add match signal: %w", err)
	}

	go b.watchNameOwnerChanged()
	return b, nil
}

func (b *Broker) watchNameOwnerChanged() {
	ch := make(chan *dbus.Signal, 16)
	b.conn.Signal(ch)
	for sig := range ch {
		if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" {
			continue
		}
		if len(sig.Body) < 3 {
			continue
		}
		name, _ := sig.Body[0].(string)
		newOwner, _ := sig.Body[2].(string)
		if newOwner != "" {
			continue // not a disconnect
		}
		// name is the unique bus name that disconnected
		b.agent.clear(name)
		b.cancelRequestsForSender(name)
	}
}

func (b *Broker) cancelRequestsForSender(sender string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for path, req := range b.requests {
		if req.sender == sender {
			req.cancelOp()
			delete(b.requests, path)
		}
	}
}

// MakeCredential is the D-Bus method handler.
func (b *Broker) MakeCredential(sender dbus.Sender, parentWindow string, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	opts, err := parseMakeCredentialOptions(options)
	if err != nil {
		return "", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{err.Error()})
	}

	path, req := b.newRequest(string(sender))
	if err := exportRequest(b.conn, path, req); err != nil {
		return "", dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{err.Error()})
	}

	b.mu.Lock()
	b.requests[path] = req
	b.mu.Unlock()

	go b.runMakeCredential(req, path, opts)
	return path, nil
}

// GetAssertion is the D-Bus method handler.
func (b *Broker) GetAssertion(sender dbus.Sender, parentWindow string, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	opts, err := parseGetAssertionOptions(options)
	if err != nil {
		return "", dbus.NewError("org.freedesktop.DBus.Error.InvalidArgs", []interface{}{err.Error()})
	}

	path, req := b.newRequest(string(sender))
	if err := exportRequest(b.conn, path, req); err != nil {
		return "", dbus.NewError("org.freedesktop.DBus.Error.Failed", []interface{}{err.Error()})
	}

	b.mu.Lock()
	b.requests[path] = req
	b.mu.Unlock()

	go b.runGetAssertion(req, path, opts)
	return path, nil
}

// RegisterUIAgent is the D-Bus method handler.
func (b *Broker) RegisterUIAgent(sender dbus.Sender, agentPath dbus.ObjectPath) *dbus.Error {
	b.agent.set(agentPath, string(sender))
	return nil
}

// UnregisterUIAgent is the D-Bus method handler.
func (b *Broker) UnregisterUIAgent(sender dbus.Sender, agentPath dbus.ObjectPath) *dbus.Error {
	b.agent.clear(string(sender))
	return nil
}

func (b *Broker) newRequest(sender string) (dbus.ObjectPath, *Request) {
	n := b.reqCount.Add(1)
	escaped := escapeDBusName(sender)
	path := dbus.ObjectPath(fmt.Sprintf("%s/request/%s/%d", brokerPath, escaped, n))
	return path, newRequest(b.conn, path, sender)
}

func (b *Broker) removeRequest(path dbus.ObjectPath) {
	b.mu.Lock()
	delete(b.requests, path)
	b.mu.Unlock()
}

func (b *Broker) runMakeCredential(req *Request, path dbus.ObjectPath, opts *types.MakeCredentialOptions) {
	defer b.removeRequest(path)

	timeout := requestTimeout(opts.TimeoutMS)

	// Enumerate providers
	scoredProviders, credIDs := b.enumerateMakeCredProviders(opts)

	if len(scoredProviders) == 0 {
		req.emitError("NotAllowedError", "no suitable authenticator found")
		return
	}

	// Build candidate descriptors
	candidates := make([]types.Candidate, len(scoredProviders))
	for i, sp := range scoredProviders {
		p := sp.Provider
		candidates[i] = types.Candidate{
			ProviderID:   p.ID(),
			ProviderName: p.Name(),
			ProviderType: p.Type(),
			Transports:   p.Transports(),
			CredentialID: credIDs[p.ID()],
		}
	}

	// Select authenticator
	selectedIdx := 0
	agentPath, _ := b.agent.get()
	if agentPath != "" || len(candidates) > 1 {
		idx, err := b.selectAuthenticator(b.conn, path, "MakeCredential", opts.RPID, candidates, timeout)
		if err != nil {
			log.Printf("SelectAuthenticator error: %v", err)
			req.emitInteractionEnded()
			return
		}
		if idx == -1 {
			req.emitCancelled()
			return
		}
		selectedIdx = idx
	}

	if selectedIdx < 0 || selectedIdx >= len(scoredProviders) {
		req.emitError("NotAllowedError", "invalid authenticator selection")
		return
	}

	selectedProvider := scoredProviders[selectedIdx].Provider

	// Collect PIN if needed
	var pin []byte
	if needsUV(opts.UserVerification) && selectedProvider.Type() == "hardware" {
		var err error
		pin, err = b.collectPIN(b.conn, path, opts.RPID, selectedProvider.ID(), -1, timeout)
		if err != nil {
			req.emitInteractionEnded()
			return
		}
		if pin == nil {
			req.emitCancelled()
			return
		}
	}

	b.notifyOperation(b.conn, path, "MakeCredential", opts.RPID, "started")

	// Check cancellation before calling provider
	select {
	case <-req.cancel:
		clearBytes(pin)
		req.emitCancelled()
		return
	default:
	}

	// Wire cancel channel to provider during the blocking operation.
	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-req.cancel:
			selectedProvider.Cancel()
		case <-stopWatch:
		}
	}()

	result, err := selectedProvider.MakeCredential(opts, pin)
	close(stopWatch)
	clearBytes(pin)

	if err != nil {
		b.notifyOperation(b.conn, path, "MakeCredential", opts.RPID, "failed")
		req.emitError("UnknownError", err.Error())
		return
	}

	b.notifyOperation(b.conn, path, "MakeCredential", opts.RPID, "success")
	req.emitSuccess(result)
}

func (b *Broker) runGetAssertion(req *Request, path dbus.ObjectPath, opts *types.GetAssertionOptions) {
	defer b.removeRequest(path)

	timeout := requestTimeout(opts.TimeoutMS)

	scoredProviders, credIDs := b.enumerateAssertionProviders(opts)

	if len(scoredProviders) == 0 {
		req.emitError("NotAllowedError", "no suitable authenticator found")
		return
	}

	candidates := make([]types.Candidate, len(scoredProviders))
	for i, sp := range scoredProviders {
		p := sp.Provider
		candidates[i] = types.Candidate{
			ProviderID:   p.ID(),
			ProviderName: p.Name(),
			ProviderType: p.Type(),
			Transports:   p.Transports(),
			CredentialID: credIDs[p.ID()],
		}
	}

	selectedIdx := 0
	agentPath, _ := b.agent.get()
	if agentPath != "" || len(candidates) > 1 {
		idx, err := b.selectAuthenticator(b.conn, path, "GetAssertion", opts.RPID, candidates, timeout)
		if err != nil {
			log.Printf("SelectAuthenticator error: %v", err)
			req.emitInteractionEnded()
			return
		}
		if idx == -1 {
			req.emitCancelled()
			return
		}
		selectedIdx = idx
	}

	if selectedIdx < 0 || selectedIdx >= len(scoredProviders) {
		req.emitError("NotAllowedError", "invalid authenticator selection")
		return
	}

	selectedProvider := scoredProviders[selectedIdx].Provider

	var pin []byte
	if needsUV(opts.UserVerification) && selectedProvider.Type() == "hardware" {
		var err error
		pin, err = b.collectPIN(b.conn, path, opts.RPID, selectedProvider.ID(), -1, timeout)
		if err != nil {
			req.emitInteractionEnded()
			return
		}
		if pin == nil {
			req.emitCancelled()
			return
		}
	}

	b.notifyOperation(b.conn, path, "GetAssertion", opts.RPID, "started")

	select {
	case <-req.cancel:
		clearBytes(pin)
		req.emitCancelled()
		return
	default:
	}

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-req.cancel:
			selectedProvider.Cancel()
		case <-stopWatch:
		}
	}()

	result, err := selectedProvider.GetAssertion(opts, pin)
	close(stopWatch)
	clearBytes(pin)

	if err != nil {
		b.notifyOperation(b.conn, path, "GetAssertion", opts.RPID, "failed")
		req.emitError("UnknownError", err.Error())
		return
	}

	b.notifyOperation(b.conn, path, "GetAssertion", opts.RPID, "success")
	req.emitSuccess(result)
}

func (b *Broker) enumerateMakeCredProviders(opts *types.MakeCredentialOptions) ([]provider.ScoredProvider, map[string][]byte) {
	var all []provider.ScoredProvider
	credIDs := map[string][]byte{}

	// Hardware tokens
	devices, err := fido2.EnumerateDevices()
	if err != nil {
		log.Printf("fido2 enumerate: %v", err)
	}
	for _, d := range devices {
		all = append(all, provider.ScoredProvider{Provider: d, Priority: 100})
	}

	// Software providers from registry
	for _, entry := range b.registry.Entries() {
		p := provider.NewDBusProvider(b.conn, entry)
		all = append(all, provider.ScoredProvider{Provider: p, Priority: entry.Priority})
	}

	filtered := provider.SelectCandidates(all, opts)
	return filtered, credIDs
}

func (b *Broker) enumerateAssertionProviders(opts *types.GetAssertionOptions) ([]provider.ScoredProvider, map[string][]byte) {
	var all []provider.ScoredProvider
	credIDs := map[string][]byte{}
	hasCredsMap := map[string][][]byte{}

	devices, err := fido2.EnumerateDevices()
	if err != nil {
		log.Printf("fido2 enumerate: %v", err)
	}
	for _, d := range devices {
		allowList := make([][]byte, len(opts.AllowCredentials))
		for i, c := range opts.AllowCredentials {
			allowList[i] = c.ID
		}
		ids, err := d.HasCredentials(opts.RPID, allowList)
		if err == nil && len(ids) > 0 {
			all = append(all, provider.ScoredProvider{Provider: d, Priority: 100})
			if len(ids) > 0 && ids[0] != nil {
				credIDs[d.ID()] = ids[0]
			}
		}
	}

	for _, entry := range b.registry.Entries() {
		p := provider.NewDBusProvider(b.conn, entry)
		allowList := make([][]byte, len(opts.AllowCredentials))
		for i, c := range opts.AllowCredentials {
			allowList[i] = c.ID
		}
		ids, err := p.HasCredentials(opts.RPID, allowList)
		if err == nil && len(ids) > 0 {
			hasCredsMap[p.ID()] = ids
			all = append(all, provider.ScoredProvider{Provider: p, Priority: entry.Priority})
			if len(ids) > 0 && ids[0] != nil {
				credIDs[p.ID()] = ids[0]
			}
		}
	}

	filtered := provider.SelectAssertionCandidates(all, opts, hasCredsMap)
	return filtered, credIDs
}

func parseMakeCredentialOptions(v map[string]dbus.Variant) (*types.MakeCredentialOptions, error) {
	opts := &types.MakeCredentialOptions{}
	var ok bool
	if opts.RPID, ok = variantString(v, "rp_id"); !ok || opts.RPID == "" {
		return nil, fmt.Errorf("missing required field: rp_id")
	}
	if opts.RPName, ok = variantString(v, "rp_name"); !ok || opts.RPName == "" {
		return nil, fmt.Errorf("missing required field: rp_name")
	}
	if opts.UserID, ok = variantBytes(v, "user_id"); !ok || len(opts.UserID) == 0 {
		return nil, fmt.Errorf("missing required field: user_id")
	}
	if opts.UserName, ok = variantString(v, "user_name"); !ok || opts.UserName == "" {
		return nil, fmt.Errorf("missing required field: user_name")
	}
	if opts.Challenge, ok = variantBytes(v, "challenge"); !ok || len(opts.Challenge) < 16 {
		return nil, fmt.Errorf("missing or too-short required field: challenge (min 16 bytes)")
	}
	opts.UserDisplayName, _ = variantString(v, "user_display_name")
	opts.AuthenticatorAttachment, _ = variantString(v, "authenticator_attachment")
	opts.ResidentKey, _ = variantString(v, "resident_key")
	opts.UserVerification, _ = variantString(v, "user_verification")
	opts.Attestation, _ = variantString(v, "attestation")
	if ms, ok := variantUint32(v, "timeout_ms"); ok {
		opts.TimeoutMS = ms
	}
	// pub_key_cred_params — required
	if raw, ok := v["pub_key_cred_params"]; ok {
		params, _ := raw.Value().([]map[string]dbus.Variant)
		for _, pm := range params {
			typ, _ := pm["type"].Value().(string)
			alg, _ := pm["alg"].Value().(int32)
			opts.PubKeyCredParams = append(opts.PubKeyCredParams, types.CredentialParam{Type: typ, Alg: alg})
		}
	}
	if len(opts.PubKeyCredParams) == 0 {
		return nil, fmt.Errorf("missing required field: pub_key_cred_params")
	}
	// exclude_credentials — optional
	if raw, ok := v["exclude_credentials"]; ok {
		excl, _ := raw.Value().([]map[string]dbus.Variant)
		for _, em := range excl {
			typ, _ := em["type"].Value().(string)
			id, _ := em["id"].Value().([]byte)
			transports, _ := em["transports"].Value().([]string)
			opts.ExcludeCredentials = append(opts.ExcludeCredentials, types.CredentialDescriptor{
				Type: typ, ID: id, Transports: transports,
			})
		}
	}
	return opts, nil
}

func parseGetAssertionOptions(v map[string]dbus.Variant) (*types.GetAssertionOptions, error) {
	opts := &types.GetAssertionOptions{}
	var ok bool
	if opts.RPID, ok = variantString(v, "rp_id"); !ok || opts.RPID == "" {
		return nil, fmt.Errorf("missing required field: rp_id")
	}
	if opts.Challenge, ok = variantBytes(v, "challenge"); !ok || len(opts.Challenge) < 16 {
		return nil, fmt.Errorf("missing or too-short required field: challenge")
	}
	opts.UserVerification, _ = variantString(v, "user_verification")
	if ms, ok := variantUint32(v, "timeout_ms"); ok {
		opts.TimeoutMS = ms
	}
	if raw, ok := v["allow_credentials"]; ok {
		allow, _ := raw.Value().([]map[string]dbus.Variant)
		for _, am := range allow {
			typ, _ := am["type"].Value().(string)
			id, _ := am["id"].Value().([]byte)
			transports, _ := am["transports"].Value().([]string)
			opts.AllowCredentials = append(opts.AllowCredentials, types.CredentialDescriptor{
				Type: typ, ID: id, Transports: transports,
			})
		}
	}
	return opts, nil
}

func variantString(m map[string]dbus.Variant, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.Value().(string)
	return s, ok
}

func variantBytes(m map[string]dbus.Variant, key string) ([]byte, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	b, ok := v.Value().([]byte)
	return b, ok
}

func variantUint32(m map[string]dbus.Variant, key string) (uint32, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	n, ok := v.Value().(uint32)
	return n, ok
}

func escapeDBusName(name string) string {
	// Unique bus names like :1.42 → _1_42
	r := strings.NewReplacer(":", "_", ".", "_")
	return r.Replace(name)
}

func requestTimeout(ms uint32) time.Duration {
	if ms == 0 {
		return time.Duration(defaultTimeoutMS) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

func needsUV(uv string) bool {
	return uv == "required"
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (b *Broker) introspector() introspector {
	return introspector{xml: `<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.PasskeyBroker">
    <method name="MakeCredential">
      <arg name="parent_window" type="s" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="handle" type="o" direction="out"/>
    </method>
    <method name="GetAssertion">
      <arg name="parent_window" type="s" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="handle" type="o" direction="out"/>
    </method>
    <method name="RegisterUIAgent">
      <arg name="agent_path" type="o" direction="in"/>
    </method>
    <method name="UnregisterUIAgent">
      <arg name="agent_path" type="o" direction="in"/>
    </method>
  </interface>
</node>`}
}
