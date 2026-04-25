package provider

import (
	"fmt"

	"github.com/cmouse/dbus-passkey/internal/types"
	"github.com/godbus/dbus/v5"
)

const providerIface = "fi.cmouse.PasskeyBroker.Provider"

// DBusProvider proxies a software provider over D-Bus.
type DBusProvider struct {
	conn       *dbus.Conn
	entry      RegistryEntry
	cancelChan chan struct{}
}

func NewDBusProvider(conn *dbus.Conn, entry RegistryEntry) *DBusProvider {
	return &DBusProvider{conn: conn, entry: entry, cancelChan: make(chan struct{}, 1)}
}

func (p *DBusProvider) ID() string           { return p.entry.ID }
func (p *DBusProvider) Name() string         { return p.entry.Name }
func (p *DBusProvider) Type() string         { return "software" }
func (p *DBusProvider) Transports() []string { return p.entry.Transports }
func (p *DBusProvider) SupportedAlgorithms() []int32 { return p.entry.SupportedAlgorithms }

func (p *DBusProvider) Cancel() {
	select {
	case p.cancelChan <- struct{}{}:
	default:
	}
}

func (p *DBusProvider) obj() dbus.BusObject {
	return p.conn.Object(p.entry.DBusName, dbus.ObjectPath(p.entry.ObjectPath))
}

func (p *DBusProvider) HasCredentials(rpID string, allowList [][]byte) ([][]byte, error) {
	obj := p.obj()
	var result [][]byte
	err := obj.Call(providerIface+".HasCredentials", 0, rpID, allowList).Store(&result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (p *DBusProvider) MakeCredential(opts *types.MakeCredentialOptions, pin []byte) (*types.MakeCredentialResult, error) {
	obj := p.obj()
	dbusOpts := makeCredentialOptsToMap(opts)
	var resultMap map[string]dbus.Variant
	if err := obj.Call(providerIface+".MakeCredential", 0, dbusOpts).Store(&resultMap); err != nil {
		return nil, err
	}
	return makeCredentialResultFromMap(resultMap, p.entry.ID)
}

func (p *DBusProvider) GetAssertion(opts *types.GetAssertionOptions, pin []byte) (*types.GetAssertionResult, error) {
	obj := p.obj()
	dbusOpts := getAssertionOptsToMap(opts)
	var resultMap map[string]dbus.Variant
	if err := obj.Call(providerIface+".GetAssertion", 0, dbusOpts).Store(&resultMap); err != nil {
		return nil, err
	}
	return getAssertionResultFromMap(resultMap, p.entry.ID)
}

func makeCredentialOptsToMap(opts *types.MakeCredentialOptions) map[string]dbus.Variant {
	m := map[string]dbus.Variant{
		"rp_id":    dbus.MakeVariant(opts.RPID),
		"rp_name":  dbus.MakeVariant(opts.RPName),
		"user_id":  dbus.MakeVariant(opts.UserID),
		"user_name": dbus.MakeVariant(opts.UserName),
		"user_display_name": dbus.MakeVariant(opts.UserDisplayName),
		"challenge": dbus.MakeVariant(opts.Challenge),
		"resident_key":       dbus.MakeVariant(opts.ResidentKey),
		"user_verification":  dbus.MakeVariant(opts.UserVerification),
		"attestation":        dbus.MakeVariant(opts.Attestation),
		"authenticator_attachment": dbus.MakeVariant(opts.AuthenticatorAttachment),
		"timeout_ms": dbus.MakeVariant(opts.TimeoutMS),
	}
	// pub_key_cred_params
	params := make([]map[string]dbus.Variant, len(opts.PubKeyCredParams))
	for i, p := range opts.PubKeyCredParams {
		params[i] = map[string]dbus.Variant{
			"type": dbus.MakeVariant(p.Type),
			"alg":  dbus.MakeVariant(p.Alg),
		}
	}
	m["pub_key_cred_params"] = dbus.MakeVariant(params)
	// exclude_credentials
	excl := make([]map[string]dbus.Variant, len(opts.ExcludeCredentials))
	for i, c := range opts.ExcludeCredentials {
		excl[i] = map[string]dbus.Variant{
			"type":       dbus.MakeVariant(c.Type),
			"id":         dbus.MakeVariant(c.ID),
			"transports": dbus.MakeVariant(c.Transports),
		}
	}
	m["exclude_credentials"] = dbus.MakeVariant(excl)
	return m
}

func getAssertionOptsToMap(opts *types.GetAssertionOptions) map[string]dbus.Variant {
	m := map[string]dbus.Variant{
		"rp_id":             dbus.MakeVariant(opts.RPID),
		"challenge":         dbus.MakeVariant(opts.Challenge),
		"user_verification": dbus.MakeVariant(opts.UserVerification),
		"timeout_ms":        dbus.MakeVariant(opts.TimeoutMS),
	}
	allow := make([]map[string]dbus.Variant, len(opts.AllowCredentials))
	for i, c := range opts.AllowCredentials {
		allow[i] = map[string]dbus.Variant{
			"type":       dbus.MakeVariant(c.Type),
			"id":         dbus.MakeVariant(c.ID),
			"transports": dbus.MakeVariant(c.Transports),
		}
	}
	m["allow_credentials"] = dbus.MakeVariant(allow)
	return m
}

func makeCredentialResultFromMap(m map[string]dbus.Variant, providerID string) (*types.MakeCredentialResult, error) {
	r := &types.MakeCredentialResult{ProviderID: providerID}
	if v, ok := m["credential_id"]; ok {
		r.CredentialID, _ = v.Value().([]byte)
	}
	if v, ok := m["attestation_object"]; ok {
		r.AttestationObject, _ = v.Value().([]byte)
	}
	if v, ok := m["client_data_json"]; ok {
		r.ClientDataJSON, _ = v.Value().([]byte)
	}
	if v, ok := m["transports"]; ok {
		r.Transports, _ = v.Value().([]string)
	}
	if r.CredentialID == nil {
		return nil, fmt.Errorf("provider returned no credential_id")
	}
	return r, nil
}

func getAssertionResultFromMap(m map[string]dbus.Variant, providerID string) (*types.GetAssertionResult, error) {
	r := &types.GetAssertionResult{ProviderID: providerID}
	if v, ok := m["credential_id"]; ok {
		r.CredentialID, _ = v.Value().([]byte)
	}
	if v, ok := m["authenticator_data"]; ok {
		r.AuthenticatorData, _ = v.Value().([]byte)
	}
	if v, ok := m["signature"]; ok {
		r.Signature, _ = v.Value().([]byte)
	}
	if v, ok := m["user_handle"]; ok {
		r.UserHandle, _ = v.Value().([]byte)
	}
	if v, ok := m["client_data_json"]; ok {
		r.ClientDataJSON, _ = v.Value().([]byte)
	}
	if r.CredentialID == nil {
		return nil, fmt.Errorf("provider returned no credential_id")
	}
	return r, nil
}
