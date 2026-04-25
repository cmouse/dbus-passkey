//go:build cgo

package fido2

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	cbor "github.com/fxamacker/cbor/v2"
	libfido2 "github.com/keys-pub/go-libfido2"

	"github.com/cmouse/dbus-passkey/internal/types"
)

// TokenProvider wraps a physical FIDO2 device.
type TokenProvider struct {
	mu       sync.Mutex
	dev      *libfido2.Device
	path     string
	id       string
	name     string
	cancelling atomic.Bool
}

// EnumerateDevices returns a TokenProvider for each connected FIDO2 device.
func EnumerateDevices() ([]*TokenProvider, error) {
	var locs []*libfido2.DeviceLocation
	var err error
	globalWorker.Run(func() {
		locs, err = libfido2.DeviceLocations()
	})
	if err != nil {
		return nil, err
	}
	out := make([]*TokenProvider, 0, len(locs))
	for i, loc := range locs {
		var dev *libfido2.Device
		globalWorker.Run(func() {
			dev, err = libfido2.NewDevice(loc.Path)
		})
		if err != nil {
			continue
		}
		out = append(out, &TokenProvider{
			dev:  dev,
			path: loc.Path,
			id:   fmt.Sprintf("fido2-%d", i),
			name: fmt.Sprintf("FIDO2 Token (%s)", loc.Path),
		})
	}
	return out, nil
}

func (t *TokenProvider) ID() string           { return t.id }
func (t *TokenProvider) Name() string         { return t.name }
func (t *TokenProvider) Type() string         { return "hardware" }
func (t *TokenProvider) Transports() []string { return []string{"usb"} }
func (t *TokenProvider) RequiresPIN() bool    { return false }
func (t *TokenProvider) SupportedAlgorithms() []int32 {
	// ES256 (-7) and EdDSA (-8) are the common supported algorithms.
	return []int32{-7, -8}
}

func (t *TokenProvider) Cancel() {
	t.cancelling.Store(true)
	// Call directly — must NOT go through the worker queue, which is blocked by the
	// in-flight operation we're trying to cancel. libfido2 cancel is thread-safe.
	_ = t.dev.Cancel()
}

func (t *TokenProvider) HasCredentials(rpID string, allowList [][]byte) ([][]byte, error) {
	// Hardware tokens don't expose a programmatic has-credentials check without PIN.
	// Return single nil entry to indicate "possibly has credentials" (discoverable flow).
	if len(allowList) == 0 {
		return [][]byte{nil}, nil
	}
	return allowList, nil
}

func (t *TokenProvider) MakeCredential(opts *types.MakeCredentialOptions, pin []byte) (*types.MakeCredentialResult, error) {
	t.cancelling.Store(false)

	clientDataJSON := buildClientDataJSON("webauthn.create", opts.Challenge, opts.RPID)
	clientDataHash := sha256.Sum256(clientDataJSON)

	rp := libfido2.RelyingParty{ID: opts.RPID, Name: opts.RPName}
	user := libfido2.User{
		ID:          opts.UserID,
		Name:        opts.UserName,
		DisplayName: opts.UserDisplayName,
	}

	credType := libfido2.ES256
	for _, param := range opts.PubKeyCredParams {
		if param.Alg == -8 {
			credType = libfido2.EDDSA
			break
		}
		if param.Alg == -7 {
			credType = libfido2.ES256
			break
		}
	}

	makeOpts := &libfido2.MakeCredentialOpts{}
	switch opts.ResidentKey {
	case "required", "preferred":
		makeOpts.RK = libfido2.True
	case "discouraged":
		makeOpts.RK = libfido2.False
	}
	switch opts.UserVerification {
	case "required":
		makeOpts.UV = libfido2.True
	case "discouraged":
		makeOpts.UV = libfido2.False
	default:
		makeOpts.UV = libfido2.Default
	}

	pinStr := string(pin)

	var att *libfido2.Attestation
	var err error
	globalWorker.Run(func() {
		att, err = t.dev.MakeCredential(clientDataHash[:], rp, user, credType, pinStr, makeOpts)
	})
	clearBytes(pin)

	if err != nil {
		return nil, err
	}

	attObj, err := buildAttestationObject(att)
	if err != nil {
		return nil, fmt.Errorf("build attestation object: %w", err)
	}

	return &types.MakeCredentialResult{
		CredentialID:      att.CredentialID,
		AttestationObject: attObj,
		ClientDataJSON:    clientDataJSON,
		Transports:        []string{"usb"},
		ProviderID:        t.id,
	}, nil
}

func (t *TokenProvider) GetAssertion(opts *types.GetAssertionOptions, pin []byte) (*types.GetAssertionResult, error) {
	t.cancelling.Store(false)

	clientDataJSON := buildClientDataJSON("webauthn.get", opts.Challenge, opts.RPID)
	clientDataHash := sha256.Sum256(clientDataJSON)

	credIDs := make([][]byte, len(opts.AllowCredentials))
	for i, c := range opts.AllowCredentials {
		credIDs[i] = c.ID
	}

	assertOpts := &libfido2.AssertionOpts{}
	switch opts.UserVerification {
	case "required":
		assertOpts.UV = libfido2.True
	case "discouraged":
		assertOpts.UV = libfido2.False
	default:
		assertOpts.UV = libfido2.Default
	}

	pinStr := string(pin)

	var assertion *libfido2.Assertion
	var err error
	globalWorker.Run(func() {
		assertion, err = t.dev.Assertion(opts.RPID, clientDataHash[:], credIDs, pinStr, assertOpts)
	})
	clearBytes(pin)

	if err != nil {
		return nil, err
	}

	return &types.GetAssertionResult{
		CredentialID:      assertion.CredentialID,
		AuthenticatorData: assertion.AuthDataCBOR,
		Signature:         assertion.Sig,
		UserHandle:        assertion.User.ID,
		ClientDataJSON:    clientDataJSON,
		ProviderID:        t.id,
	}, nil
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func buildClientDataJSON(typ string, challenge []byte, rpID string) []byte {
	cd := clientData{
		Type:      typ,
		Challenge: encodeBase64URL(challenge),
		Origin:    "https://" + rpID,
	}
	b, _ := json.Marshal(cd)
	return b
}

// encodeBase64URL encodes bytes to base64url without padding.
func encodeBase64URL(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	n := len(b)
	out := make([]byte, 0, (n*4+2)/3)
	for i := 0; i < n; i += 3 {
		var b0, b1, b2 byte
		b0 = b[i]
		if i+1 < n {
			b1 = b[i+1]
		}
		if i+2 < n {
			b2 = b[i+2]
		}
		out = append(out,
			chars[b0>>2],
			chars[((b0&3)<<4)|(b1>>4)],
			chars[((b1&0xf)<<2)|(b2>>6)],
			chars[b2&0x3f],
		)
	}
	// trim padding chars that represent zero-bits beyond data
	switch n % 3 {
	case 1:
		out = out[:len(out)-2]
	case 2:
		out = out[:len(out)-1]
	}
	return string(out)
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// buildAttestationObject constructs a CBOR-encoded WebAuthn attestation object
// from the fields returned by go-libfido2. Format "packed" with x5c statement.
func buildAttestationObject(att *libfido2.Attestation) ([]byte, error) {
	// attStmt for "packed" format with full attestation
	var attStmt interface{}
	if att.Format == "packed" && len(att.Cert) > 0 {
		attStmt = map[interface{}]interface{}{
			"alg": int(-7), // ES256
			"sig": att.Sig,
			"x5c": [][]byte{att.Cert},
		}
	} else if att.Format == "none" || att.Format == "" {
		attStmt = map[interface{}]interface{}{}
	} else {
		attStmt = map[interface{}]interface{}{
			"sig": att.Sig,
		}
	}

	obj := map[interface{}]interface{}{
		"fmt":      att.Format,
		"attStmt":  attStmt,
		"authData": att.AuthData,
	}
	return cbor.Marshal(obj)
}
