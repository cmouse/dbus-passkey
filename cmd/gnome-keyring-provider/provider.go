//go:build cgo

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/godbus/dbus/v5"
)

type gnomeKeyringProvider struct {
	token *pkcs11Token
	ss    *secretService
}

func newGnomeKeyringProvider(conn *dbus.Conn) (*gnomeKeyringProvider, error) {
	token, err := newPKCS11Token()
	if err != nil {
		return nil, err
	}
	ss, err := newSecretService(conn)
	if err != nil {
		token.close()
		return nil, err
	}
	return &gnomeKeyringProvider{token: token, ss: ss}, nil
}

func (p *gnomeKeyringProvider) close() {
	p.ss.close()
	p.token.close()
}

// HasCredentials implements fi.cmouse.PasskeyBroker.Provider.HasCredentials.
func (p *gnomeKeyringProvider) HasCredentials(rpID string, allowList [][]byte) ([][]byte, *dbus.Error) {
	metas, err := p.ss.FindCredentials(rpID, allowList)
	if err != nil {
		return [][]byte{}, nil
	}
	ids := make([][]byte, len(metas))
	for i, m := range metas {
		ids[i] = m.CredID
	}
	if ids == nil {
		ids = [][]byte{}
	}
	return ids, nil
}

// MakeCredential implements fi.cmouse.PasskeyBroker.Provider.MakeCredential.
func (p *gnomeKeyringProvider) MakeCredential(options map[string]dbus.Variant) (map[string]dbus.Variant, *dbus.Error) {
	rpID, _ := varStr(options, "rp_id")
	challenge, _ := varBytes(options, "challenge")
	userID, _ := varBytes(options, "user_id")
	userName, _ := varStr(options, "user_name")
	userDisplayName, _ := varStr(options, "user_display_name")
	pinBytes, _ := varBytes(options, "pin")
	initPIN, _ := varBool(options, "init_pin")

	if rpID == "" || len(challenge) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("missing rp_id or challenge"))
	}
	if len(pinBytes) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("PIN required"))
	}
	defer clearBytes(pinBytes)

	if initPIN {
		if err := p.token.InitPIN(pinBytes); err != nil {
			return nil, dbus.MakeFailedError(fmt.Errorf("init PIN: %w", err))
		}
	}

	sh, err := p.token.Login(pinBytes)
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	defer p.token.Logout(sh)

	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("generate credential ID: %w", err))
	}

	if err := p.token.GenerateKeyPair(sh, credID); err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("generate key pair: %w", err))
	}

	xy, err := p.token.GetPublicKey(sh, credID)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("get public key: %w", err))
	}

	authData, err := buildMakeAuthData(rpID, credID, xy)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("authData: %w", err))
	}
	attObj, err := buildAttestationObject(authData)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("attestation object: %w", err))
	}
	clientDataJSON := buildClientDataJSON("webauthn.create", challenge, rpID)

	meta := credMeta{
		CredID:          credID,
		RPID:            rpID,
		UserID:          userID,
		UserName:        userName,
		UserDisplayName: userDisplayName,
		SignCount:       0,
	}
	if err := p.ss.StoreCredential(meta); err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("store credential: %w", err))
	}

	return map[string]dbus.Variant{
		"credential_id":      dbus.MakeVariant(credID),
		"attestation_object": dbus.MakeVariant(attObj),
		"client_data_json":   dbus.MakeVariant(clientDataJSON),
		"transports":         dbus.MakeVariant([]string{"internal"}),
	}, nil
}

// GetAssertion implements fi.cmouse.PasskeyBroker.Provider.GetAssertion.
func (p *gnomeKeyringProvider) GetAssertion(options map[string]dbus.Variant) (map[string]dbus.Variant, *dbus.Error) {
	rpID, _ := varStr(options, "rp_id")
	challenge, _ := varBytes(options, "challenge")
	pinBytes, _ := varBytes(options, "pin")
	allowIDs := extractCredIDs(options, "allow_credentials")

	if rpID == "" || len(challenge) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("missing rp_id or challenge"))
	}
	if len(pinBytes) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("PIN required"))
	}
	defer clearBytes(pinBytes)

	sh, err := p.token.Login(pinBytes)
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}
	defer p.token.Logout(sh)

	metas, err := p.ss.FindCredentials(rpID, allowIDs)
	if err != nil || len(metas) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("no matching credential for rp=%s", rpID))
	}
	meta := metas[0]

	clientDataJSON := buildClientDataJSON("webauthn.get", challenge, rpID)
	clientDataHash := sha256.Sum256(clientDataJSON)
	authData := buildGetAssertAuthData(rpID, meta.SignCount+1)

	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash[:])
	digest := h.Sum(nil)

	sig, err := p.token.Sign(sh, meta.CredID, digest)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("sign: %w", err))
	}

	meta.SignCount++
	_ = p.ss.UpdateSignCount(meta.CredID, rpID, meta.SignCount)

	return map[string]dbus.Variant{
		"credential_id":      dbus.MakeVariant(meta.CredID),
		"authenticator_data": dbus.MakeVariant(authData),
		"signature":          dbus.MakeVariant(sig),
		"user_handle":        dbus.MakeVariant(meta.UserID),
		"client_data_json":   dbus.MakeVariant(clientDataJSON),
	}, nil
}

// --- crypto helpers ---

type coseEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

func buildMakeAuthData(rpID string, credID []byte, xy []byte) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))
	x, y := xy[:32], xy[32:]
	coseKey, err := cbor.Marshal(coseEC2Key{Kty: 2, Alg: -7, Crv: 1, X: x, Y: y})
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, 0x45)
	buf = appendUint32(buf, 0)
	buf = append(buf, make([]byte, 16)...)
	buf = appendUint16(buf, uint16(len(credID)))
	buf = append(buf, credID...)
	buf = append(buf, coseKey...)
	return buf, nil
}

func buildGetAssertAuthData(rpID string, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	var buf []byte
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, 0x05)
	buf = appendUint32(buf, signCount)
	return buf
}

func buildAttestationObject(authData []byte) ([]byte, error) {
	type attObj struct {
		Fmt      string            `cbor:"fmt"`
		AttStmt  map[string][]byte `cbor:"attStmt"`
		AuthData []byte            `cbor:"authData"`
	}
	return cbor.Marshal(attObj{Fmt: "none", AttStmt: map[string][]byte{}, AuthData: authData})
}

func buildClientDataJSON(typ string, challenge []byte, rpID string) []byte {
	type fields struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	d := fields{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://" + rpID,
	}
	data, _ := json.Marshal(d)
	return data
}

// --- D-Bus option helpers ---

func varStr(m map[string]dbus.Variant, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.Value().(string)
	return s, ok
}

func varBytes(m map[string]dbus.Variant, key string) ([]byte, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	b, ok := v.Value().([]byte)
	return b, ok
}

func varBool(m map[string]dbus.Variant, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := v.Value().(bool)
	return b, ok
}

func extractCredIDs(options map[string]dbus.Variant, key string) [][]byte {
	v, ok := options[key]
	if !ok {
		return nil
	}
	switch t := v.Value().(type) {
	case []map[string]dbus.Variant:
		var ids [][]byte
		for _, m := range t {
			if id, ok := m["id"].Value().([]byte); ok {
				ids = append(ids, id)
			}
		}
		return ids
	case []interface{}:
		var ids [][]byte
		for _, item := range t {
			if m, ok := item.(map[string]dbus.Variant); ok {
				if id, ok := m["id"].Value().([]byte); ok {
					ids = append(ids, id)
				}
			}
		}
		return ids
	}
	return nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func appendUint32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendUint16(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}
