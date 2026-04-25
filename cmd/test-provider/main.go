package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

const (
	busName    = "fi.cmouse.PasskeyBroker.TestProvider"
	objectPath = "/fi/cmouse/PasskeyBroker/TestProvider"
	iface      = "fi.cmouse.PasskeyBroker.Provider"
)

const introspectXML = `<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="fi.cmouse.PasskeyBroker.Provider">
    <method name="HasCredentials">
      <arg name="rp_id" type="s" direction="in"/>
      <arg name="allow_list" type="aay" direction="in"/>
      <arg name="matching_ids" type="aay" direction="out"/>
    </method>
    <method name="MakeCredential">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="result" type="a{sv}" direction="out"/>
    </method>
    <method name="GetAssertion">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="result" type="a{sv}" direction="out"/>
    </method>
    <property name="SupportedTransports" type="as" access="read"/>
    <property name="SupportedAlgorithms" type="ai" access="read"/>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="data" type="s" direction="out"/>
    </method>
  </interface>
</node>`

// storedCredential holds a single passkey with its private key material.
type storedCredential struct {
	ID              []byte `json:"id"`
	RPID            string `json:"rp_id"`
	UserID          []byte `json:"user_id"`
	UserName        string `json:"user_name"`
	UserDisplayName string `json:"user_display_name"`
	PrivKeyD        []byte `json:"priv_key_d"`
	PubKeyX         []byte `json:"pub_key_x"`
	PubKeyY         []byte `json:"pub_key_y"`
	SignCount       uint32 `json:"sign_count"`
}

type testProvider struct {
	mu          sync.RWMutex
	credentials []storedCredential
	storePath   string
}

func newTestProvider() *testProvider {
	p := &testProvider{}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("warning: cannot determine home dir: %v — in-memory only", err)
		return p
	}
	dir := filepath.Join(home, ".local", "share", "dbus-passkey-testprovider")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("warning: cannot create storage dir %s: %v — in-memory only", dir, err)
		return p
	}
	p.storePath = filepath.Join(dir, "credentials.json")
	p.load()
	return p
}

func (p *testProvider) load() {
	data, err := os.ReadFile(p.storePath)
	if err != nil {
		return
	}
	var creds []storedCredential
	if err := json.Unmarshal(data, &creds); err != nil {
		log.Printf("warning: cannot parse %s: %v", p.storePath, err)
		return
	}
	p.credentials = creds
	log.Printf("loaded %d credential(s) from %s", len(creds), p.storePath)
}

func (p *testProvider) save() {
	if p.storePath == "" {
		return
	}
	data, err := json.MarshalIndent(p.credentials, "", "  ")
	if err != nil {
		log.Printf("warning: marshal credentials: %v", err)
		return
	}
	if err := os.WriteFile(p.storePath, data, 0600); err != nil {
		log.Printf("warning: save credentials: %v", err)
	}
}

// HasCredentials implements fi.cmouse.PasskeyBroker.Provider.HasCredentials.
func (p *testProvider) HasCredentials(rpID string, allowList [][]byte) ([][]byte, *dbus.Error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var matching [][]byte
	for _, cred := range p.credentials {
		if cred.RPID != rpID {
			continue
		}
		if len(allowList) == 0 {
			matching = append(matching, cred.ID)
			continue
		}
		for _, allowed := range allowList {
			if bytes.Equal(cred.ID, allowed) {
				matching = append(matching, cred.ID)
				break
			}
		}
	}
	if matching == nil {
		matching = [][]byte{}
	}
	return matching, nil
}

// MakeCredential implements fi.cmouse.PasskeyBroker.Provider.MakeCredential.
func (p *testProvider) MakeCredential(options map[string]dbus.Variant) (map[string]dbus.Variant, *dbus.Error) {
	rpID, _ := varStr(options, "rp_id")
	challenge, _ := varBytes(options, "challenge")
	userID, _ := varBytes(options, "user_id")
	userName, _ := varStr(options, "user_name")
	userDisplayName, _ := varStr(options, "user_display_name")

	if rpID == "" || len(challenge) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("missing rp_id or challenge"))
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("key generation: %w", err))
	}

	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("credential ID: %w", err))
	}

	authData, err := buildMakeAuthData(rpID, credID, privKey)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("authData: %w", err))
	}

	attObj, err := buildAttestationObject(authData)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("attestation object: %w", err))
	}

	clientDataJSON := buildClientDataJSON("webauthn.create", challenge, rpID)

	cred := storedCredential{
		ID:              credID,
		RPID:            rpID,
		UserID:          userID,
		UserName:        userName,
		UserDisplayName: userDisplayName,
		PrivKeyD:        padTo32(privKey.D.Bytes()),
		PubKeyX:         padTo32(privKey.PublicKey.X.Bytes()),
		PubKeyY:         padTo32(privKey.PublicKey.Y.Bytes()),
		SignCount:       0,
	}

	p.mu.Lock()
	p.credentials = append(p.credentials, cred)
	p.save()
	p.mu.Unlock()

	log.Printf("MakeCredential: created cred %x for rp=%s user=%s", credID[:8], rpID, userName)

	return map[string]dbus.Variant{
		"credential_id":      dbus.MakeVariant(credID),
		"attestation_object": dbus.MakeVariant(attObj),
		"client_data_json":   dbus.MakeVariant(clientDataJSON),
		"transports":         dbus.MakeVariant([]string{"internal"}),
	}, nil
}

// GetAssertion implements fi.cmouse.PasskeyBroker.Provider.GetAssertion.
func (p *testProvider) GetAssertion(options map[string]dbus.Variant) (map[string]dbus.Variant, *dbus.Error) {
	rpID, _ := varStr(options, "rp_id")
	challenge, _ := varBytes(options, "challenge")

	if rpID == "" || len(challenge) == 0 {
		return nil, dbus.MakeFailedError(fmt.Errorf("missing rp_id or challenge"))
	}

	allowIDs := extractCredIDs(options, "allow_credentials")

	p.mu.Lock()
	defer p.mu.Unlock()

	cred := p.findCredential(rpID, allowIDs)
	if cred == nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("no matching credential for rp=%s", rpID))
	}

	cred.SignCount++

	privKey := &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(cred.PrivKeyD),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(cred.PubKeyX),
			Y:     new(big.Int).SetBytes(cred.PubKeyY),
		},
	}

	clientDataJSON := buildClientDataJSON("webauthn.get", challenge, rpID)
	clientDataHash := sha256.Sum256(clientDataJSON)

	authData := buildGetAssertAuthData(rpID, cred.SignCount)

	// WebAuthn spec: sign(authData || hash(clientDataJSON))
	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash[:])
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest)
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("sign: %w", err))
	}

	type ecSig struct{ R, S *big.Int }
	sig, err := asn1.Marshal(ecSig{R: r, S: s})
	if err != nil {
		return nil, dbus.MakeFailedError(fmt.Errorf("encode signature: %w", err))
	}

	p.save()

	log.Printf("GetAssertion: signed for rp=%s cred=%x count=%d", rpID, cred.ID[:8], cred.SignCount)

	return map[string]dbus.Variant{
		"credential_id":      dbus.MakeVariant(cred.ID),
		"authenticator_data": dbus.MakeVariant(authData),
		"signature":          dbus.MakeVariant(sig),
		"user_handle":        dbus.MakeVariant(cred.UserID),
		"client_data_json":   dbus.MakeVariant(clientDataJSON),
	}, nil
}

// findCredential finds the first credential matching rpID and optional allow list.
// Caller must hold p.mu.Lock().
func (p *testProvider) findCredential(rpID string, allowIDs [][]byte) *storedCredential {
	for i := range p.credentials {
		c := &p.credentials[i]
		if c.RPID != rpID {
			continue
		}
		if len(allowIDs) == 0 {
			return c
		}
		for _, id := range allowIDs {
			if bytes.Equal(c.ID, id) {
				return c
			}
		}
	}
	return nil
}

// --- Crypto helpers ---

func buildMakeAuthData(rpID string, credID []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(rpID))

	x := padTo32(privKey.PublicKey.X.Bytes())
	y := padTo32(privKey.PublicKey.Y.Bytes())

	// COSE EC2 key with integer keys as required by CTAP2/WebAuthn
	coseKey, err := cbor.Marshal(coseEC2Key{
		Kty: 2,  // EC2
		Alg: -7, // ES256
		Crv: 1,  // P-256
		X:   x,
		Y:   y,
	})
	if err != nil {
		return nil, fmt.Errorf("COSE key: %w", err)
	}

	var buf []byte
	buf = append(buf, rpIDHash[:]...)      // rpIdHash: 32 bytes
	buf = append(buf, 0x45)                // flags: UP(0x01) | UV(0x04) | AT(0x40)
	buf = appendUint32(buf, 0)             // signCount: 0
	buf = append(buf, make([]byte, 16)...) // aaguid: 16 zero bytes
	buf = appendUint16(buf, uint16(len(credID)))
	buf = append(buf, credID...)
	buf = append(buf, coseKey...)
	return buf, nil
}

func buildGetAssertAuthData(rpID string, signCount uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	var buf []byte
	buf = append(buf, rpIDHash[:]...) // 32 bytes
	buf = append(buf, 0x05)           // flags: UP(0x01) | UV(0x04)
	buf = appendUint32(buf, signCount)
	return buf
}

func buildAttestationObject(authData []byte) ([]byte, error) {
	type attObj struct {
		Fmt      string            `cbor:"fmt"`
		AttStmt  map[string][]byte `cbor:"attStmt"`
		AuthData []byte            `cbor:"authData"`
	}
	return cbor.Marshal(attObj{
		Fmt:      "none",
		AttStmt:  map[string][]byte{},
		AuthData: authData,
	})
}

type clientDataFields struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func buildClientDataJSON(typ string, challenge []byte, rpID string) []byte {
	d := clientDataFields{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://" + rpID,
	}
	data, _ := json.Marshal(d)
	return data
}

// coseEC2Key encodes as CBOR with the integer keys required by COSE (RFC 8152).
// We use a struct with cbor tags to get deterministic encoding.
type coseEC2Key struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// --- D-Bus option parsing helpers ---

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

// extractCredIDs extracts the "id" field from each entry in an aa{sv} option.
// Handles both []map[string]dbus.Variant and []interface{} (godbus may use either).
func extractCredIDs(options map[string]dbus.Variant, key string) [][]byte {
	v, ok := options[key]
	if !ok {
		return nil
	}
	return collectIDs(v.Value())
}

func collectIDs(val interface{}) [][]byte {
	switch t := val.(type) {
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
			switch m := item.(type) {
			case map[string]dbus.Variant:
				if id, ok := m["id"].Value().([]byte); ok {
					ids = append(ids, id)
				}
			}
		}
		return ids
	}
	return nil
}

// --- Byte helpers ---

func padTo32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
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

func main() {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Fatalf("dbus session bus: %v", err)
	}
	defer conn.Close()

	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("cannot own %s (reply=%d): %v", busName, reply, err)
	}

	provider := newTestProvider()

	conn.Export(provider, dbus.ObjectPath(objectPath), iface)
	conn.Export(introspect.Introspectable(introspectXML), dbus.ObjectPath(objectPath),
		"org.freedesktop.DBus.Introspectable")

	if provider.storePath != "" {
		log.Printf("credentials: %s", provider.storePath)
	} else {
		log.Printf("credentials: in-memory only")
	}
	log.Printf("running as %s at %s", busName, objectPath)
	log.Printf("")
	log.Printf("register with broker — add to /etc/dbus-passkey/providers.d/test-provider.conf:")
	log.Printf("  [Provider]")
	log.Printf("  Name=PasskeyTestProvider")
	log.Printf("  ID=test-provider")
	log.Printf("  DBusName=%s", busName)
	log.Printf("  ObjectPath=%s", objectPath)
	log.Printf("  Transports=internal")
	log.Printf("  SupportedAlgorithms=-7")
	log.Printf("  Priority=50")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Println("shutting down")
}
