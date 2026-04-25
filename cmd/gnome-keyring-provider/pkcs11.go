//go:build cgo

package main

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// modulePaths are tried in order; first one that loads wins.
var modulePaths = []string{
	"/usr/lib/x86_64-linux-gnu/pkcs11/gnome-keyring-pkcs11.so",
	"/usr/lib/pkcs11/gnome-keyring-pkcs11.so",
	"p11-kit-proxy.so",
}

// p256OID is the DER encoding of the P-256 curve OID (1.2.840.10045.3.1.7).
var p256OID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

type pkcs11Token struct {
	ctx  *pkcs11.Ctx
	slot uint
}

func newPKCS11Token() (*pkcs11Token, error) {
	var ctx *pkcs11.Ctx
	var err error
	for _, path := range modulePaths {
		ctx = pkcs11.New(path)
		if err = ctx.Initialize(); err == nil {
			break
		}
		ctx.Destroy()
		ctx = nil
	}
	if ctx == nil {
		return nil, fmt.Errorf("gnome-keyring PKCS#11 module not found; tried: %v", modulePaths)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("no PKCS#11 slots with token present")
	}
	return &pkcs11Token{ctx: ctx, slot: slots[0]}, nil
}

func (t *pkcs11Token) close() {
	t.ctx.Finalize()
	t.ctx.Destroy()
}

func (t *pkcs11Token) openSession() (pkcs11.SessionHandle, error) {
	return t.ctx.OpenSession(t.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
}

// HasObjects reports whether any dbus-passkey key objects exist on the token.
// Used to detect first-use (no PIN initialized yet).
func (t *pkcs11Token) HasObjects() (bool, error) {
	sh, err := t.openSession()
	if err != nil {
		return false, err
	}
	defer t.ctx.CloseSession(sh)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "dbus-passkey"),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if err := t.ctx.FindObjectsInit(sh, template); err != nil {
		return false, err
	}
	defer t.ctx.FindObjectsFinal(sh)
	objs, _, err := t.ctx.FindObjects(sh, 1)
	if err != nil {
		return false, err
	}
	return len(objs) > 0, nil
}

// InitPIN sets the user PIN for the token (first-use setup).
// gnome-keyring uses an empty SO PIN.
func (t *pkcs11Token) InitPIN(pin []byte) error {
	sh, err := t.openSession()
	if err != nil {
		return err
	}
	defer t.ctx.CloseSession(sh)

	if err := t.ctx.Login(sh, pkcs11.CKU_SO, ""); err != nil {
		return fmt.Errorf("SO login: %w", err)
	}
	defer t.ctx.Logout(sh)

	if err := t.ctx.InitPIN(sh, string(pin)); err != nil {
		return fmt.Errorf("InitPIN: %w", err)
	}
	return nil
}

// Login authenticates the user session with the provided PIN.
// Returns the session handle; caller must call Logout(sh) and CloseSession(sh) when done.
func (t *pkcs11Token) Login(pin []byte) (pkcs11.SessionHandle, error) {
	sh, err := t.openSession()
	if err != nil {
		return 0, err
	}
	if err := t.ctx.Login(sh, pkcs11.CKU_USER, string(pin)); err != nil {
		t.ctx.CloseSession(sh)
		if err == pkcs11.Error(pkcs11.CKR_USER_PIN_NOT_INITIALIZED) {
			return 0, errPINNotInitialized
		}
		return 0, fmt.Errorf("login: %w", err)
	}
	return sh, nil
}

func (t *pkcs11Token) Logout(sh pkcs11.SessionHandle) {
	t.ctx.Logout(sh)
	t.ctx.CloseSession(sh)
}

// GenerateKeyPair creates a persistent EC P-256 key pair with CKA_ID=credID.
// Session must be authenticated (Login called first).
func (t *pkcs11Token) GenerateKeyPair(sh pkcs11.SessionHandle, credID []byte) error {
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, credID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "dbus-passkey"),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, p256OID),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, credID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "dbus-passkey"),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	_, _, err := t.ctx.GenerateKeyPair(sh, mech, pubTemplate, privTemplate)
	return err
}

// Sign performs CKM_ECDSA on hash using the private key identified by credID.
// Returns raw r||s bytes (64 bytes for P-256), DER-encodes to ASN.1 SEQUENCE.
func (t *pkcs11Token) Sign(sh pkcs11.SessionHandle, credID []byte, hash []byte) ([]byte, error) {
	privKey, err := t.findPrivKey(sh, credID)
	if err != nil {
		return nil, err
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
	if err := t.ctx.SignInit(sh, mech, privKey); err != nil {
		return nil, fmt.Errorf("SignInit: %w", err)
	}
	raw, err := t.ctx.Sign(sh, hash)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}
	return derEncodeECSig(raw)
}

func (t *pkcs11Token) findPrivKey(sh pkcs11.SessionHandle, credID []byte) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, credID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "dbus-passkey"),
	}
	if err := t.ctx.FindObjectsInit(sh, template); err != nil {
		return 0, fmt.Errorf("FindObjectsInit: %w", err)
	}
	defer t.ctx.FindObjectsFinal(sh)
	objs, _, err := t.ctx.FindObjects(sh, 1)
	if err != nil || len(objs) == 0 {
		return 0, fmt.Errorf("private key not found for credential")
	}
	return objs[0], nil
}

// DeleteKey removes the key pair identified by credID.
func (t *pkcs11Token) DeleteKey(sh pkcs11.SessionHandle, credID []byte) error {
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
			pkcs11.NewAttribute(pkcs11.CKA_ID, credID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, "dbus-passkey"),
		}
		if err := t.ctx.FindObjectsInit(sh, template); err != nil {
			continue
		}
		objs, _, _ := t.ctx.FindObjects(sh, 1)
		t.ctx.FindObjectsFinal(sh)
		for _, obj := range objs {
			t.ctx.DestroyObject(sh, obj)
		}
	}
	return nil
}

// derEncodeECSig converts raw r||s (64 bytes for P-256) to DER ASN.1.
func derEncodeECSig(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("unexpected ECDSA signature length: %d", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	type ecSig struct{ R, S *big.Int }
	return asn1.Marshal(ecSig{R: r, S: s})
}

// GetPublicKey retrieves the EC public key coordinates (x||y, 64 bytes) for a credential.
func (t *pkcs11Token) GetPublicKey(sh pkcs11.SessionHandle, credID []byte) ([]byte, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, credID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "dbus-passkey"),
	}
	if err := t.ctx.FindObjectsInit(sh, template); err != nil {
		return nil, err
	}
	defer t.ctx.FindObjectsFinal(sh)
	objs, _, err := t.ctx.FindObjects(sh, 1)
	if err != nil || len(objs) == 0 {
		return nil, fmt.Errorf("public key not found")
	}
	attrs, err := t.ctx.GetAttributeValue(sh, objs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil || len(attrs) == 0 {
		return nil, fmt.Errorf("get EC_POINT: %w", err)
	}
	// CKA_EC_POINT is a DER-encoded OCTET STRING containing the uncompressed point 04||x||y.
	point := attrs[0].Value
	// Some modules omit the outer OCTET STRING wrapper and return 04||x||y directly.
	if len(point) == 65 && point[0] == 0x04 {
		return point[1:], nil
	}
	// Unwrap DER OCTET STRING: 04 <len> 04 <x> <y>
	if len(point) > 2 && point[0] == 0x04 {
		inner := point[2:]
		if len(inner) == 65 && inner[0] == 0x04 {
			return inner[1:], nil
		}
	}
	return nil, fmt.Errorf("cannot parse EC_POINT: %x", point)
}

var errPINNotInitialized = fmt.Errorf("PINNotInitialized")
