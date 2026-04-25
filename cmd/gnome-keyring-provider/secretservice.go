package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	ssService    = "org.freedesktop.secrets"
	ssPath       = "/org/freedesktop/secrets"
	ssIface      = "org.freedesktop.secrets.Service"
	ssCollIface  = "org.freedesktop.secrets.Collection"
	ssItemIface  = "org.freedesktop.secrets.Item"
	ssSessionIface = "org.freedesktop.secrets.Session"
	defaultAlias = "/org/freedesktop/secrets/aliases/default"
)

type credMeta struct {
	CredID          []byte `json:"cred_id"`
	RPID            string `json:"rp_id"`
	UserID          []byte `json:"user_id"`
	UserName        string `json:"user_name"`
	UserDisplayName string `json:"user_display_name"`
	SignCount       uint32 `json:"sign_count"`
}

type secretService struct {
	conn        *dbus.Conn
	sessionPath dbus.ObjectPath
}

// dbusSecret is the D-Bus Secret struct: (session, parameters, value, content_type).
type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func newSecretService(conn *dbus.Conn) (*secretService, error) {
	svc := conn.Object(ssService, dbus.ObjectPath(ssPath))

	var output dbus.Variant
	var sessionPath dbus.ObjectPath
	call := svc.Call(ssIface+".OpenSession", 0, "plain", dbus.MakeVariant(""))
	if call.Err != nil {
		return nil, fmt.Errorf("OpenSession: %w", call.Err)
	}
	if err := call.Store(&output, &sessionPath); err != nil {
		return nil, fmt.Errorf("OpenSession store: %w", err)
	}
	return &secretService{conn: conn, sessionPath: sessionPath}, nil
}

func (ss *secretService) close() {
	obj := ss.conn.Object(ssService, ss.sessionPath)
	obj.Call(ssSessionIface+".Close", dbus.FlagNoReplyExpected)
}

// FindCredentials searches for credentials matching rpID and optional allowList.
func (ss *secretService) FindCredentials(rpID string, allowList [][]byte) ([]credMeta, error) {
	attrs := map[string]string{
		"app":   "dbus-passkey",
		"rp_id": rpID,
	}
	svc := ss.conn.Object(ssService, dbus.ObjectPath(ssPath))
	var unlocked, locked []dbus.ObjectPath
	if err := svc.Call(ssIface+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return nil, fmt.Errorf("SearchItems: %w", err)
	}

	// Unlock any locked items
	if len(locked) > 0 {
		var unlockedNow []dbus.ObjectPath
		var prompt dbus.ObjectPath
		if err := svc.Call(ssIface+".Unlock", 0, locked).Store(&unlockedNow, &prompt); err == nil {
			unlocked = append(unlocked, unlockedNow...)
		}
	}

	var results []credMeta
	for _, itemPath := range unlocked {
		meta, err := ss.readItem(itemPath)
		if err != nil {
			continue
		}
		if len(allowList) == 0 {
			results = append(results, meta)
			continue
		}
		for _, id := range allowList {
			if hex.EncodeToString(id) == hex.EncodeToString(meta.CredID) {
				results = append(results, meta)
				break
			}
		}
	}
	return results, nil
}

func (ss *secretService) readItem(itemPath dbus.ObjectPath) (credMeta, error) {
	obj := ss.conn.Object(ssService, itemPath)
	var secret dbusSecret
	if err := obj.Call(ssItemIface+".GetSecret", 0, ss.sessionPath).Store(&secret); err != nil {
		return credMeta{}, err
	}
	var meta credMeta
	if err := json.Unmarshal(secret.Value, &meta); err != nil {
		return credMeta{}, err
	}
	return meta, nil
}

// StoreCredential creates a Secret Service item for the given credential metadata.
func (ss *secretService) StoreCredential(meta credMeta) error {
	payload, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	secret := dbusSecret{
		Session:     ss.sessionPath,
		Parameters:  []byte{},
		Value:       payload,
		ContentType: "application/json",
	}

	label := fmt.Sprintf("Passkey: %s @ %s", meta.UserName, meta.RPID)
	attrs := map[string]string{
		"app":     "dbus-passkey",
		"rp_id":   meta.RPID,
		"cred_id": hex.EncodeToString(meta.CredID),
	}

	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant(label),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attrs),
	}

	coll := ss.conn.Object(ssService, dbus.ObjectPath(defaultAlias))
	var itemPath dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := coll.Call(ssCollIface+".CreateItem", 0, properties, secret, true).Store(&itemPath, &prompt); err != nil {
		return fmt.Errorf("CreateItem: %w", err)
	}
	return nil
}

// UpdateSignCount reads the item for credID, updates sign_count, and rewrites it.
func (ss *secretService) UpdateSignCount(credID []byte, rpID string, count uint32) error {
	attrs := map[string]string{
		"app":     "dbus-passkey",
		"cred_id": hex.EncodeToString(credID),
	}
	svc := ss.conn.Object(ssService, dbus.ObjectPath(ssPath))
	var unlocked, locked []dbus.ObjectPath
	if err := svc.Call(ssIface+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return err
	}
	if len(unlocked) == 0 {
		return fmt.Errorf("credential not found in Secret Service")
	}
	meta, err := ss.readItem(unlocked[0])
	if err != nil {
		return err
	}
	meta.SignCount = count
	return ss.StoreCredential(meta)
}
