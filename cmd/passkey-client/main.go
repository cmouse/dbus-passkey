// passkey-client is a manual test client for the dbus-passkey broker.
// It stays connected to D-Bus while waiting for the async Response signal,
// so the broker does not auto-cancel the request on client disconnect.
//
// Usage:
//
//	dbus-passkey-client make-credential [--rp example.com] [--user testuser]
//	dbus-passkey-client get-assertion   --rp example.com --cred-id <hex>
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	brokerService = "org.freedesktop.PasskeyBroker"
	brokerPath    = "/org/freedesktop/PasskeyBroker"
	brokerIface   = "org.freedesktop.PasskeyBroker"
	requestIface  = "org.freedesktop.PasskeyBroker.Request"
	timeout       = 60 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: passkey-client <make-credential|get-assertion|enumerate> [flags]")
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		log.Fatalf("connect session bus: %v", err)
	}
	defer conn.Close()

	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(brokerService),
		dbus.WithMatchInterface(requestIface),
		dbus.WithMatchMember("Response"),
	); err != nil {
		log.Fatalf("add match: %v", err)
	}
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)

	switch cmd {
	case "make-credential":
		runMakeCredential(conn, signals, args)
	case "get-assertion":
		runGetAssertion(conn, signals, args)
	case "enumerate":
		runEnumerate(conn)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func runMakeCredential(conn *dbus.Conn, signals <-chan *dbus.Signal, args []string) {
	fs := flag.NewFlagSet("make-credential", flag.ExitOnError)
	rpID := fs.String("rp", "example.com", "relying party ID")
	userName := fs.String("user", "testuser", "user name")
	uv := fs.String("uv", "preferred", "user-verification: required|preferred|discouraged")
	fs.Parse(args)

	challenge := make([]byte, 32)
	rand.Read(challenge)

	opts := map[string]dbus.Variant{
		"rp_id":             dbus.MakeVariant(*rpID),
		"rp_name":           dbus.MakeVariant(*rpID),
		"user_id":           dbus.MakeVariant([]byte(*userName)),
		"user_name":         dbus.MakeVariant(*userName),
		"challenge":         dbus.MakeVariant(challenge),
		"user_verification": dbus.MakeVariant(*uv),
		"pub_key_cred_params": dbus.MakeVariant([]map[string]dbus.Variant{
			{"type": dbus.MakeVariant("public-key"), "alg": dbus.MakeVariant(int32(-7))},
		}),
	}

	obj := conn.Object(brokerService, dbus.ObjectPath(brokerPath))
	var requestPath dbus.ObjectPath
	if err := obj.Call(brokerIface+".MakeCredential", 0, "", opts).Store(&requestPath); err != nil {
		log.Fatalf("MakeCredential call: %v", err)
	}
	log.Printf("request: %s", requestPath)
	log.Printf("waiting for response (touch key if prompted)...")

	results, err := waitResponse(signals, requestPath, timeout)
	if err != nil {
		log.Fatalf("MakeCredential: %v", err)
	}

	credID, _ := results["credential_id"].Value().([]byte)
	attObj, _ := results["attestation_object"].Value().([]byte)
	providerID, _ := results["provider_id"].Value().(string)

	fmt.Printf("OK\n")
	fmt.Printf("provider:           %s\n", providerID)
	fmt.Printf("credential_id:      %s\n", hex.EncodeToString(credID))
	fmt.Printf("attestation_object: %s\n", hex.EncodeToString(attObj))
	fmt.Printf("\nTo assert, run:\n  passkey-client get-assertion --rp %s --cred-id %s\n",
		*rpID, hex.EncodeToString(credID))
}

func runGetAssertion(conn *dbus.Conn, signals <-chan *dbus.Signal, args []string) {
	fs := flag.NewFlagSet("get-assertion", flag.ExitOnError)
	rpID := fs.String("rp", "example.com", "relying party ID")
	credIDHex := fs.String("cred-id", "", "credential ID (hex)")
	uv := fs.String("uv", "preferred", "user-verification: required|preferred|discouraged")
	fs.Parse(args)

	challenge := make([]byte, 32)
	rand.Read(challenge)

	opts := map[string]dbus.Variant{
		"rp_id":             dbus.MakeVariant(*rpID),
		"challenge":         dbus.MakeVariant(challenge),
		"user_verification": dbus.MakeVariant(*uv),
	}

	if *credIDHex != "" {
		credID, err := hex.DecodeString(*credIDHex)
		if err != nil {
			log.Fatalf("invalid cred-id hex: %v", err)
		}
		opts["allow_credentials"] = dbus.MakeVariant([]map[string]dbus.Variant{
			{
				"type":       dbus.MakeVariant("public-key"),
				"id":         dbus.MakeVariant(credID),
				"transports": dbus.MakeVariant([]string{"usb", "internal"}),
			},
		})
	}

	obj := conn.Object(brokerService, dbus.ObjectPath(brokerPath))
	var requestPath dbus.ObjectPath
	if err := obj.Call(brokerIface+".GetAssertion", 0, "", opts).Store(&requestPath); err != nil {
		log.Fatalf("GetAssertion call: %v", err)
	}
	log.Printf("request: %s", requestPath)
	log.Printf("waiting for response (touch key if prompted)...")

	results, err := waitResponse(signals, requestPath, timeout)
	if err != nil {
		log.Fatalf("GetAssertion: %v", err)
	}

	credID, _ := results["credential_id"].Value().([]byte)
	sig, _ := results["signature"].Value().([]byte)
	providerID, _ := results["provider_id"].Value().(string)

	fmt.Printf("OK\n")
	fmt.Printf("provider:    %s\n", providerID)
	fmt.Printf("credential:  %s\n", hex.EncodeToString(credID))
	fmt.Printf("signature:   %s\n", hex.EncodeToString(sig))
}

func runEnumerate(conn *dbus.Conn) {
	obj := conn.Object(brokerService, dbus.ObjectPath(brokerPath))
	var result []map[string]dbus.Variant
	if err := obj.Call(brokerIface+".EnumerateAuthenticators", 0).Store(&result); err != nil {
		log.Fatalf("EnumerateAuthenticators: %v", err)
	}
	for i, a := range result {
		id, _ := a["id"].Value().(string)
		name, _ := a["name"].Value().(string)
		typ, _ := a["type"].Value().(string)
		fmt.Printf("[%d] %s  (%s, %s)\n", i, name, id, typ)
	}
}

func waitResponse(signals <-chan *dbus.Signal, path dbus.ObjectPath, to time.Duration) (map[string]dbus.Variant, error) {
	timer := time.NewTimer(to)
	defer timer.Stop()
	for {
		select {
		case sig := <-signals:
			if sig.Path != path || sig.Name != requestIface+".Response" {
				continue
			}
			code, _ := sig.Body[0].(uint32)
			results, _ := sig.Body[1].(map[string]dbus.Variant)
			if code != 0 {
				errCode, _ := results["error_code"].Value().(string)
				errMsg, _ := results["error_message"].Value().(string)
				return nil, fmt.Errorf("response code=%d %s: %s", code, errCode, errMsg)
			}
			return results, nil
		case <-timer.C:
			return nil, fmt.Errorf("timeout after %s", to)
		}
	}
}
