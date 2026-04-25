package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	brokerService    = "org.freedesktop.PasskeyBroker"
	brokerPath       = "/org/freedesktop/PasskeyBroker"
	brokerIface      = "org.freedesktop.PasskeyBroker"
	requestIface     = "org.freedesktop.PasskeyBroker.Request"
	providerService  = "fi.cmouse.PasskeyBroker.TestProvider"
	nameWaitTimeout  = 30 * time.Second
	responseTimeout  = 15 * time.Second
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("e2e test FAILED: %v", err)
	}
	log.Println("e2e test PASSED")
}

func run() error {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("connect session bus: %w", err)
	}
	defer conn.Close()

	log.Println("waiting for broker...")
	if err := waitForName(conn, brokerService, nameWaitTimeout); err != nil {
		return err
	}
	log.Println("waiting for test-provider...")
	if err := waitForName(conn, providerService, nameWaitTimeout); err != nil {
		return err
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(brokerService),
		dbus.WithMatchInterface(requestIface),
		dbus.WithMatchMember("Response"),
	); err != nil {
		return fmt.Errorf("add match signal: %w", err)
	}

	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)

	log.Println("running MakeCredential...")
	credID, err := doMakeCredential(conn, signals)
	if err != nil {
		return fmt.Errorf("MakeCredential: %w", err)
	}
	log.Printf("MakeCredential: OK, credID prefix=%x", credID[:min(8, len(credID))])

	log.Println("running GetAssertion...")
	if err := doGetAssertion(conn, signals, credID); err != nil {
		return fmt.Errorf("GetAssertion: %w", err)
	}
	log.Println("GetAssertion: OK")

	return nil
}

func doMakeCredential(conn *dbus.Conn, signals <-chan *dbus.Signal) ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}

	opts := map[string]dbus.Variant{
		"rp_id":     dbus.MakeVariant("example.com"),
		"rp_name":   dbus.MakeVariant("Example"),
		"user_id":   dbus.MakeVariant([]byte("e2e-user-1")),
		"user_name": dbus.MakeVariant("e2e-user"),
		"challenge": dbus.MakeVariant(challenge),
		"pub_key_cred_params": dbus.MakeVariant([]map[string]dbus.Variant{
			{
				"type": dbus.MakeVariant("public-key"),
				"alg":  dbus.MakeVariant(int32(-7)),
			},
		}),
	}

	obj := conn.Object(brokerService, dbus.ObjectPath(brokerPath))
	var requestPath dbus.ObjectPath
	if err := obj.Call(brokerIface+".MakeCredential", 0, "", opts).Store(&requestPath); err != nil {
		return nil, fmt.Errorf("call: %w", err)
	}
	log.Printf("  request path: %s", requestPath)

	results, err := waitResponse(signals, requestPath, responseTimeout)
	if err != nil {
		return nil, err
	}
	credID, _ := results["credential_id"].Value().([]byte)
	if len(credID) == 0 {
		return nil, fmt.Errorf("response missing credential_id")
	}
	return credID, nil
}

func doGetAssertion(conn *dbus.Conn, signals <-chan *dbus.Signal, credID []byte) error {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("rand: %w", err)
	}

	opts := map[string]dbus.Variant{
		"rp_id":     dbus.MakeVariant("example.com"),
		"challenge": dbus.MakeVariant(challenge),
		"allow_credentials": dbus.MakeVariant([]map[string]dbus.Variant{
			{
				"type":       dbus.MakeVariant("public-key"),
				"id":         dbus.MakeVariant(credID),
				"transports": dbus.MakeVariant([]string{"internal"}),
			},
		}),
	}

	obj := conn.Object(brokerService, dbus.ObjectPath(brokerPath))
	var requestPath dbus.ObjectPath
	if err := obj.Call(brokerIface+".GetAssertion", 0, "", opts).Store(&requestPath); err != nil {
		return fmt.Errorf("call: %w", err)
	}
	log.Printf("  request path: %s", requestPath)

	_, err := waitResponse(signals, requestPath, responseTimeout)
	return err
}

func waitResponse(signals <-chan *dbus.Signal, path dbus.ObjectPath, timeout time.Duration) (map[string]dbus.Variant, error) {
	timer := time.NewTimer(timeout)
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
				return nil, fmt.Errorf("response code=%d error=%s: %s", code, errCode, errMsg)
			}
			return results, nil
		case <-timer.C:
			return nil, fmt.Errorf("timeout waiting for response on %s", path)
		}
	}
}

func waitForName(conn *dbus.Conn, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var owner string
		err := conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, name).Store(&owner)
		if err == nil && owner != "" {
			log.Printf("  %s ready (%s)", name, owner)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s to appear on bus", name)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
