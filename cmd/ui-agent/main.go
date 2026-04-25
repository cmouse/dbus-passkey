package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

const (
	agentBusName    = "org.freedesktop.PasskeyBroker.UIAgent"
	agentObjectPath = dbus.ObjectPath("/org/freedesktop/PasskeyBroker/UIAgent")

	brokerBusName    = "org.freedesktop.PasskeyBroker"
	brokerObjectPath = dbus.ObjectPath("/org/freedesktop/PasskeyBroker")
	brokerIface      = "org.freedesktop.PasskeyBroker"
)

// introspectXML is read from the existing interface definition file.
// Embedded here so the binary is self-contained.
const introspectXML = `<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.PasskeyBroker.UIAgent">
    <method name="SelectAuthenticator">
      <arg name="request_handle" type="o" direction="in"/>
      <arg name="operation" type="s" direction="in"/>
      <arg name="rp_id" type="s" direction="in"/>
      <arg name="candidates" type="aa{sv}" direction="in"/>
      <arg name="selected_index" type="i" direction="out"/>
    </method>
    <method name="CollectPIN">
      <arg name="request_handle" type="o" direction="in"/>
      <arg name="rp_id" type="s" direction="in"/>
      <arg name="provider_id" type="s" direction="in"/>
      <arg name="attempts_left" type="i" direction="in"/>
      <arg name="pin" type="s" direction="out"/>
    </method>
    <method name="CollectNewPIN">
      <arg name="request_handle" type="o" direction="in"/>
      <arg name="token_id" type="s" direction="in"/>
      <arg name="token_name" type="s" direction="in"/>
      <arg name="min_length" type="i" direction="in"/>
      <arg name="pin" type="s" direction="out"/>
    </method>
    <method name="ConfirmReset">
      <arg name="request_handle" type="o" direction="in"/>
      <arg name="token_id" type="s" direction="in"/>
      <arg name="token_name" type="s" direction="in"/>
      <arg name="confirmed" type="b" direction="out"/>
    </method>
    <method name="NotifyOperation">
      <arg name="request_handle" type="o" direction="in"/>
      <arg name="operation" type="s" direction="in"/>
      <arg name="rp_id" type="s" direction="in"/>
      <arg name="status" type="s" direction="in"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="data" type="s" direction="out"/>
    </method>
  </interface>
</node>`

func main() {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Fatalf("connect session bus: %v", err)
	}
	defer conn.Close()

	reply, err := conn.RequestName(agentBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("request bus name: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("bus name %s already owned", agentBusName)
	}

	agent := &agentService{}
	if err := conn.Export(agent, agentObjectPath, agentIface); err != nil {
		log.Fatalf("export UIAgent: %v", err)
	}
	if err := conn.Export(
		introspect.Introspectable(introspectXML),
		agentObjectPath,
		"org.freedesktop.DBus.Introspectable",
	); err != nil {
		log.Fatalf("export introspectable: %v", err)
	}

	broker := conn.Object(brokerBusName, brokerObjectPath)
	if err := broker.Call(brokerIface+".RegisterUIAgent", 0, agentObjectPath).Err; err != nil {
		log.Fatalf("RegisterUIAgent: %v", err)
	}
	log.Printf("UI agent registered at %s", agentObjectPath)

	// Watch for broker disconnect so we can exit cleanly.
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
	); err != nil {
		log.Printf("add match signal: %v", err)
	}
	sigCh := make(chan *dbus.Signal, 8)
	conn.Signal(sigCh)

	osSig := make(chan os.Signal, 1)
	signal.Notify(osSig, syscall.SIGTERM, syscall.SIGINT)

	for {
		select {
		case sig := <-sigCh:
			if sig == nil {
				return
			}
			if sig.Name == "org.freedesktop.DBus.NameOwnerChanged" &&
				len(sig.Body) == 3 {
				name, _ := sig.Body[0].(string)
				newOwner, _ := sig.Body[2].(string)
				if name == brokerBusName && newOwner == "" {
					log.Printf("broker disappeared, exiting")
					return
				}
			}
		case <-osSig:
			broker.Call(brokerIface+".UnregisterUIAgent", dbus.FlagNoReplyExpected, agentObjectPath)
			return
		}
	}
}
