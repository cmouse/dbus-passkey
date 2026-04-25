//go:build cgo

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
	busName    = "fi.cmouse.PasskeyBroker.GnomeKeyringProvider"
	objectPath = "/fi/cmouse/PasskeyBroker/GnomeKeyringProvider"
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

	provider, err := newGnomeKeyringProvider(conn)
	if err != nil {
		log.Fatalf("init provider: %v", err)
	}
	defer provider.close()

	conn.Export(provider, dbus.ObjectPath(objectPath), iface)
	conn.Export(introspect.Introspectable(introspectXML), dbus.ObjectPath(objectPath),
		"org.freedesktop.DBus.Introspectable")

	log.Printf("running as %s at %s", busName, objectPath)
	log.Printf("register with broker — add to /etc/dbus-passkey/providers.d/gnome-keyring-provider.conf:")
	log.Printf("  [Provider]")
	log.Printf("  Name=GNOME Keyring")
	log.Printf("  ID=gnome-keyring-provider")
	log.Printf("  DBusName=%s", busName)
	log.Printf("  ObjectPath=%s", objectPath)
	log.Printf("  Transports=internal")
	log.Printf("  SupportedAlgorithms=-7")
	log.Printf("  Priority=40")
	log.Printf("  RequiresPIN=true")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Println("shutting down")
}
