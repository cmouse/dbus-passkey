package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cmouse/dbus-passkey/internal/broker"
	"github.com/cmouse/dbus-passkey/internal/provider"
	"github.com/godbus/dbus/v5"
)

func main() {
	providersDir := flag.String("providers-dir", "", "override providers config directory")
	flag.Parse()

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		log.Fatalf("connect session bus: %v", err)
	}
	defer conn.Close()

	reply, err := conn.RequestName("org.freedesktop.PasskeyBroker", dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("request name: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("name already taken")
	}

	var reg *provider.Registry
	if *providersDir != "" {
		reg = provider.NewRegistryWithDirs(*providersDir)
	} else {
		reg = provider.NewRegistry()
	}

	_, err = broker.New(conn, reg)
	if err != nil {
		log.Fatalf("create broker: %v", err)
	}

	log.Println("dbus-passkey running")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for sig := range sigs {
		switch sig {
		case syscall.SIGHUP:
			log.Println("reloading provider registry")
			reg.Reload()
		default:
			log.Println("shutting down")
			return
		}
	}
}
