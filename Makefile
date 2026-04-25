BINARY = dbus-passkey
PREFIX ?= /usr

build:
	CGO_ENABLED=1 go build -o $(BINARY) ./cmd/dbus-passkey

build-nofido2:
	CGO_ENABLED=0 go build -o $(BINARY)-nofido2 ./cmd/dbus-passkey

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/libexec/$(BINARY)
	install -Dm644 systemd/dbus-passkey.service $(DESTDIR)$(PREFIX)/lib/systemd/user/dbus-passkey.service
	install -Dm644 dbus-service/org.freedesktop.PasskeyBroker.service \
		$(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.PasskeyBroker.service
	install -Dm644 config/providers.d/example.conf \
		$(DESTDIR)$(PREFIX)/share/dbus-passkey/providers.d/example.conf

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-nofido2

.PHONY: build build-nofido2 install vet clean
