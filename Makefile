BINARY           = dbus-passkey
UI_AGENT         = dbus-passkey-ui-agent
TEST_PROVIDER    = dbus-passkey-test-provider
KEYRING_PROVIDER = dbus-passkey-gnome-keyring-provider
E2E_TEST         = dbus-passkey-e2e-test
CLIENT           = dbus-passkey-client
PREFIX ?= /usr

all: build-all

build:
	CGO_ENABLED=1 go build -o $(BINARY) ./cmd/dbus-passkey

build-nofido2:
	CGO_ENABLED=0 go build -o $(BINARY)-nofido2 ./cmd/dbus-passkey

build-ui-agent:
	CGO_ENABLED=0 go build -o $(UI_AGENT) ./cmd/ui-agent

build-test-provider:
	CGO_ENABLED=0 go build -o $(TEST_PROVIDER) ./cmd/test-provider

build-gnome-keyring-provider:
	CGO_ENABLED=1 go build -o $(KEYRING_PROVIDER) ./cmd/gnome-keyring-provider

build-e2e-test:
	CGO_ENABLED=0 go build -o $(E2E_TEST) ./cmd/e2e-test

build-client:
	CGO_ENABLED=0 go build -o $(CLIENT) ./cmd/passkey-client

build-all: build build-ui-agent build-test-provider build-gnome-keyring-provider build-e2e-test build-client

build-all-nofido2: build-nofido2 build-ui-agent build-test-provider build-e2e-test build-client

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/libexec/$(BINARY)
	install -Dm644 systemd/dbus-passkey.service $(DESTDIR)$(PREFIX)/lib/systemd/user/dbus-passkey.service
	install -Dm644 dbus-service/org.freedesktop.PasskeyBroker.service \
		$(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.PasskeyBroker.service
	install -Dm644 config/providers.d/example.conf \
		$(DESTDIR)$(PREFIX)/share/dbus-passkey/providers.d/example.conf

install-test-provider: build-test-provider
	install -Dm755 $(TEST_PROVIDER) $(DESTDIR)$(PREFIX)/libexec/$(TEST_PROVIDER)
	install -Dm644 config/providers.d/test-provider.conf \
		$(DESTDIR)$(PREFIX)/share/dbus-passkey/providers.d/test-provider.conf

install-gnome-keyring-provider: build-gnome-keyring-provider
	install -Dm755 $(KEYRING_PROVIDER) $(DESTDIR)$(PREFIX)/libexec/$(KEYRING_PROVIDER)
	install -Dm644 config/providers.d/gnome-keyring-provider.conf \
		$(DESTDIR)$(PREFIX)/share/dbus-passkey/providers.d/gnome-keyring-provider.conf

install-ui-agent: build-ui-agent
	install -Dm755 $(UI_AGENT) $(DESTDIR)$(PREFIX)/libexec/$(UI_AGENT)
	install -Dm644 dbus/org.freedesktop.PasskeyBroker.UIAgent.service \
		$(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.PasskeyBroker.UIAgent.service
	install -Dm644 systemd/dbus-passkey-ui-agent.service \
		$(DESTDIR)$(PREFIX)/lib/systemd/user/dbus-passkey-ui-agent.service

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-nofido2 $(UI_AGENT) $(TEST_PROVIDER) $(KEYRING_PROVIDER) $(E2E_TEST) $(CLIENT)

.PHONY: build build-nofido2 build-ui-agent build-test-provider build-gnome-keyring-provider \
        build-e2e-test build-client build-all build-all-nofido2 \
        install install-test-provider install-gnome-keyring-provider install-ui-agent vet clean all
