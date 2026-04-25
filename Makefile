BINARY = dbus-passkey
TEST_PROVIDER = dbus-passkey-test-provider
UI_AGENT = dbus-passkey-ui-agent
PREFIX ?= /usr

build:
	CGO_ENABLED=1 go build -o $(BINARY) ./cmd/dbus-passkey

build-nofido2:
	CGO_ENABLED=0 go build -o $(BINARY)-nofido2 ./cmd/dbus-passkey

build-test-provider:
	CGO_ENABLED=0 go build -o $(TEST_PROVIDER) ./cmd/test-provider

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

build-ui-agent:
	CGO_ENABLED=0 go build -o $(UI_AGENT) ./cmd/ui-agent

install-ui-agent: build-ui-agent
	install -Dm755 $(UI_AGENT) $(DESTDIR)$(PREFIX)/libexec/$(UI_AGENT)
	install -Dm644 dbus/org.freedesktop.PasskeyBroker.UIAgent.service \
		$(DESTDIR)$(PREFIX)/share/dbus-1/services/org.freedesktop.PasskeyBroker.UIAgent.service
	install -Dm644 systemd/dbus-passkey-ui-agent.service \
		$(DESTDIR)$(PREFIX)/lib/systemd/user/dbus-passkey-ui-agent.service

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-nofido2 $(TEST_PROVIDER) $(UI_AGENT)

.PHONY: build build-nofido2 build-test-provider build-ui-agent install install-test-provider install-ui-agent vet clean
