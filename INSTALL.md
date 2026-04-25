# Installation

## Build Dependencies

- Go 1.22 or later
- `libfido2-dev` (or equivalent for your distro)
- `pkg-config`
- C compiler (gcc or clang)

### Debian / Ubuntu

```sh
apt install libfido2-dev pkg-config gcc
```

### Fedora / RHEL

```sh
dnf install libfido2-devel pkgconf gcc
```

### Arch Linux

```sh
pacman -S libfido2 pkgconf gcc
```

## Build

```sh
git clone https://github.com/cmouse/dbus-passkey
cd dbus-passkey
make build
```

To build without hardware FIDO2 support (no libfido2 required):

```sh
make build-nofido2
```

## Install

```sh
sudo make install
```

Installs to `/usr/libexec/dbus-passkey` by default. Override with `PREFIX`:

```sh
sudo make install PREFIX=/usr/local
```

This also installs:
- `systemd/dbus-passkey.service` → `$PREFIX/lib/systemd/user/`
- `dbus-service/org.freedesktop.PasskeyBroker.service` → `$PREFIX/share/dbus-1/services/`
- `config/providers.d/example.conf` → `$PREFIX/share/dbus-passkey/providers.d/`

## Enable (systemd user session)

```sh
systemctl --user enable --now dbus-passkey
```

The D-Bus service file also allows on-demand activation: any application calling `org.freedesktop.PasskeyBroker` will start the daemon automatically.

## udev Rules (hardware tokens)

To allow non-root access to FIDO2 USB tokens, install the appropriate udev rules. Most distros ship these with the libfido2 or `fido2-tools` package:

```sh
# Debian/Ubuntu
apt install fido2-tools

# Fedora
dnf install fido2-tools
```

If not available, the upstream rules are at:
https://github.com/Yubico/libfido2/tree/main/udev

Place them in `/etc/udev/rules.d/` and reload:

```sh
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## Software Providers

Place provider `.conf` files in:
- `/usr/share/dbus-passkey/providers.d/` — system-wide
- `/etc/dbus-passkey/providers.d/` — local overrides (take precedence)

Send SIGHUP to the broker to reload providers without restarting:

```sh
systemctl --user kill -s HUP dbus-passkey
```

## Verify

After starting the daemon:

```sh
dbus-send --session \
  --dest=org.freedesktop.PasskeyBroker \
  --print-reply \
  /org/freedesktop/PasskeyBroker \
  org.freedesktop.DBus.Introspectable.Introspect
```

Should return the broker interface XML.
