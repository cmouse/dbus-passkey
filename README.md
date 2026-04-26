# D-Bus Passkey

## Broker daemon

A D-Bus broker daemon that routes FIDO2/passkey operations to physical hardware tokens (via libfido2) and registered software providers. Applications call the broker; the broker handles device selection, PIN collection (via a UI agent), and operation dispatch.

## UI Agent

Provides a UI agent that can be used to do selection, PIN entry and consent.

## Gnome keyring provider

This can be installed if you have Gnome keyring as a software passkey.

## Features

The broker provides support for physical keys and 3rd party software tokens.

# Fast installation

You can find pre-built binaries under releases. These binaries are intended to be ran under your account,
so if you use the systemd units, they need to run as your session, so place them under /etc/systemd/user or $HOME/.config/systemd/user.

The binaries can go under /usr/bin/ or ${HOME}/.local/bin.

See below for testing instructions.

## Architecture

```
Application
    │  MakeCredential / GetAssertion
    ▼
org.freedesktop.PasskeyBroker   (this daemon)
    ├── Hardware tokens          (libfido2, USB)
    ├── GNOME Keyring provider   (PKCS#11 keys + Secret Service metadata)
    └── Software providers       (fi.cmouse.PasskeyBroker.Provider, D-Bus)

UI Agent (separate process)
    └── org.freedesktop.PasskeyBroker.UIAgent
        ├── SelectAuthenticator
        ├── CollectPIN / CollectNewPIN
        └── NotifyOperation
```

The broker owns no credentials. Hardware tokens store them on-device; software providers manage their own storage.

## D-Bus Interfaces

| Interface | Who implements | Purpose |
|-----------|---------------|---------|
| `org.freedesktop.PasskeyBroker` | This daemon | Application-facing: MakeCredential, GetAssertion |
| `org.freedesktop.PasskeyBroker.UIAgent` | UI component | Authenticator selection, PIN entry, status notifications |
| `fi.cmouse.PasskeyBroker.Provider` | Software providers | Software passkey backends |

Full interface definitions are in the [`dbus/`](dbus/) directory.

### MakeCredential

```
MakeCredential(parent_window s, options a{sv}) -> (handle o)
```

Returns a Request object path. Connect to the `Response` signal on that path:

```
signal Response(response u, results a{sv})
```

Response codes: `0` success, `1` cancelled, `2` interaction-ended (timeout/UI gone), `3` error.

### GetAssertion

```
GetAssertion(parent_window s, options a{sv}) -> (handle o)
```

Same Request/Response pattern as MakeCredential.

### UI Agent

Register a UI agent to handle authenticator selection and PIN entry:

```
RegisterUIAgent(agent_path o)
UnregisterUIAgent(agent_path o)
```

The broker watches the agent's D-Bus name; if the UI process exits, the agent is auto-unregistered and the broker falls back to headless auto-selection.

## GNOME Keyring Provider

`dbus-passkey-gnome-keyring-provider` is a software passkey provider for users without hardware
FIDO2 tokens. Private keys are generated and stored inside gnome-keyring's PKCS#11 module —
they are never exposed in plaintext. Credential metadata is stored encrypted in the
GNOME Keyring Secret Service (default collection).

Every operation (registration and assertion) requires the user to enter a PIN via the UI agent.
On first use a "Set new PIN" dialog appears to initialize the PKCS#11 token; thereafter a
"Enter PIN" dialog appears before each operation, providing explicit user consent.

### Prerequisites

- `gnome-keyring` with PKCS#11 support (`gnome-keyring-pkcs11.so`)
- `dbus-passkey-ui-agent` running (required for PIN prompts)

### Installation

```sh
make install-gnome-keyring-provider
```

This installs the binary to `$(PREFIX)/libexec/` and the provider config to
`$(PREFIX)/share/dbus-passkey/providers.d/gnome-keyring-provider.conf`.

The provider config sets `RequiresPIN=true`, which tells the broker to always collect
a PIN via the UI agent before calling into the provider.

### Verifying stored keys

```sh
# List PKCS#11 objects (adjust module path for your distro)
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/gnome-keyring-pkcs11.so -O

# List Secret Service metadata
secret-tool search app dbus-passkey
```

### Security properties

| Property | Detail |
|----------|--------|
| Private key storage | gnome-keyring PKCS#11 (CKA_SENSITIVE=true, CKA_EXTRACTABLE=false) |
| Metadata storage | Secret Service default collection (encrypted at rest) |
| Per-operation consent | PIN required; collected via UI agent before every operation |
| Key algorithm | EC P-256 (ES256, COSE alg -7) |

## Software Providers

Drop `.conf` files into `/usr/share/dbus-passkey/providers.d/` (or `/etc/dbus-passkey/providers.d/` to override):

```ini
[Provider]
Name=My Software Token
ID=my-softtoken
DBusName=org.example.SoftToken
ObjectPath=/org/example/SoftToken
Transports=software;internal
SupportedAlgorithms=-7;-8
Priority=50
```

D-Bus service activation handles provider process lifetime — providers ship their own `.service` files in `/usr/share/dbus-1/services/`. Send SIGHUP to the broker to reload the provider registry without dropping active requests.

## Authenticator Management

### Enumerate

```
EnumerateAuthenticators() -> aa{sv}
```

Returns all available authenticators — both connected hardware FIDO2 tokens and registered software providers. Each entry includes `id`, `name`, `type`, `has_pin`, `pin_retries`, `is_fido2`, `min_pin_length`.

Use the returned `id` with the management methods below.

### Set / Change PIN

```
SetPIN(token_id s, parent_window s) -> (handle o)
```

Async. The broker calls `CollectNewPIN` on the UI agent (and `CollectPIN` for the old PIN if one is already set). `token_id` is the `id` from `EnumerateAuthenticators`.

### Reset Token

```
ResetToken(token_id s, parent_window s) -> (handle o)
```

Async. Calls `ConfirmReset` on the UI agent, then performs CTAP2 `authenticatorReset`.

**Important:** CTAP2 reset only succeeds within ~10 seconds of device power-up and requires a physical touch. Remove and reinsert the token immediately before calling `ResetToken`. All credentials on the device are permanently erased.

## Testing / Manual Verification

`dbus-passkey-client` is a command-line test client that exercises the broker over D-Bus.

### List authenticators

```sh
dbus-passkey-client enumerate
# [0] PasskeyTestProvider  (test-provider, software)
# [1] YubiKey 5C NFC       (fido2-<serial>, fido2)
```

### Register a credential

```sh
dbus-passkey-client make-credential --rp example.com --user alice
# OK
# provider:           fido2-12345678
# credential_id:      deadbeef…
# attestation_object: 82…
#
# To assert, run:
#   dbus-passkey-client get-assertion --rp example.com --cred-id deadbeef…
```

Options: `--rp` (relying-party ID, default `example.com`), `--user` (username, default `testuser`), `--uv` (user-verification policy: `required|preferred|discouraged`, default `preferred`).

### Assert / authenticate

```sh
dbus-passkey-client get-assertion --rp example.com --cred-id deadbeef…
# OK
# provider:    fido2-12345678
# credential:  deadbeef…
# signature:   3045…
```

Omit `--cred-id` to allow any credential for the RP (discoverable credential / passkey flow).

## Security Notes

- **PIN handling**: PINs are held in memory only from UI agent return to provider/libfido2 call. The `[]byte` buffer is zeroed after use. A transient `string` copy exists for the libfido2 API call and will persist until GC.
- **No credential storage**: the broker never persists credentials.
- **Caller disconnect**: if the calling application disconnects while an operation is in progress, the broker cancels the operation and emits `Response(1, {})`.

## License

MIT — see [LICENSE](LICENSE).
