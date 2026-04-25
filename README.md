# dbus-passkey

A D-Bus broker daemon that routes FIDO2/passkey operations to physical hardware tokens (via libfido2) and registered software providers. Applications call the broker; the broker handles device selection, PIN collection (via a UI agent), and operation dispatch.

## Architecture

```
Application
    │  MakeCredential / GetAssertion
    ▼
org.freedesktop.PasskeyBroker   (this daemon)
    ├── Hardware tokens          (libfido2, USB)
    └── Software providers       (fi.cmouse.PasskeyBroker.Provider, D-Bus)

UI Agent (separate process)
    └── org.freedesktop.PasskeyBroker.UIAgent
        ├── SelectAuthenticator
        ├── CollectPIN
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

## Security Notes

- **PIN handling**: PINs are held in memory only from UI agent return to provider/libfido2 call. The `[]byte` buffer is zeroed after use. A transient `string` copy exists for the libfido2 API call and will persist until GC.
- **No credential storage**: the broker never persists credentials.
- **Caller disconnect**: if the calling application disconnects while an operation is in progress, the broker cancels the operation and emits `Response(1, {})`.

## License

MIT — see [LICENSE](LICENSE).
