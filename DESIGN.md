# dbus-passkey Design

## Purpose

`dbus-passkey` is a session-bus D-Bus daemon that acts as a broker between applications that need FIDO2/passkey operations and the authenticators that perform them — either physical USB hardware tokens (via libfido2) or software providers (via D-Bus). It handles authenticator selection, PIN collection, and result dispatch. It stores no credentials.

---

## Component Map

```
cmd/dbus-passkey/          Binary entry point — bus setup, signal loop
cmd/test-provider/         Reference software provider binary

internal/
  broker/
    broker.go              Core D-Bus service object; orchestrates all operations
    request.go             Per-operation D-Bus object (async handle + Response signal)
    agent.go               UI agent registry and call helpers

  provider/
    interface.go           Provider interface and RegistryEntry types
    registry.go            Loads .conf files from providers.d/; SIGHUP reload
    dbus_provider.go       DBusProvider — proxies a software provider over D-Bus
    selector.go            Candidate filtering and priority sorting

  fido2/                   CGO build tag guards all libfido2 access
    device.go              Worker goroutine + TokenProvider
    token_provider.go      libfido2 MakeCredential/GetAssertion implementation
    enrollment.go          EnumerateTokenInfos, SetPIN, ResetToken
    *_stub.go              No-CGO stubs returning NotSupportedError

  types/
    webauthn.go            Shared structs (options, results, candidate, authenticator info)
```

---

## D-Bus Interfaces

Three separate interfaces divide responsibility cleanly:

| Interface | Implemented by | Direction |
|-----------|---------------|-----------|
| `org.freedesktop.PasskeyBroker` | This daemon | Applications call the broker |
| `org.freedesktop.PasskeyBroker.UIAgent` | UI process | Broker calls the agent |
| `fi.cmouse.PasskeyBroker.Provider` | Software providers | Broker calls providers |

The broker is the hub. It never calls back into the application; it only emits signals on Request objects the application watches.

---

## Async Request Pattern

All credential operations (`MakeCredential`, `GetAssertion`, `SetPIN`, `ResetToken`) are asynchronous. The method call returns immediately with an object path; the result arrives later as a signal on that path.

```
Application                   Broker                       Provider
    |                            |                              |
    |-- MakeCredential(opts) --> |                              |
    |<-- /request/…/1 ----------|                              |
    |                            |-- (goroutine starts) ------> |
    |                            |<-- result ------------------- |
    |<-- Response(0, results) ---|                              |
```

### Request Object Lifecycle

1. `broker.newRequest()` generates a unique path: `…/request/<escaped-sender>/<counter>`
2. `exportRequest()` exports the object at that path with two interfaces:
   - `org.freedesktop.PasskeyBroker.Request` — exposes `Close()` and `Response` signal
   - `org.freedesktop.DBus.Introspectable`
3. The operation runs in a goroutine. On completion (success, error, or cancel):
   - `emitResponse()` fires exactly once (guarded by `sync.Once`)
   - The object is un-exported before emitting the signal, preventing re-entry
4. The application may call `Close()` to cancel before the result arrives.

`Request` holds two `sync.Once` guards:
- `cancelOnce` — idempotent `close(cancel)` channel; wired to `cancelRequestsForSender` on disconnect and to the `Close()` method
- `emitOnce` — ensures exactly one `Response` signal is emitted even under concurrent cancel+completion races

---

## Provider Abstraction

All authenticators — hardware and software — implement the same `Provider` interface:

```go
type Provider interface {
    ID() string
    Name() string
    Type() string              // "hardware" or "software"
    Transports() []string
    SupportedAlgorithms() []int32
    HasCredentials(rpID string, allowList [][]byte) ([][]byte, error)
    MakeCredential(opts *MakeCredentialOptions, pin []byte) (*MakeCredentialResult, error)
    GetAssertion(opts *GetAssertionOptions, pin []byte) (*GetAssertionResult, error)
    Cancel()
}
```

`TokenProvider` wraps a libfido2 device. `DBusProvider` wraps a software provider over D-Bus. The broker and selector layers treat them identically.

### Software Provider Registry

Providers are registered by dropping INI `.conf` files into:
- `/usr/share/dbus-passkey/providers.d/` — system defaults
- `/etc/dbus-passkey/providers.d/` — site overrides (same `ID` replaces system entry)

The registry is loaded at startup and reloaded on SIGHUP without dropping active requests. D-Bus service activation handles provider process lifetime — providers ship their own `.service` files.

---

## libfido2 Worker

All libfido2 calls must run on a single OS thread because libfido2 is not thread-safe across devices and maintains internal USB context state. A buffered channel (`chan func()`) serialises all libfido2 operations:

```
Worker goroutine (runtime.LockOSThread)
    ┌──────────────────────────────────────────────┐
    │  for fn := range ch { fn() }                 │
    └──────────────────────────────────────────────┘
         ↑  ↑  ↑
         │  │  └── RetryCount, Info, IsFIDO2 (enrollment)
         │  └───── GetAssertion
         └──────── MakeCredential
```

`Worker.Run(fn)` blocks the calling goroutine until `fn` returns on the worker thread.

**Cancel is exempt**: `TokenProvider.Cancel()` calls `dev.Cancel()` directly — not through the worker — because the worker is blocked on the in-flight operation we are trying to cancel. libfido2's cancel is thread-safe by design.

---

## Cancel Propagation

Cancel flows from three sources to the blocking provider call:

```
Application calls Close()  ──┐
                              ├──> req.cancelOp() ──> close(req.cancel)
Client disconnects (D-Bus) ──┘                              │
                                                            ▼
                                                   stopWatch goroutine
                                                            │
                                                   selectedProvider.Cancel()
```

The `stopWatch` goroutine pattern used in `runMakeCredential` / `runGetAssertion` / `runResetToken`:

```go
stopWatch := make(chan struct{})
go func() {
    select {
    case <-req.cancel:
        selectedProvider.Cancel()
    case <-stopWatch:
    }
}()
result, err := selectedProvider.MakeCredential(opts, pin)
close(stopWatch)
```

This ensures `Cancel()` is called precisely if and only if cancellation arrives during the blocking call. The goroutine exits immediately on either outcome.

---

## Client Disconnect Handling

The broker subscribes to `org.freedesktop.DBus.NameOwnerChanged`. When a client's unique bus name disappears (`newOwner == ""`):

1. The agent registry clears the entry if it was registered by that sender.
2. All pending requests whose `req.sender` matches the disconnected name are cancelled.

Sender matching uses the exact unique bus name (e.g. `:1.42`) stored in `Request.sender` at creation time. String equality, not substring match, prevents `:1.4` from matching `:1.42`.

---

## Authenticator Selection

### MakeCredential

1. Enumerate connected hardware tokens (`fido2.EnumerateDevices`)
2. Enumerate software providers from registry (`provider.Registry.Entries`)
3. Filter by `authenticator_attachment` and algorithm support (`SelectCandidates`)
4. If a UI agent is registered or multiple candidates exist, call `SelectAuthenticator`
5. If `user_verification == "required"` and provider is hardware, collect PIN via `CollectPIN`

### GetAssertion

Same flow, but step 2–3 include a `HasCredentials` call to each provider:
- Hardware tokens return all `allowList` entries (cannot check without PIN)
- Software providers return only IDs they actually hold

Only providers reporting at least one matching credential are presented as candidates.

### Priority

Software providers carry a `Priority` field (default 50, higher = preferred). Hardware tokens are assigned priority 100. `SelectCandidates` sorts descending so the best candidate is index 0 — the default selection when no UI agent is registered.

---

## UI Agent

The UI agent is a separate process implementing `org.freedesktop.PasskeyBroker.UIAgent`. It is registered by calling `RegisterUIAgent(path)` on the broker. Last-write-wins; one agent at a time.

The broker calls the agent synchronously (with a timeout) from within the operation goroutine:

| Method | When called |
|--------|-------------|
| `SelectAuthenticator` | Before performing the operation, if multiple candidates exist |
| `CollectPIN` | When hardware UV is required |
| `CollectNewPIN` | During `SetPIN` |
| `ConfirmReset` | Before `ResetToken` |
| `NotifyOperation` | Status updates (fire-and-forget) |

If no agent is registered:
- `SelectAuthenticator` auto-picks index 0
- `CollectPIN` / `CollectNewPIN` return nil (operation cancels)
- `ConfirmReset` returns false (reset cancels)

---

## Enrollment Operations

### EnumerateAuthenticators

Synchronous. Returns combined list of:
- Hardware: probed via libfido2 (`IsFIDO2`, `Info`, `RetryCount`) — includes `has_pin`, `pin_retries`, `min_pin_length`
- Software: taken directly from the provider registry — `has_pin = false`, `pin_retries = -1`

The `id` field for hardware tokens is the device path string (e.g. `/dev/hidraw0`), used as the `token_id` argument for `SetPIN` and `ResetToken`.

### SetPIN

Async. Sequence:
1. Probe device to find current `HasPIN` and `MinPINLength`
2. `CollectNewPIN` via UI agent
3. If `HasPIN`, `CollectPIN` for the old PIN
4. Check cancellation
5. `fido2.SetPIN(path, newPIN, oldPIN)`
6. Zero PIN buffers immediately after the call

### ResetToken

Async. Sequence:
1. Probe device for display name
2. `ConfirmReset` via UI agent (destructive — asks for explicit confirmation)
3. Check cancellation
4. `fido2.ResetToken(path, req.cancel)` — blocks until user touches device or cancel arrives

**CTAP2 constraint**: reset only succeeds within ~10 seconds of device power-up. The device must be physically removed and reinserted immediately before calling `ResetToken`.

---

## PIN Security

- PINs are collected as Go `string` from the UI agent, immediately converted to `[]byte`
- The `[]byte` buffer is zeroed (`clearBytes`) immediately after the libfido2 call
- A transient `string` copy is created inside `fido2.SetPIN` for the libfido2 API and persists until GC — unavoidable with the current libfido2 Go binding
- PINs are never logged, persisted, or returned over D-Bus

---

## WebAuthn Data Construction (Hardware)

`TokenProvider` constructs WebAuthn-compatible output from raw libfido2 fields:

**clientDataJSON** — built locally:
```json
{"type":"webauthn.create","challenge":"<base64url>","origin":"https://<rpid>"}
```

**attestationObject** — CBOR map:
```
{
  "fmt":      <attestation format from device>,
  "attStmt":  {"x5c": [...], "sig": <bytes>},
  "authData": <raw authenticator data from device>
}
```
libfido2 returns raw fields (`AuthData`, `Cert`, `Sig`, `Format`), not a pre-packed CBOR blob. The broker packs them using `fxamacker/cbor/v2`.

**Assertion signature** — returned verbatim from libfido2 (`AuthDataCBOR`, `Sig`).

---

## Build Variants

The `fido2` package uses Go build tags to isolate all CGO:

| Tag | Effect |
|-----|--------|
| `cgo` (default with CGO_ENABLED=1) | Full libfido2 support |
| `!cgo` (CGO_ENABLED=0) | Stubs returning `NotSupportedError`; software providers still work |

The `!cgo` build produces a portable binary with no C dependencies, suitable for environments without USB FIDO2 hardware or where libfido2 is not available.

---

## Concurrency Model

| Goroutine | Lifetime | Purpose |
|-----------|----------|---------|
| Main | Process | Signal handling (SIGHUP, SIGTERM) |
| `watchNameOwnerChanged` | Process | Disconnect detection |
| `run{MakeCredential,GetAssertion,SetPIN,ResetToken}` | Per-request | Operation execution |
| `stopWatch` | Scoped to blocking op | Cancel propagation to provider |
| libfido2 worker | Process | Serialises all C library calls |
| `notifyOperation` goroutine | Fire-and-forget | Status signals to UI agent |

The broker's `requests` map is protected by `sync.Mutex`. The agent registry uses `sync.RWMutex`. The libfido2 worker owns its OS thread. There are no shared mutable data structures between operation goroutines.
