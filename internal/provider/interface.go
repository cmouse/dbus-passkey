package provider

import "github.com/cmouse/dbus-passkey/internal/types"

// Provider is the interface all authenticator backends implement.
type Provider interface {
	ID() string
	Name() string
	Type() string // "hardware" or "software"
	Transports() []string
	SupportedAlgorithms() []int32

	// HasCredentials returns matching credential IDs. If allowList empty,
	// returns a single nil entry if any resident cred exists, else empty.
	HasCredentials(rpID string, allowList [][]byte) ([][]byte, error)

	MakeCredential(opts *types.MakeCredentialOptions, pin []byte) (*types.MakeCredentialResult, error)
	GetAssertion(opts *types.GetAssertionOptions, pin []byte) (*types.GetAssertionResult, error)

	// Cancel interrupts an in-progress operation. Must be safe to call from any goroutine.
	Cancel()

	// RequiresPIN reports whether the broker must collect a PIN before calling
	// MakeCredential or GetAssertion on this provider.
	RequiresPIN() bool
}

// RegistryEntry is metadata loaded from a provider .conf file.
type RegistryEntry struct {
	Name                string
	ID                  string
	DBusName            string
	ObjectPath          string
	Transports          []string
	SupportedAlgorithms []int32
	Priority            int
	RequiresPIN         bool
}
