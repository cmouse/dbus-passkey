//go:build !cgo

package fido2

import (
	"fmt"

	"github.com/cmouse/dbus-passkey/internal/types"
)

// EnumerateDevices returns empty when CGO disabled.
func EnumerateDevices() ([]*TokenProvider, error) {
	return nil, nil
}

// TokenProvider stub satisfies the interface but always errors.
type TokenProvider struct {
	id   string
	path string
}

func (t *TokenProvider) ID() string                    { return t.id }
func (t *TokenProvider) Name() string                  { return "FIDO2 Token (disabled)" }
func (t *TokenProvider) Type() string                  { return "hardware" }
func (t *TokenProvider) Transports() []string          { return []string{"usb"} }
func (t *TokenProvider) RequiresPIN() bool             { return false }
func (t *TokenProvider) SupportedAlgorithms() []int32 { return []int32{-7} }

func (t *TokenProvider) HasCredentials(_ string, _ [][]byte) ([][]byte, error) {
	return nil, fmt.Errorf("NotSupportedError: fido2 support not compiled")
}

func (t *TokenProvider) MakeCredential(_ *types.MakeCredentialOptions, _ []byte) (*types.MakeCredentialResult, error) {
	return nil, fmt.Errorf("NotSupportedError: fido2 support not compiled")
}

func (t *TokenProvider) GetAssertion(_ *types.GetAssertionOptions, _ []byte) (*types.GetAssertionResult, error) {
	return nil, fmt.Errorf("NotSupportedError: fido2 support not compiled")
}

func (t *TokenProvider) Cancel() {}
