//go:build !cgo

package fido2

import (
	"fmt"

	"github.com/cmouse/dbus-passkey/internal/types"
)

func EnumerateTokenInfos() ([]*types.AuthenticatorInfo, error) {
	return nil, nil
}

func SetPIN(path string, newPIN, oldPIN []byte) error {
	return fmt.Errorf("NotSupportedError: fido2 support not compiled")
}

func ResetToken(path string, cancelCh <-chan struct{}) error {
	return fmt.Errorf("NotSupportedError: fido2 support not compiled")
}
