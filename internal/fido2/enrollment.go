//go:build cgo

package fido2

import (
	"fmt"

	libfido2 "github.com/keys-pub/go-libfido2"

	"github.com/cmouse/dbus-passkey/internal/types"
)

// EnumerateTokenInfos returns info about all connected FIDO2/U2F devices.
func EnumerateTokenInfos() ([]*types.AuthenticatorInfo, error) {
	var locs []*libfido2.DeviceLocation
	var err error
	globalWorker.Run(func() {
		locs, err = libfido2.DeviceLocations()
	})
	if err != nil {
		return nil, err
	}

	infos := make([]*types.AuthenticatorInfo, 0, len(locs))
	for _, loc := range locs {
		info := probeDevice(loc.Path)
		infos = append(infos, info)
	}
	return infos, nil
}

func probeDevice(path string) *types.AuthenticatorInfo {
	info := &types.AuthenticatorInfo{
		ID:         path,
		Name:       "FIDO2 Token (" + path + ")",
		Type:       "hardware",
		Transports: []string{"usb"},
		PINRetries: -1,
	}

	var dev *libfido2.Device
	var err error
	globalWorker.Run(func() {
		dev, err = libfido2.NewDevice(path)
	})
	if err != nil {
		return info
	}

	var isFIDO2 bool
	globalWorker.Run(func() {
		isFIDO2, err = dev.IsFIDO2()
	})
	info.IsFIDO2 = isFIDO2 && err == nil

	if info.IsFIDO2 {
		var devInfo *libfido2.DeviceInfo
		globalWorker.Run(func() {
			devInfo, err = dev.Info()
		})
		if err == nil {
			fillInfoFromDeviceInfo(info, devInfo)
		}

		var retries int
		globalWorker.Run(func() {
			retries, err = dev.RetryCount()
		})
		if err == nil {
			info.PINRetries = retries
		}
	}

	return info
}

func fillInfoFromDeviceInfo(info *types.AuthenticatorInfo, di *libfido2.DeviceInfo) {
	for _, opt := range di.Options {
		switch opt.Name {
		case "clientPin":
			info.HasPIN = opt.Value == libfido2.True
		case "minPINLength":
			// minPINLength appears as an extension, not option — handled separately
		}
	}
	for _, ext := range di.Extensions {
		if ext == "minPinLength" {
			info.MinPINLength = 4 // conservative default when extension present
		}
	}
	if info.MinPINLength == 0 {
		info.MinPINLength = 4 // CTAP2 minimum
	}
}

// SetPIN sets or changes the PIN on the device at path.
// oldPIN must be nil/empty if no PIN is currently set.
// Validates PIN length before calling libfido2.
func SetPIN(path string, newPIN, oldPIN []byte) error {
	if len(newPIN) < 4 {
		return fmt.Errorf("PIN must be at least 4 characters")
	}
	if len(newPIN) > 63 {
		return fmt.Errorf("PIN must not exceed 63 bytes")
	}

	newPINStr := string(newPIN)
	oldPINStr := string(oldPIN)

	var dev *libfido2.Device
	var err error
	globalWorker.Run(func() {
		dev, err = libfido2.NewDevice(path)
	})
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}

	globalWorker.Run(func() {
		err = dev.SetPIN(newPINStr, oldPINStr)
	})
	return err
}

// ResetToken performs a CTAP2 authenticatorReset.
// This is time-windowed (~10s after power-up) and requires user presence (touch).
// cancelCh allows cancellation while waiting for user touch.
func ResetToken(path string, cancelCh <-chan struct{}) error {
	var dev *libfido2.Device
	var err error
	globalWorker.Run(func() {
		dev, err = libfido2.NewDevice(path)
	})
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		globalWorker.Run(func() {
			done <- dev.Reset()
		})
	}()

	select {
	case err = <-done:
		return err
	case <-cancelCh:
		_ = dev.Cancel()
		<-done
		return fmt.Errorf("cancelled")
	}
}
