package fidoutils

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/keys-pub/go-libfido2"

	"fidokit/utils"
)

var Debug bool

// DisableBiometrics should be set later via a cli flag to allow
// the user to use PIN fallback on their biometric keys; otherwise
// the user will never be prompted for a PIN, as it is assumed that
// they will be able to authenticate biometrically. In the specific
// case of the biometric scanner failing, or if the user no longer
// has any fingers to authenticate with, this would cause problems.
var DisableBiometrics = false

// ErrNoDevice indicates that no compatible device is available to the program.
var ErrNoDevice = errors.New("no device")

const ClientDataHashText = "create-credential"
const AssertionSaltText = "vault-master-key"

var ClientDataHash = sha256.Sum256([]byte(ClientDataHashText))
var AssertionSalt = sha256.Sum256([]byte(AssertionSaltText))

// User is required for setup. Not stored on the security key.
var User = libfido2.User{
	ID:   []byte("n/a"),
	Name: "n/a",
	// DisplayName, Icon
}

var RelyingParty = libfido2.RelyingParty{
	ID:   "crypto.zyte.dev",
	Name: "crypto",
}

// MakeCredentialOpts contains options used to create non-resident credentials
// for a key using the FIDO2 hmac-secret key extension, also requiring UV.
var MakeCredentialOpts = &libfido2.MakeCredentialOpts{
	Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
	RK:         libfido2.False, // non-resident key
	UV:         libfido2.True,  // user verification required
}

var AssertionOpts = &libfido2.AssertionOpts{
	Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
	HMACSalt:   AssertionSalt[:], // salt for deterministic derivation
	UV:         libfido2.True,    // user verification required
}

// InteractiveGetPIN requests for the PIN of the security key, or
// returns an empty string if it supports on-device biometric UV.
func InteractiveGetPIN(dev *libfido2.Device) (string, error) {
	if Debug {
		fmt.Println("[DEBUG] InteractiveGetPIN")
	}

	info, err := dev.Info()
	if err != nil {
		return "", fmt.Errorf("GetHeaderByCredID device info: %w", err)
	}

	getOptionValue := func(opts []libfido2.Option, name string) bool {
		for _, opt := range opts {
			if opt.Name == name && opt.Value == "true" {
				return true
			}
		}
		return false
	}

	hasPIN := getOptionValue(info.Options, "clientPin")
	hasBio := getOptionValue(info.Options, "bioEnroll")
	if Debug {
		fmt.Printf("[DEBUG] clientPin=%d bioEnroll=%d\n", btoi(hasPIN), btoi(hasBio))
	}

	// biometric auth is not permitted by the user, but
	// this key only supports biometric authentication.
	// this is a rare, or potentially impossible case.
	if hasBio && !hasPIN && DisableBiometrics {
		return "", fmt.Errorf("this key does not support PIN fallback, but biometric authentication is disabled")
	}

	// security key supports biometric authentication,
	// user should do this instead of providing a PIN.
	if hasBio && !DisableBiometrics {
		return "", nil
	}

	pin := utils.ReadNonEmptyLine("Enter PIN: ")
	return pin, nil
}

func InteractiveMakeCredential() (*libfido2.Attestation, error) {
	if Debug {
		fmt.Println("[DEBUG] InteractiveMakeCredential")
	}

	dev, err := InteractiveGetDevice()
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	pin, err := InteractiveGetPIN(dev)
	if err != nil {
		return nil, fmt.Errorf("GetHeaderByCredID pin: %w", err)
	}

	return InteractiveMakeCredentialFor(dev, pin)
}

func InteractiveMakeCredentialFor(dev *libfido2.Device, pin string) (*libfido2.Attestation, error) {
	if Debug {
		fmt.Printf("[DEBUG] InteractiveMakeCredentialFor(%v, %s)\n", dev, pin)
	}

	fmt.Println("Tap your security key.")
	cred, err := dev.MakeCredential(ClientDataHash[:], RelyingParty, User, libfido2.ES256, pin, MakeCredentialOpts)
	if err != nil {
		return nil, fmt.Errorf("make credential: %w", err)
	}

	return cred, nil
}

func InteractiveAssertion(credIDs [][]byte) (*libfido2.Assertion, error) {
	if Debug {
		fmt.Printf("[DEBUG] InteractiveAssertion(%v)\n", credIDs)
	}

	dev, err := InteractiveGetDevice()
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}

	pin, err := InteractiveGetPIN(dev)
	if err != nil {
		return nil, fmt.Errorf("pin: %w", err)
	}

	return InteractiveAssertionFor(dev, pin, credIDs)
}

func InteractiveAssertionFor(dev *libfido2.Device, pin string, credIDs [][]byte) (*libfido2.Assertion, error) {
	if Debug {
		fmt.Printf("[DEBUG] InteractiveAssertionFor(%v, %s, %v)\n", dev, pin, credIDs)
	}

	fmt.Println("Tap your security key.")
	assert, err := dev.Assertion(RelyingParty.ID, ClientDataHash[:], credIDs, pin, AssertionOpts)
	if err != nil {
		return nil, fmt.Errorf("assertion: %w", err)
	}

	return assert, nil
}

// InteractiveGetDevice chooses the FIDO2 device to use.
//
// Connected devices:
//
//	0  -> returns ErrNoDevice
//	1  -> returns devices[0]
//	2+ -> prompts the user to tap the device they want to use (timeout 30s)
func InteractiveGetDevice() (*libfido2.Device, error) {
	devs, err := fido2GetDevices()
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, ErrNoDevice
	}
	if len(devs) == 1 {
		return devs[0], nil
	}
	fmt.Println("Multiple keys found: tap the key you want to use.")
	return libfido2.SelectDevice(devs, 30*time.Second)
}
