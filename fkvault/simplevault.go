package fkvault

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/keys-pub/go-libfido2"
	"golang.org/x/crypto/chacha20poly1305"

	"fidokit/crypto"
	"fidokit/fidoutils"
	"fidokit/utils"
)

type SimpleVault struct {
	*BaseVault `json:",inline"`

	// Headers is a list of vault headers, any of which can be used to decrypt the vault.
	Headers map[string]*VaultHeader `json:"headers"`
}

// NewSimple creates a new SimpleVault.
func NewSimple(name, description string) *SimpleVault {
	now := time.Now().UTC()
	return &SimpleVault{
		BaseVault: newBase(TypeSimple, now, name, description),
		Headers:   map[string]*VaultHeader{},
	}
}

// InteractiveCreateHeader creates a new header encrypting the master key.
// If there are no existing headers, it generates a new key and adds it.
// If there are existing headers, it prompts the user to unlock one of
// them to recover the vault master key, then re-encrypts it using the
// key the user wants to add and then adds it to the vault.
func (v *SimpleVault) InteractiveCreateHeader(credentialID, derivedKey []byte, name string) error {
	if Debug {
		fmt.Println("[DEBUG] InteractiveVaultCreateHeader")
	}

	if len(v.Headers) == 0 {
		// fixme prompt inputPath for this key
		var masterKey []byte
		masterKeyHex := utils.ReadNonEmptyLine("Enter a master key (hex), or leave blank to randomly generate one: ")
		if len(masterKeyHex) > 0 {
			var err error
			masterKey, err = hex.DecodeString(masterKeyHex)
			if err != nil {
				log.Fatalln("decode master key:", err)
			}
		} else {
			masterKey = utils.MustGenerateKey()
			fmt.Println("Master Key:", hex.EncodeToString(masterKey))
		}

		aead, err := chacha20poly1305.New(derivedKey)
		if err != nil {
			return fmt.Errorf("create aead: %w", err)
		}
		encryptedKey, err := crypto.EncryptChaCha20(aead, masterKey)
		if err != nil {
			return fmt.Errorf("encrypt vault master key: %w", err)
		}

		v.Headers[name] = &VaultHeader{
			Name:         name,
			CredentialID: credentialID,
			EncryptedKey: encryptedKey,
		}
		v.Metadata.Modified = time.Now().UTC()
		return nil
	}

	// use another key to unlock the master key.

	fmt.Println("Please unlock one of the existing headers to recover the vault master key.")
	fmt.Println("Existing keys:", v.HeaderCSVString())

	// in the normal case, or when assumptions are permitted but cannot
	// be made, wait for user input before attempting an assertion.
	if !MakeAssumptions || fidoutils.GetConnectedDeviceCount() == 0 {
		utils.ReadLine("Press ENTER to continue once you have plugged in an existing key.")
	}

	assertion, err := fidoutils.InteractiveAssertion(v.GetCredIDs())
	if err != nil {
		return fmt.Errorf("assertion: %w", err)
	}

	if Debug {
		fmt.Printf("[DEBUG] derived key from existing header: %x\n", assertion.HMACSecret)
	}

	originalKeyHeader, err := v.GetHeaderByCredID(assertion.CredentialID)
	if err != nil {
		return fmt.Errorf("get header by credID: %w", err)
	}
	originalEncryptedKey := originalKeyHeader.EncryptedKey

	// decrypt the vault master key
	aead, err := chacha20poly1305.New(assertion.HMACSecret)
	if err != nil {
		return fmt.Errorf("create aead: %w", err)
	}
	decryptedKey, err := crypto.DecryptChaCha20(aead, originalEncryptedKey)
	if err != nil {
		return fmt.Errorf("decrypt vault master key: %w", err)
	}

	// encrypt the vault master key with the new key
	aead, err = chacha20poly1305.New(derivedKey)
	if err != nil {
		return fmt.Errorf("create aead: %w", err)
	}
	encryptedKey, err := crypto.EncryptChaCha20(aead, decryptedKey)
	if err != nil {
		return fmt.Errorf("encrypt vault master key: %w", err)
	}
	// add new header
	v.Headers[name] = &VaultHeader{
		Name:         name,
		CredentialID: credentialID,
		EncryptedKey: encryptedKey,
	}
	v.Metadata.Modified = time.Now().UTC()
	return nil
}

func (v *SimpleVault) InteractiveAdd() error {
	fmt.Println("Insert the FIDO2 key you want to add.")
	if !MakeAssumptions || fidoutils.GetConnectedDeviceCount() == 0 {
		utils.ReadLine("Press ENTER when you have inserted the key.")
	}

	dev, err := fidoutils.InteractiveGetDevice()
	if err != nil {
		return fmt.Errorf("get device: %w", err)
	}

	pin, err := fidoutils.InteractiveGetPIN(dev)
	if err != nil {
		return fmt.Errorf("get pin: %w", err)
	}

	cred, err := fidoutils.InteractiveMakeCredentialFor(dev, pin)
	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}
	if Debug {
		fmt.Printf("[DEBUG] credID: %x\n", cred.CredentialID)
	}

	assertion, err := fidoutils.InteractiveAssertionFor(dev, pin, [][]byte{cred.CredentialID})
	if err != nil {
		return fmt.Errorf("assertion: %w", err)
	}

	if Debug {
		fmt.Printf("[DEBUG] derived key: %x\n", assertion.HMACSecret)
	}

	name := utils.ReadNonEmptyLine("Enter a name for this key: ")
	err = v.InteractiveCreateHeader(cred.CredentialID, assertion.HMACSecret, name)
	if err != nil {
		return fmt.Errorf("create header: %w", err)
	}

	return nil
}

func (v *SimpleVault) InteractiveDelete() error {
	name := ""
	for name == "" {
		name = utils.ReadLine("Enter key name to delete: ")
	}

	err := v.DeleteHeader(name)
	if err != nil {
		if errors.Is(err, ErrNoHeader) {
			fmt.Println("Header not found!")
		}
		log.Fatalln("delete header:", err)
	}

	fmt.Println("Header deleted!")
	return nil
}

func (v *SimpleVault) InteractiveUnlock() ([]byte, error) {
	if len(v.Headers) == 0 {
		return nil, ErrNotInitialized
	}

	credentialIDs := v.GetCredIDs()

	var err error
	var assertion *libfido2.Assertion
	// fixme I don't like this loop
	for assertion == nil {
		if !MakeAssumptions || fidoutils.GetConnectedDeviceCount() == 0 {
			utils.ReadLine("Insert an enrolled FIDO2 key, then press ENTER.")
		}

		assertion, err = fidoutils.InteractiveAssertion(credentialIDs)
		if errors.Is(err, libfido2.ErrNoCredentials) {
			fmt.Println("No credentials found: this key is not enrolled in the vault. Try another.")
			continue
		} else if err != nil {
			return nil, fmt.Errorf("assertion: %w", err)
		}
	}

	if Debug {
		fmt.Printf("[DEBUG] derived key: %x\n", assertion.HMACSecret)
	}

	// find the header for the assertion credential id
	header, err := v.GetHeaderByCredID(assertion.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("get header by cred ID: %w", err)
	}
	encryptedKey := header.EncryptedKey

	// decrypt the master key using the key derived from the FIDO2 assertion's HMAC secret
	aead, _ := chacha20poly1305.New(assertion.HMACSecret)
	masterKey, err := crypto.DecryptChaCha20(aead, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return masterKey, nil
}

func (v *SimpleVault) DeleteHeader(name string) error {
	if _, ok := v.Headers[name]; !ok {
		return ErrNoHeader
	}

	delete(v.Headers, name)
	v.Metadata.Modified = time.Now().UTC()
	return nil
}

// DeleteAllHeaders resets the list of headers.
func (v *SimpleVault) DeleteAllHeaders() {
	v.Headers = nil
	v.Metadata.Modified = time.Now().UTC()
}

func (v *SimpleVault) HeaderCSVString() string {
	var buf strings.Builder
	for _, h := range v.Headers {
		buf.WriteString(h.Name)
		buf.WriteString(", ")
	}
	str := buf.String()
	return str[:len(str)-2] // remove trailing ", "
}

func (v *SimpleVault) GetHeaderByCredID(credID []byte) (*VaultHeader, error) {
	for _, header := range v.Headers {
		if slices.Equal(header.CredentialID, credID) {
			return header, nil
		}
	}
	return nil, ErrNoHeader
}

func (v *SimpleVault) GetCredIDs() [][]byte {
	credIDs := make([][]byte, len(v.Headers))
	i := 0
	for _, h := range v.Headers {
		credIDs[i] = h.CredentialID
		i++
	}
	return credIDs
}
