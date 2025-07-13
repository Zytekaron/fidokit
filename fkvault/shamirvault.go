package fkvault

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/zytekaron/shamir-go"
	"golang.org/x/crypto/chacha20poly1305"

	"fidokit/crypto"
	"fidokit/fidoutils"
	"fidokit/utils"
)

type ShamirVault struct {
	*BaseVault `json:",inline"`

	// K is the number of shares required to decrypt the vault.
	K byte `json:"k"`
	// N is the total number of shares generated for keys.
	N byte `json:"n"`
	// Shares is a list of shamir-based vault shares, N of which must be combined to decrypt the vault.
	Shares map[byte]*VaultHeader `json:"shares"`
}

// NewShamir creates a new ShamirVault.
//
// For a '1 of n' unlock system, consider using BaseVault for simplicity.
//
//	2 <= k <= 255
//	k <= n <= 255
func NewShamir(name, description string, k, n byte) *ShamirVault {
	if k < 0 || n < 0 || n < k {
		panic("invalid k and/or n")
	}

	now := time.Now().UTC()
	return &ShamirVault{
		BaseVault: newBase(TypeShamir, now, name, description),
		K:         k,
		N:         n,
		Shares:    map[byte]*VaultHeader{},
	}
}

func (v *ShamirVault) InteractiveInitialize() error {
	if Debug {
		fmt.Println("[DEBUG] InteractiveInitialize")
	}

	// fixme prompt inputPath for this key
	masterKeyHex := utils.ReadNonEmptyLine("Enter a master key (hex), or leave blank to randomly generate one: ")
	var masterKey []byte
	if len(masterKeyHex) > 0 {
		var err error
		masterKey, err = hex.DecodeString(masterKeyHex)
		if err != nil {
			return fmt.Errorf("decode master key: %w", err)
		}
	} else {
		masterKey = utils.MustGenerateKey()
		fmt.Println("Master Key:", hex.EncodeToString(masterKey))
	}

	shares, err := shamir.SplitTagged(masterKey, v.K, v.N)
	if err != nil {
		return fmt.Errorf("split: %w", err)
	}

	fmt.Println()
	fmt.Println("You will now be walked through the process of adding keys to your vault.")
	fmt.Println("You will be asked to plug in each key you wish to add.")
	fmt.Println("You may plug in multiple keys at once; you will be prompted to select one.")
	fmt.Println()
	fmt.Println("Note that all keys must be present while creating a Shamir vault.")
	fmt.Println("See README.md for more information on this technical requirement.")
	fmt.Println()

	for i, share := range shares {
		// in the normal case, or when assumptions are permitted but cannot
		// be made, wait for user input before attempting an assertion.
		if !MakeAssumptions || fidoutils.GetConnectedDeviceCount() < int(v.N) {
			utils.ReadLine("Insert in the next key you want to use, then press ENTER.")
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

		aead, err := chacha20poly1305.New(assertion.HMACSecret)
		if err != nil {
			return fmt.Errorf("create aead: %w", err)
		}
		encryptedKey, err := crypto.EncryptChaCha20(aead, share)
		if err != nil {
			return fmt.Errorf("encrypt vault master key: %w", err)
		}

		name := utils.ReadLine("Enter a name for this key: ")

		v.Shares[i] = &VaultHeader{
			Name:         name,
			CredentialID: assertion.CredentialID,
			EncryptedKey: encryptedKey,
		}
	}

	v.Metadata.Modified = time.Now().UTC()
	return nil
}

func (v *ShamirVault) InteractiveCombine() ([]byte, error) {
	if Debug {
		fmt.Println("[DEBUG] InteractiveCombine")
	}

	fmt.Println("You will now be walked through the process of combining shares.")
	fmt.Println("You will be asked to plug in and authenticate using enrolled keys.")
	fmt.Println("You may plug in multiple keys at once; you will be prompted to select one.")
	fmt.Println()
	fmt.Println("You must have at least", v.K, "keys out of the", v.N, "enrolled keys to unlock the vault.")
	fmt.Println()

	credIDs := v.GetCredIDs()

	decryptMap := map[byte][]byte{}
	for len(decryptMap) < int(v.K) {
		if !MakeAssumptions || fidoutils.GetConnectedDeviceCount() < int(v.K) {
			utils.ReadLine("Insert in the next key you want to use, then press ENTER.")
		}

		assertion, err := fidoutils.InteractiveAssertion(credIDs)
		if err != nil {
			return nil, fmt.Errorf("assertion: %w", err)
		}
		if Debug {
			fmt.Printf("[DEBUG] derived key: %x\n", assertion.HMACSecret)
		}
		credID := assertion.CredentialID
		index, header, err := v.GetHeaderByCredID(credID)
		if err != nil {
			return nil, fmt.Errorf("get header by credID: %w", err)
		}

		if _, ok := decryptMap[index]; ok {
			fmt.Println("You already used this key. Select another key to unlock the vault.")
			continue
		}

		aead, err := chacha20poly1305.New(assertion.HMACSecret)
		if err != nil {
			return nil, fmt.Errorf("create aead: %w", err)
		}
		decryptedKey, err := crypto.DecryptChaCha20(aead, header.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt vault master key: %w", err)
		}

		decryptMap[index] = decryptedKey
	}

	return shamir.CombineTagged(decryptMap)
}

// DeleteAllHeaders resets the list of headers.
func (v *ShamirVault) DeleteAllHeaders() {
	v.Shares = map[byte]*VaultHeader{}
	v.Metadata.Modified = time.Now().UTC()
}

func (v *ShamirVault) MarshalJSON() ([]byte, error) {
	type Alias ShamirVault // avoid recursion
	return json.Marshal(struct {
		Alias
		Type string `json:"type"`
	}{
		Alias: Alias(*v),
		Type:  "shamir",
	})
}

func (v *ShamirVault) GetHeaderByCredID(credID []byte) (byte, *VaultHeader, error) {
	for key, header := range v.Shares {
		if slices.Equal(header.CredentialID, credID) {
			return key, header, nil
		}
	}
	return 0, nil, ErrNoHeader
}

func (v *ShamirVault) GetCredIDs() [][]byte {
	credIDs := make([][]byte, len(v.Shares))
	for i, h := range v.Shares {
		credIDs[i-1] = h.CredentialID
	}
	return credIDs
}
