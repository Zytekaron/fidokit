package fkvault

import (
	"encoding/json"
	"fmt"
	"time"

	"fidokit/fidoutils"
	"fidokit/utils"
)

type Type string

const (
	TypeSimple Type = "simple"
	TypeShamir Type = "shamir"
)

var Types = []Type{TypeSimple, TypeShamir}

var ErrInvalidVersion = fmt.Errorf("invalid vault version")

// BaseVault is a vault protected by a set of FIDO2 keys, *any* of which can be used
// individually to unlock the entire vault. The master key to the vault is stored
// as a component of each header, not in any form within the vault structure itself.
type BaseVault struct {
	// Version is used internally and should not be manually modified.
	Version int `json:"version"`
	// Type is the vault type.
	Type Type `json:"type"`
	// ID is automatically generated and is used internally but can be referred to externally.
	ID string `json:"id"`
	// Name is a descriptive name in any format to identify the vault.
	Name string `json:"name"`
	// Description is additional text in any format to provide information about the vault.
	Description string `json:"description,omitempty"`

	// ClientDataHashText is the hash passed into each operation.
	ClientDataHashText string `json:"client_data_hash"`
	// AssertionSaltText is the value hashed using SHA256 and passed into the assertion to generate a reproducible result.
	AssertionSaltText string `json:"salt"`

	// RPID is the relying party ID.
	RPID string `json:"rp_id"`

	// Metadata contains meta-information about the vault.
	Metadata Metadata `json:"metadata"`
}

// VaultHeader holds parameters used with FIDO2 devices to facilitate
// deterministic derivation of secrets using hardware security keys.
//
// Usage:
//  1. Use the FIDO2 hardware security key associated with this header
//     along with the Salt and other data to regenerate the derived key.
//  2. Use the derived key with XChaCha20+Poly1305 to decrypt the key.
//  3. Use the key (for a regular vault) or the share (for a Shamir vault)
//     to decrypt the vault itself. For Shamir vaults, K of N is required.
type VaultHeader struct {
	// Name is the user-provided name for the entry, used to identify it later.
	Name string `json:"name"`
	// CredentialID is the cryptographic identifier for a credential associated with a specific security key.
	CredentialID []byte `json:"credential_id"`
	// EncryptedKey contains either the master key of the parent vault in the case of typical vaults or the
	// Shamir share portion for Shamir-based vaults. It is encrypted using the key derived from the assertion.
	EncryptedKey []byte `json:"encrypted_key"`
}

func newBase(typ Type, created time.Time, name, description string) *BaseVault {
	return &BaseVault{
		Version:            CurrentVaultVersion,
		ID:                 utils.RandomID(),
		Type:               typ,
		Name:               name,
		Description:        description,
		ClientDataHashText: fidoutils.ClientDataHashText,
		AssertionSaltText:  fidoutils.AssertionSaltText,
		RPID:               fidoutils.RelyingParty.ID,
		Metadata: Metadata{
			Created:  created,
			Modified: created,
		},
	}
}

// ParseJSON takes in a Vault in JSON format, then parses it into
// a SimpleVault or ShamirVault, depending on the type field.
// The vault's version is also considered during parsing.
func ParseJSON(data []byte) (any, error) {
	var container struct {
		Type    Type `json:"type"`
		Version int  `json:"version"`
	}
	err := json.Unmarshal(data, &container)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault type: %w", err)
	}

	if container.Version < 0 || container.Version > 1 {
		return nil, ErrInvalidVersion
	}

	var vault any
	switch container.Type {
	case TypeSimple:
		vault = &SimpleVault{}
	case TypeShamir:
		vault = &ShamirVault{}
	default:
		return nil, fmt.Errorf("unknown vault type: %s", container.Type)
	}

	err = json.Unmarshal(data, &vault)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault: %w", err)
	}
	return vault, nil
}
