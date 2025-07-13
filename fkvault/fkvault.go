package fkvault

import (
	"encoding/json"
	"errors"
	"time"
)

const CurrentVaultVersion = 0

var Debug bool

// MakeAssumptions will forego prompting the user to press ENTER after
// inserting a key for the next step, if and only if there are multiple
// keys connected (SimpleVault unlock/create = 1; SimpleVault add = 2+;
// ShamirVault create = N+; ShamirVault unlock = K+).
// The assumption being made here is that the user is plugging in ALL the
// keys they wish to use at the same time, OR the user knows the flow of
// the program in detail - else prompts may begin before keys are ready.
var MakeAssumptions bool

// ErrNoHeader is returned when a header cannot be found.
var ErrNoHeader = errors.New("no header")

// ErrNotInitialized is returned when a vault has not yet
// been initialized, but an attempt is made to unlock it.
var ErrNotInitialized = errors.New("vault is not initialized")

type Metadata struct {
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
}

func GetVaultInfo(data []byte) (typ string, version int, err error) {
	var t struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
	}
	return t.Type, t.Version, json.Unmarshal(data, &t)
}
