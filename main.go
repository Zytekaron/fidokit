package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"slices"
	"strconv"

	"fidokit/fidoutils"
	"github.com/spf13/pflag"

	"fidokit/fkvault"
	"fidokit/utils"
)

const debug = false

var vaultPath, inputPath, outputPath string
var debugMode, disableBiometrics, noAssumptions, skipChecks bool

func init() {
	pflag.StringVarP(&vaultPath, "vault", "v", "vault.json", "The relative path to your vault, default simple.json")
	pflag.StringVarP(&inputPath, "input", "i", "stdin", "The file path to read the input from during initialization, default 'stdin'")
	pflag.StringVarP(&outputPath, "output", "o", "stdout", "The file path to write the output to during unlocking, default 'stdout'")
	pflag.BoolVarP(&debugMode, "debug", "D", false, "Enable debug mode")
	pflag.BoolVar(&disableBiometrics, "disable-biometrics", false, "Disable biometric authentication; always use PIN")
	pflag.BoolVar(&noAssumptions, "no-assumptions", false, "Disable assumptions; always prompt the user to press ENTER before attempting to select a key. Useful if you need more time or are in a special situation regarding what keys are plugged in.")
	pflag.BoolVar(&skipChecks, "skip-checks", false, "Skip vault integrity verification (for recovery attempts)")
	pflag.Parse()

	// global variables work, passing config is annoying :)
	fidoutils.Debug = debugMode
	fkvault.Debug = debugMode
	utils.Debug = debugMode
	fkvault.MakeAssumptions = !noAssumptions
	fidoutils.DisableBiometrics = disableBiometrics

	// check for the plugdev group on linux and warn if the running user doesn't have it.
	if runtime.GOOS == "linux" {
		plugdevOk, err := utils.CheckPlugdev()
		if err != nil {
			log.Fatalln("checking plugdev group:", err)
		}
		if !plugdevOk {
			fmt.Println("Detected Linux, and current user is not in `plugdev` group.")
			fmt.Println("Security keys may not work unless this script runs as root,")
			fmt.Println("or if the effective user is a member of the `plugdev` group.")
			fmt.Println("If this message is unexpected, you may need to add a udev rule.")
			fmt.Println("Read more: https://developers.yubico.com/libfido2")
		}
	}
}

func main() {
	if len(vaultPath) == 0 {
		vaultPath = utils.ReadNonEmptyLine("Enter vault file path: ")
	}

	_, err := os.Open(vaultPath)
	if os.IsNotExist(err) {
		fmt.Println("Vault file does not exist. Creating new vault.")
		for {
			typ := utils.ReadLine("Enter vault type (simple, shamir): ")
			switch typ {
			case "simple":
				vault := doCreateSimpleVault()
				interactiveSimpleVault(vault)
				return
			case "shamir":
				vault := doCreateShamirVault()
				interactiveShamirVault(vault)
				return
			}
		}
	} else if err != nil {
		log.Fatalln("open vault:", err)
	}

	anyVault := mustLoadVault(vaultPath)
	verifyVault(anyVault)

	switch vault := anyVault.(type) {
	case *fkvault.SimpleVault:
		interactiveSimpleVault(vault)
	case *fkvault.ShamirVault:
		interactiveShamirVault(vault)
	}
}

func doCreateSimpleVault() *fkvault.SimpleVault {
	//vaultPath = utils.ReadLine("Enter vault file path: ")
	name := utils.ReadLine("Enter vault name: ")
	desc := utils.ReadLine("Enter vault description: ")

	return fkvault.NewSimple(name, desc)
}

func doCreateShamirVault() *fkvault.ShamirVault {
	//vaultPath = utils.ReadLine("Enter vault file path: ")
	name := utils.ReadLine("Enter vault name: ")
	desc := utils.ReadLine("Enter vault description: ")

	nv := utils.ReadNonEmptyLine("Enter value for n (total shares): ")
	n, err := strconv.Atoi(nv)
	if err != nil {
		log.Fatalln("parse n:", err)
	}

	kv := utils.ReadNonEmptyLine("Enter value for k (min required): ")
	k, err := strconv.Atoi(kv)
	if err != nil {
		log.Fatalln("parse k:", err)
	}

	return fkvault.NewShamir(name, desc, byte(k), byte(n))
}

func verifyVault(anyVault any) {
	if skipChecks {
		return
	}

	var err error
	switch vault := anyVault.(type) {
	case *fkvault.SimpleVault:
		err = verifySimpleVault(vault)
	case *fkvault.ShamirVault:
		err = verifyShamirVault(vault)
	}
	if err == nil {
		return
	}

	fmt.Println("The vault file appears to be corrupted.")
	fmt.Println()
	fmt.Println("This usually happens if the vault file was modified manually.")
	fmt.Println("If you are sure that the vault was not modified manually, then")
	fmt.Println("there may be a bug somewhere in this program or in the integrity")
	fmt.Println("verification process which needs to be resolved.")
	fmt.Println()
	fmt.Println("You should first back up the current version of the vault file,")
	fmt.Println("then try running the program using --skip-verify. This may work if")
	fmt.Println("the vault corruption is not severe, for example if some keys in a")
	fmt.Println("Shamir vault are erroneously deleted, but K or more are still there.")
	fmt.Println()
	fmt.Println("If some fields are missing or empty, you may be able to manually")
	fmt.Println("set them to recover the vault. You should create a backup of the")
	fmt.Println("current state of the vault file before attempting this.")
	fmt.Println()
	fmt.Println("Here are some examples of required fields which might be missing:")
	fmt.Println("\t\"version\": 0,")
	fmt.Println("\t\"client_data_hash\": \"create-credential\",")
	fmt.Println("\t\"salt\": \"vault-master-key\",")
	fmt.Println("\t\"rp_id\": \"crypto.zyte.dev\",")
	fmt.Println()
	fmt.Println("If you are sure that the vault was not modified manually, and.")
	fmt.Println("this vault encrypts a master key which you need to recover,")
	fmt.Println("then feel free to contact me for support in this process.")
	fmt.Println("All contents of the vault are useless without keys, so you")
	fmt.Println("can send the contents of the vault over to me for analysis.")
	fmt.Println()
	fmt.Println("https://github.com/zytekaron/fidokit") // fixme
	fmt.Println("https://zyte.dev/contact")
	fmt.Println()

	log.Fatalln(err)
}

func verifySimpleVault(v *fkvault.SimpleVault) error {
	for name, header := range v.Headers {
		if name != header.Name {
			return fmt.Errorf("header key '%s' and value name '%s' do not match", name, header.Name)
		}

		if len(header.CredentialID) == 0 {
			return fmt.Errorf("CredentialID is missing or empty for '%s'", name)
		}
		if len(header.EncryptedKey) == 0 {
			return fmt.Errorf("EncryptedKey is missing or empty for '%s'", name)
		}
	}

	return verifyBaseVault(v.BaseVault)
}

func verifyShamirVault(v *fkvault.ShamirVault) error {
	// constraint: 2 <= k <= 255
	if v.K < 2 {
		return errors.New("k is out of bounds (2 <= k <= 255)")
	}
	// constraint: k <= n <= 255
	if v.N < v.K {
		return errors.New("n is out of bounds (k <= n <= 255)")
	}

	// 0 = uninitialized; n = initialized
	if len(v.Shares) != 0 && len(v.Shares) != int(v.N) {
		return errors.New("invalid number of shares compared to n")
	}

	for index, share := range v.Shares {
		if index < 0 || index > v.N {
			return errors.New("invalid number of shares compared to n")
		}

		if len(share.CredentialID) == 0 {
			return fmt.Errorf("CredentialID is missing or empty for '%d'", index)
		}
		if len(share.EncryptedKey) == 0 {
			return fmt.Errorf("EncryptedKey is missing or empty for '%d'", index)
		}
	}

	return verifyBaseVault(v.BaseVault)
}

func verifyBaseVault(v *fkvault.BaseVault) error {
	if v.Version < 0 {
		return errors.New("version is negative")
	}
	if v.Version > fkvault.CurrentVaultVersion {
		return errors.New("version is greater than the latest version known to this build")
	}

	if !slices.Contains(fkvault.Types, v.Type) {
		return errors.New("invalid vault type")
	}

	if v.ClientDataHashText == "" {
		return errors.New("ClientDataHashText is empty")
	}
	if v.AssertionSaltText == "" {
		return errors.New("AssertionSaltText is empty")
	}
	if v.RPID == "" {
		return errors.New("RPID is empty")
	}

	// disabled: non-critical
	//if v.Metadata.Created.After(v.Metadata.Modified) {
	//	return errors.New("created time is after modified time")
	//}

	return nil
}

func mustLoadVault(path string) any {
	vault, err := loadVault(path)
	if err != nil {
		log.Fatalln("load vault:", err)
	}
	return vault
}

func loadVault(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	vault, err := fkvault.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}
	return vault, nil
}

func mustSaveVault(path string, vault any) {
	err := saveVault(path, vault)
	if err != nil {
		log.Fatalln("save vault:", err)
	}
}

func saveVault(path string, vault any) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	err = encoder.Encode(vault)
	if err != nil {
		return fmt.Errorf("encode/write vault: %w", err)
	}
	return nil
}
