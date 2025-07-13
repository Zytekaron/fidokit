package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"fidokit/fidoutils"
	"fidokit/fkvault"
	"fidokit/utils"
)

func interactiveSimpleVault(vault *fkvault.SimpleVault) {
	fmt.Println("Vault Info:")
	fmt.Println("  Type:   ", vault.Type)
	fmt.Println("  Name:   ", vault.Name)
	fmt.Println("  Desc:   ", vault.Description)
	fmt.Println("  Keys:   ", len(vault.Headers))
	fmt.Println("  Created:", vault.Metadata.Created)
	fmt.Println("  Updated:", vault.Metadata.Modified)
	fmt.Println()

	if debug {
		fmt.Println("Advanced Vault Info:")
		fmt.Println("  ID:  ", vault.ID)
		fmt.Println("  Type:", vault.Type)
		fmt.Println("  Ver: ", vault.Version)
		fmt.Println("  RPID:", vault.RPID)
		fmt.Println("  CDH: ", vault.ClientDataHashText)
		fmt.Println("  Salt:", vault.AssertionSaltText)
		fmt.Println()
	}

	for {
		input := utils.ReadLine("Enter command (? for help): ")
		if len(input) == 0 {
			continue
		}
		fmt.Println()

		switch input {
		case "?", "??", "h", "help", "help-all":
			fmt.Println("Commands:")
			fmt.Println("  l, list:   list headers (key entries)")
			fmt.Println("  u, unlock: unlock the master key (cached)")
			fmt.Println("* a, add:    create a new header *")
			fmt.Println("* d, delete: delete a header *")
			fmt.Println("* r, reset:  reset vault *")
			fmt.Println("  s, save:   save vault to disk")
			fmt.Println("  q, quit:   exit without saving")
			fmt.Println("  x, done:   exit and save vault")
			fmt.Println("")
			fmt.Println("* changes are in memory only, you must save")
			fmt.Println("  them to disk manually using `save` or `done`")
			fmt.Println("")
			if input == "??" || input == "help-all" {
				fmt.Println("Developer:")
				fmt.Println("  D, devs:   list connected FIDO2 devices")
				fmt.Println("  I, info:   view advanced vault information")
				fmt.Println("  P, print:  print vault json to stdout")
				fmt.Println("  L, listv:  list headers verbosely (key entries)")
				fmt.Println("")
			}

		case "I", "info":
			fmt.Println("Vault Info:")
			fmt.Println("  Type:   ", vault.Type)
			fmt.Println("  Name:   ", vault.Name)
			fmt.Println("  Desc:   ", vault.Description)
			fmt.Println("  Keys:   ", len(vault.Headers))
			fmt.Println("  Created:", vault.Metadata.Created)
			fmt.Println("  Updated:", vault.Metadata.Modified)
			fmt.Println()
			fmt.Println("Advanced Vault Info:")
			fmt.Println("  ID:  ", vault.ID)
			fmt.Println("  Type:", vault.Type)
			fmt.Println("  Ver: ", vault.Version)
			fmt.Println("  RPID:", vault.RPID)
			fmt.Println("  CDH: ", vault.ClientDataHashText)
			fmt.Println("  Salt:", vault.AssertionSaltText)
			fmt.Println()

		case "D", "devs":
			fidoutils.PrintConnectedDevices()

		case "l", "list":
			fmt.Println("Keys:")
			for name := range vault.Headers {
				fmt.Printf("- %s\n", name)
			}

		case "L", "listv", "listverbose":
			fmt.Println("Headers:")
			for name, h := range vault.Headers {
				fmt.Printf("- %s:\n\tcredential_id=%x\n\tencrypted_key=%x\n", name, h.CredentialID, h.EncryptedKey)
			}

		case "a", "add":
			err := vault.InteractiveAdd()
			if err != nil {
				log.Fatalln("add:", err)
			}

		case "u", "unlock":
			masterKey, err := vault.InteractiveUnlock()
			if err != nil {
				log.Fatalln("unlock:", err)
			}

			if outputPath != "" && outputPath != "1" && outputPath != "stdout" {
				err := os.WriteFile(outputPath, masterKey, 0600)
				if err != nil {
					log.Fatalln("write master key to output file:", err)
				}
				fmt.Println("Master key written to output file.")
			} else {
				fmt.Printf("Master Key (hex): %x\n", masterKey)
			}

		case "d", "delete":
			vault.InteractiveDelete()

		case "s", "save", "w", "write":
			mustSaveVault(vaultPath, vault)
			fmt.Println("Saved!")

		case "r", "reset":
			vault.DeleteAllHeaders()
			fmt.Println("Vault reset!")

		case "P", "print", "dump":
			data, err := json.MarshalIndent(vault, "", "    ")
			if err != nil {
				log.Fatalln("marshal vault:", err)
			}
			fmt.Println(string(data))

		case "q", "quit", "cancel":
			os.Exit(0)

		case "wq", "x", "done", "exit":
			mustSaveVault(vaultPath, vault)
			fmt.Println("Exiting and saving changes.")
			os.Exit(0)
		}

		fmt.Println()
	}
}

// 64a92cd6c62602f944df43
