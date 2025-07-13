# fidokit

**version:** 0.0.1 (beta)

> [!CAUTION]
> 🚨 **Security Notice**  
> This tool handles cryptographic material.
> Use at your own risk and review the code before deploying.
> I offer no guarantees of data integrity for this progtam,
> and this project is in early development, so you should
> expect major breaking changes prior to an official release.

> [!WARNING]
> Erasing or resetting a FIDO2 key will render it unusable for
> recovery of a vault. If you erase or reset keys such that you
> no longer have enough, it will become permanently irrecoverable.

> [!WARNING]
> This program does **not** offer security against post-quantum
> cryptographic attacks, as FIDO2 keys do not support this yet.
> This means all vaults are vulnerable to future quantum-based
> decryption attacks against the algorithm which this program
> uses on FIDO2 security keys; ES256 (ECDSA + P-256 + SHA256).

## Compatibility

This program works with keys which support **FIDO2** with the **hmac-secret** extension.

Here are some popular supported keys:
- YubiKey 5 series, except 5Ci
- Solo v2, Solo Tap
- Nitrokey 3

NFC keys have **not** been tested with this program, but should
work as long as you have an NFC reader for a compatible system.
Cryptnox FIDO2 cards will **not** work over SmartCard interfaces.

Tested keys:
- YubiKey 5C Bio (5.7)
- YubiKey 5C NFC (5.4)
- YubiKey 5A NFC (5.4)
- YubiKey 5C Nano (5.7, 5.4, 5.1)

## Platforms

Development is primarily done on macOS, and functionality is
tested on Linux. I don't use or currently plan to officially
support Windows, however it's likely that it will still work.

- macOS: Tested and working
- Linux: Not tested
- Windows: Not tested

## TODO

- Improve overall user experience in CLI prompting.
- Support for an accessory password prior to unlocking.
- Release and lock in an official Shamir version.
- Perform retries after timeout or authentication failure instead of crashing.
- Perform testing before first release:
  - Varying key types (Bio, NFC)
  - Shamir k=1
  - Shamir k=n
  - Shamir vault recovery with corruption

## Terminology

- Vault: A structure (stored as JSON) which contains information necessary to access a Master Key.
- Master Key: A single key, typically encoded in the terminal as hex, being encrypted by the vault.
- Shamir: A shorthand name referring to the [Shamir Secret Sharing System](https://en.wikipedia.org/wiki/Shamir's_secret_sharing).

## Vault Types

### Simple Vaults

Any of the keys enrolled in a Simple vault can be used to unlock the vault's master key.

Keys can be trivially enrolled by bringing an existing key together with the key you wish
to enroll. The program recovers the master key using your existing key, and then encrypts
the master key with your new key, so it can also recover it later.

Keys can also trivially be removed by deleting the associated named entry for a key.

### Shamir Vaults

A certain number of keys, specified by the user, must be present in person at the same
time to successfully decrypt a Shamir vault.

All keys must be present at the time of creation for a Shamir vault to be created.
This is because the shares cannot be expanded or retracted later, like you can do
with a simple vault by adding or removing entries, and implementing it such that
keys can  be added later by temporarily encrypting them via other means is both
more difficult to implement and less secure.

If I implemented a method to add a new key by decrypting and then recreating shares,
all keys would still need to be present to re-encrypt their newly created shares,
which is no better than simply reinstantiating the vault.

## Flags

```
    -v, --vault
      * Default: 'vault.json'
      * Sets the file path to your vault.json
        
    -i, --input
      * Default: 'stdin'
      * Sets an input file path, which the program will read a master key
        from when initializing a new vault, instead of using standard input.
        This flag is ignored for all other operations.
        
    -o, --output
      * Default: 'stdout'
      * Sets an output file path, which the program will write the master key
        to when you unlock a vault, instead of using standard output.
        This flag is ignored for all other operations.
    
    -D, --debug
      * Enables debug information, which may provide useful information
        if you are trying to investigate an error or recover your vault.
        You should also enable this option if submitting a bug report.

    -U, --unlock
      * Starts the program in "unlock mode", which is used in scripting
        contexts to prompt the user to directly unlock the vault instead
        of providing the user with an interactive menu that must be exited.

    --disable-biometrics
      * This flag can be used to disable the behavior where PIN entry is
        skipped for keys that support biometrics. This can be used if you
        do not currently have the means to authenticate using biometrics with
        your keys. It will instead ask for the backup PIN for each key. If
        you use a key which ONLY supports biometrics, the program will exit.

    --no-assumptions
      * By default the program will assume, for any given operation,
        that if enough keys are connected at once, then all of the keys
        needed for this step have been connected ahead of time. If you
        are doing something slightly non-standard, for example you have extra
        keys plugged in, but none of them can be used to unlock a simple vault,
        you may use this option to ensure the program asks you to press ENTER
        *each time* before prompting for key selection or running assertions.
      
    --skip-checks
      * This option tells the program to skip all the extra vault integrity
        checks when loading a vault. The vault must still present as valid
        JSON and the value types must be correct, but the program will not
        check if the parsed data is internally consistent.
        
        This option exists as a way to ignore important issues temporarily so
        you can attempt to recover the master key despite them. You should only
        need to use this option in cases where there is an exceptional bug in
        the program or you have modified the vault manually and corrupted it.
        
        An example of a vault corruption where this would be useful is if you
        changed the value of "n" in a Shamir vault JSON file, and also removed
        some shares manually, meaning they do not match what they did during
        initial creation. The program will still allow you to recover the key
        as long as "k" is at least the value used during initialization, and
        at least "k" shares are still present in JSON file and in person.
        
        If you enable this option and are still not able to recover your vault,
        feel free to contact me for further assistance, however I will not be
        able to assist if the vault is corrupted beyond repair. I suggest
        keeping backups and never manually modifying the JSON file.

```

# Similar Projects

- [tmo1/vidovault](https://github.com/tmo1/fidovault) -
  "A tool to control access to secrets via symmetric
  encryption and decryption using hardware FIDO2 keys."
  This was my initial inspiration and starting point for this project.
- [RockwellShah/filekey](https://github.com/RockwellShah/filekey) -
  "Encrypt and share files securely with passkeys. Fully offline,
  easy-to-use, and zero-knowledge for ultimate file protection."
- [riastradh/fidocrypt](https://github.com/riastradh/fidocrypt) -
  "U2F/FIDO-based key derivation and encapsulation."

# License

**fidokit** is licensed under the [MIT License](./LICENSE).
