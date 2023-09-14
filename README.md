# putty-go

Consume [puTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/) keys (PPK files) in go

## Overview

This library supports version 2 and version 3 PPK files, with the following limitations:
* ssh-ed448 keys cannot be converted to Go public/private keys.
* Argon2d KDF is not supported.

## Examples

### Load the public and private keys from a password-protected PPK file

```go
keyPair, err := LoadKeypair("mykey.ppk", []byte("hunter2"))
```

For unencrypted PPK files, use `ppk.NoPassphrase` as the passphrase.

### Load the public key from a password-protected PPK file without the password (skips MAC verification)

```go
ppk, err := InsecureParseFile("mykey.ppk")
pub, err := putty.UnmarshalPublicKey(ppk.PublicBytes, ppk.Comment)
```
