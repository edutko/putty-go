package ppk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/argon2"
)

func decryptAndVerifyMAC(ppk PPK, passphrase []byte) ([]byte, error) {
	k, err := deriveKeyMaterial(ppk, passphrase)
	if err != nil {
		return nil, err
	}

	decryptedPrivateKey := ppk.PrivateBytes
	if ppk.Encryption == AES256CBC {
		bm := cipher.NewCBCDecrypter(k.cipher, k.iv)
		paddedPlaintext := make([]byte, len(ppk.PrivateBytes))
		bm.CryptBlocks(paddedPlaintext, ppk.PrivateBytes)
		decryptedPrivateKey = paddedPlaintext
	}

	var payload []byte
	payload = appendBytesWithLength(payload, []byte(ppk.Type)...)
	payload = appendBytesWithLength(payload, []byte(ppk.Encryption)...)
	payload = appendBytesWithLength(payload, []byte(ppk.Comment)...)
	payload = appendBytesWithLength(payload, ppk.PublicBytes...)
	payload = appendBytesWithLength(payload, decryptedPrivateKey...)

	k.mac.Reset()
	k.mac.Write(payload)
	mac := k.mac.Sum(nil)

	if !bytes.Equal(ppk.MAC, mac) {
		return nil, fmt.Errorf("corrupted data or incorrect password")
	}

	return decryptedPrivateKey, nil
}

type keyMaterial struct {
	mac    hash.Hash
	cipher cipher.Block
	iv     []byte
}

func deriveKeyMaterial(ppk PPK, passphrase []byte) (keyMaterial, error) {
	switch ppk.Version {
	case 2:
		return deriveV2KeyMaterial(ppk, passphrase)
	case 3:
		return deriveV3KeyMaterial(ppk, passphrase)
	default:
		return keyMaterial{}, fmt.Errorf("unsupported PPK version: %d", ppk.Version)
	}
}

func deriveV2KeyMaterial(ppk PPK, passphrase []byte) (keyMaterial, error) {
	var k keyMaterial
	switch ppk.Encryption {
	case NoEncryption:
		hk := sha1.Sum(append([]byte("putty-private-key-file-mac-key"), passphrase...))
		k.mac = hmac.New(sha1.New, hk[:])

	case AES256CBC:
		var b1, b2 []byte
		b1 = binary.BigEndian.AppendUint32(b1, 0)
		b1 = append(b1, []byte(passphrase)...)
		h1 := sha1.Sum(b1)
		b2 = binary.BigEndian.AppendUint32(b2, 1)
		b2 = append(b2, []byte(passphrase)...)
		h2 := sha1.Sum(b2)

		k.cipher, _ = aes.NewCipher(append(h1[:], h2[:]...)[:32])
		k.iv = make([]byte, aes.BlockSize)
		hk := sha1.Sum(append([]byte("putty-private-key-file-mac-key"), passphrase...))
		k.mac = hmac.New(sha1.New, hk[:])

	default:
		return k, fmt.Errorf("unsupported PPK encryption: %s", ppk.Encryption)
	}

	return k, nil
}

func deriveV3KeyMaterial(ppk PPK, passphrase []byte) (keyMaterial, error) {
	var k keyMaterial
	switch ppk.Encryption {
	case NoEncryption:
		k.mac = hmac.New(sha256.New, []byte{})

	case AES256CBC:
		var h []byte
		switch ppk.KeyDerivation {
		case Argon2i:
			h = argon2.Key(passphrase, ppk.Argon2Salt, uint32(ppk.Argon2Passes), uint32(ppk.Argon2Memory), uint8(ppk.Argon2Parallelism), 32+aes.BlockSize+32)
		case Argon2id:
			h = argon2.IDKey(passphrase, ppk.Argon2Salt, uint32(ppk.Argon2Passes), uint32(ppk.Argon2Memory), uint8(ppk.Argon2Parallelism), 32+aes.BlockSize+32)
		default:
			return k, fmt.Errorf("unsupported key derivation algorithm: %s", ppk.KeyDerivation)
		}

		k.cipher, _ = aes.NewCipher(h[:32])
		k.iv = h[32 : 32+aes.BlockSize]
		k.mac = hmac.New(sha256.New, h[32+aes.BlockSize:32+aes.BlockSize+32])

	default:
		return k, fmt.Errorf("unsupported PPK encryption: %v", ppk.Encryption)
	}

	return k, nil
}

func appendBytesWithLength(dest []byte, elems ...byte) []byte {
	dest = binary.BigEndian.AppendUint32(dest, uint32(len(elems)))
	return append(dest, elems...)
}
