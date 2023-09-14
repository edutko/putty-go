package ppk

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/edutko/putty-go/putty"
)

// https://the.earth.li/~sgtatham/putty/0.78/htmldoc/AppendixC.html#ppk
type PPK struct {
	Version           int
	Type              string
	Encryption        Encryption
	Comment           string
	PublicBytes       []byte
	KeyDerivation     Argon2Flavor
	Argon2Memory      int
	Argon2Passes      int
	Argon2Parallelism int
	Argon2Salt        []byte
	PrivateBytes      []byte
	MAC               []byte
}

type Encryption string

const (
	NoEncryption Encryption = "none"
	AES256CBC    Encryption = "aes256-cbc"
)

type Argon2Flavor string

const (
	Argon2d  Argon2Flavor = "Argon2d"
	Argon2i  Argon2Flavor = "Argon2i"
	Argon2id Argon2Flavor = "Argon2id"
)

var NoPassphrase = []byte("")

func LoadKeypair(file string, passphrase []byte) (putty.Keypair, error) {
	ppk, err := InsecureParseFile(file)
	if err != nil {
		return nil, err
	}

	kp, err := ppk.Decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	return kp, nil
}

func InsecureParseFile(file string) (*PPK, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	ppk, err := InsecureParse(b)
	if err != nil {
		return nil, err
	}

	return ppk, nil
}

func InsecureParse(b []byte) (*PPK, error) {
	var p PPK
	var err error
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}

		key, value, found := strings.Cut(strings.TrimSpace(s.Text()), ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if !found {
			return nil, fmt.Errorf("invalid PPK file")
		}

		switch key {
		case "PuTTY-User-Key-File-2":
			p.Version = 2
			p.Type = value
		case "PuTTY-User-Key-File-3":
			p.Version = 3
			p.Type = value
		case "Encryption":
			p.Encryption = Encryption(value)
		case "Comment":
			p.Comment = value
		case "Public-Lines":
			p.PublicBytes, err = parseWrappedBase64(s, value)
		case "Key-Derivation":
			p.KeyDerivation = Argon2Flavor(value)
		case "Argon2-Memory":
			p.Argon2Memory, err = strconv.Atoi(value)
		case "Argon2-Passes":
			p.Argon2Passes, err = strconv.Atoi(value)
		case "Argon2-Parallelism":
			p.Argon2Parallelism, err = strconv.Atoi(value)
		case "Argon2-Salt":
			p.Argon2Salt, err = hex.DecodeString(value)
		case "Private-Lines":
			p.PrivateBytes, err = parseWrappedBase64(s, value)
		case "Private-MAC":
			p.MAC, err = hex.DecodeString(value)
		default:
			return nil, fmt.Errorf("invalid PPK file: unexpected header")
		}

		if err != nil {
			return nil, err
		}
	}

	if s.Err() != nil {
		return nil, fmt.Errorf("invalid PPK file: %w", s.Err())
	}

	if p.Version == 0 || p.Type == "" || p.Encryption == "" || len(p.PublicBytes) == 0 || len(p.PrivateBytes) == 0 {
		return nil, fmt.Errorf("invalid PPK file: missing required fields")
	}

	return &p, nil
}

func (ppk PPK) Decrypt(passphrase []byte) (putty.Keypair, error) {
	privateBytes, err := decryptAndVerifyMAC(ppk, passphrase)
	if err != nil {
		return nil, err
	}

	kp, err := putty.UnmarshalKeypair(privateBytes, ppk.PublicBytes, ppk.Comment)
	if err != nil {
		return nil, err
	}

	return kp, nil
}
