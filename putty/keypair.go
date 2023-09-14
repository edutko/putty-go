package putty

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

type Keypair interface {
	Type() string
	Private() crypto.PrivateKey
	Public() crypto.PublicKey
	Comment() string
}

type PublicKey interface {
	Type() string
	Key() crypto.PublicKey
	Comment() string
}

const (
	KeyTypeDSA      = "ssh-dss"
	KeyTypeECDSA256 = "ecdsa-sha2-nistp256"
	KeyTypeECDSA384 = "ecdsa-sha2-nistp384"
	KeyTypeECDSA521 = "ecdsa-sha2-nistp521"
	KeyTypeEd25519  = "ssh-ed25519"
	KeyTypeEd448    = "ssh-ed448"
	KeyTypeRSA      = "ssh-rsa"
)

func UnmarshalKeypair(privBytes, pubBytes []byte, comment string) (Keypair, error) {
	pub, err := UnmarshalPublicKey(pubBytes, comment)
	if err != nil {
		return nil, err
	}

	switch pub.Type() {
	case KeyTypeDSA:
		priv, err := unmarshalDSAPrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		priv.PublicKey = pub.Key().(dsa.PublicKey)
		return &keypair{priv, pub}, nil

	case KeyTypeECDSA256, KeyTypeECDSA384, KeyTypeECDSA521:
		priv, err := unmarshalECDSAPrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		priv.PublicKey = pub.Key().(ecdsa.PublicKey)
		return &keypair{priv, pub}, nil

	case KeyTypeEd25519:
		priv, err := unmarshalEd25519PrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		return &keypair{priv, pub}, nil

	case KeyTypeEd448:
		priv, err := unmarshalEd448PrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		return &keypair{priv, pub}, nil

	case KeyTypeRSA:
		priv, err := unmarshalRSAPrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		priv.PublicKey = pub.Key().(rsa.PublicKey)
		qInv := priv.Precomputed.Qinv
		priv.Precompute()
		if priv.Precomputed.Qinv.Cmp(qInv) != 0 {
			return nil, fmt.Errorf("invalid RSA private key")
		}
		return &keypair{priv, pub}, nil

	default:
		return nil, fmt.Errorf("")
	}
}

func UnmarshalPublicKey(pubBytes []byte, comment string) (PublicKey, error) {
	keyType, rest, err := unmarshalString(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshalString: %w", err)
	}
	var k crypto.PublicKey
	switch keyType {
	case KeyTypeDSA:
		k, err = unmarshalDSAPublicKey(rest)

	case KeyTypeECDSA256, KeyTypeECDSA384, KeyTypeECDSA521:
		k, err = unmarshalECDSAPublicKey(rest, keyType)

	case KeyTypeEd25519:
		k, err = unmarshalEd25519PublicKey(rest)

	case KeyTypeEd448:
		k, err = unmarshalEd448PublicKey(rest)

	case KeyTypeRSA:
		k, err = unmarshalRSAPublicKey(rest)

	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}
	if err != nil {
		return nil, err
	}

	return &publicKey{typ: keyType, key: k, comment: comment}, nil
}

var curves = map[string]elliptic.Curve{
	KeyTypeECDSA256: elliptic.P256(),
	KeyTypeECDSA384: elliptic.P384(),
	KeyTypeECDSA521: elliptic.P521(),
}

type keypair struct {
	priv crypto.PrivateKey
	pub  PublicKey
}

func (k *keypair) Type() string {
	return k.pub.Type()
}

func (k *keypair) Private() crypto.PrivateKey {
	return k.priv
}

func (k *keypair) Public() crypto.PublicKey {
	return k.pub.(crypto.PublicKey)
}

func (k *keypair) Comment() string {
	return k.pub.Comment()
}

type publicKey struct {
	typ     string
	key     crypto.PublicKey
	comment string
}

func (p publicKey) Type() string {
	return p.typ
}

func (p publicKey) Key() crypto.PublicKey {
	return p.key
}

func (p publicKey) Comment() string {
	return p.comment
}

type ed448PrivateKey []byte
type ed448PublicKey []byte

const ed448PrivateKeySize = 56
const ed448PublicKeySize = 56

func (pub ed448PublicKey) Equal(x crypto.PublicKey) bool {
	if b, ok := x.(ed448PublicKey); ok {
		return bytes.Equal(pub, b)
	} else {
		return false
	}
}
