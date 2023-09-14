package putty

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ed25519"
)

func unmarshalDSAPrivateKey(b []byte) (*dsa.PrivateKey, error) {
	x, _, err := unmarshalMPInt(b)
	if err != nil {
		return nil, err
	}
	return &dsa.PrivateKey{
		X: x,
	}, nil
}

func unmarshalDSAPublicKey(b []byte) (dsa.PublicKey, error) {
	rest := b
	p, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return dsa.PublicKey{}, err
	}
	q, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return dsa.PublicKey{}, err
	}
	g, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return dsa.PublicKey{}, err
	}
	y, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return dsa.PublicKey{}, err
	}
	return dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: p,
			Q: q,
			G: g,
		},
		Y: y,
	}, nil
}

func unmarshalECDSAPrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	d, _, err := unmarshalMPInt(b)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		D: d,
	}, nil
}

func unmarshalECDSAPublicKey(b []byte, keyType string) (ecdsa.PublicKey, error) {
	rest := b
	curve, rest, err := unmarshalString(rest)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	if curves[keyType].Params().Name != goCurveName(curve) {
		return ecdsa.PublicKey{}, fmt.Errorf("mismatched curve: %s in %s key", curve, keyType)
	}
	key, _, err := readLengthPrefixedBytes(rest)
	if err != nil {
		return ecdsa.PublicKey{}, err
	}
	x, y := elliptic.Unmarshal(curves[keyType], key)

	return ecdsa.PublicKey{
		Curve: curves[keyType],
		X:     x,
		Y:     y,
	}, nil
}

func unmarshalEd25519PrivateKey(b []byte) (ed25519.PrivateKey, error) {
	k, _, err := readLengthPrefixedBytes(b)
	if err != nil {
		return nil, err
	}
	if len(k) != ed25519.SeedSize {
		err = fmt.Errorf("invalid Ed25519 scalar: expected %d bytes, found %d bytes", ed25519.SeedSize, len(k))
	}
	return ed25519.NewKeyFromSeed(k), nil
}

func unmarshalEd25519PublicKey(b []byte) (ed25519.PublicKey, error) {
	k, _, err := readLengthPrefixedBytes(b)
	if err != nil {
		return nil, err
	}
	if len(k) != ed25519.PublicKeySize {
		err = fmt.Errorf("invalid Ed25519 point: expected %d bytes, found %d bytes", ed25519.PublicKeySize, len(k))
	}
	return k, nil
}

func unmarshalEd448PrivateKey(b []byte) (ed448PrivateKey, error) {
	k, _, err := readLengthPrefixedBytes(b)
	if err != nil {
		return nil, err
	}
	if len(k) != ed448PrivateKeySize {
		err = fmt.Errorf("invalid Ed448 scalar: expected %d bytes, found %d bytes", ed448PrivateKeySize, len(k))
	}
	return k, nil
}

func unmarshalEd448PublicKey(b []byte) (ed448PublicKey, error) {
	k, _, err := readLengthPrefixedBytes(b)
	if err != nil {
		return nil, err
	}
	if len(k) != ed448PublicKeySize {
		err = fmt.Errorf("invalid Ed448 point: expected %d bytes, found %d bytes", ed448PublicKeySize, len(k))
	}
	return k, nil
}

func unmarshalRSAPrivateKey(b []byte) (*rsa.PrivateKey, error) {
	rest := b
	d, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return nil, err
	}
	p, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return nil, err
	}
	q, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return nil, err
	}
	qInv, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return nil, err
	}
	return &rsa.PrivateKey{
		D:           d,
		Primes:      []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{Qinv: qInv},
	}, nil
}

func unmarshalRSAPublicKey(b []byte) (rsa.PublicKey, error) {
	rest := b
	var i *big.Int
	i, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	e := int(i.Int64())
	n, rest, err := unmarshalMPInt(rest)
	if err != nil {
		return rsa.PublicKey{}, err
	}
	return rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func unmarshalMPInt(b []byte) (*big.Int, []byte, error) {
	i, rest, err := readLengthPrefixedBytes(b)
	return big.NewInt(0).SetBytes(i), rest, err
}

func unmarshalString(b []byte) (string, []byte, error) {
	s, rest, err := readLengthPrefixedBytes(b)
	return string(s), rest, err
}

func readLengthPrefixedBytes(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, b, fmt.Errorf("short data")
	}

	l := binary.BigEndian.Uint32(b[:4])
	if len(b) < 4+int(l) {
		return nil, b, fmt.Errorf("short data")
	}

	return b[4 : 4+l], b[4+l:], nil
}

func goCurveName(s string) string {
	return strings.Replace(s, "nistp", "P-", 1)
}
