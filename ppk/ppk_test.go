package ppk

import (
	"crypto"
	"crypto/dsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func loadPassword() []byte {
	b, err := os.ReadFile("testdata/password")
	if err != nil {
		panic(err)
	}
	return b
}

func TestLoadKeypair(t *testing.T) {
	defaultPassword := loadPassword()

	for f, k := range keypairs {
		t.Run(f, func(t *testing.T) {
			password := make([]byte, 0)
			if ppks[f].Encryption != NoEncryption {
				password = defaultPassword
			}

			kp, err := LoadKeypair("testdata/"+f, password)

			assert.Nil(t, err)
			assert.Equal(t, k, kp.Private())
		})
	}
}

func TestLoadKeypair_errors(t *testing.T) {
	testCases := []struct {
		file string
		msg  string
	}{
		{"nonexistent.ppk", "nonexistent.ppk: no such file or directory"},
		{"invalid/invalid-base64.ppk", "illegal base64 data"},
		{"invalid/invalid-hex.ppk", "encoding/hex: invalid byte: "},
		{"invalid/long-private.ppk", "invalid PPK file"},
		{"invalid/short-private.ppk", "unexpected EOF"},
		{"ecdsa-384-enc.ppk", "corrupted data or incorrect password"},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			priv, err := LoadKeypair("testdata/"+tc.file, NoPassphrase)

			assert.Nil(t, priv)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestInsecureParse(t *testing.T) {
	for f := range ppks {
		t.Run(f, func(t *testing.T) {
			b, _ := os.ReadFile("testdata/" + f)
			ppk, err := InsecureParse(b)

			assert.Nil(t, err)
			assert.Equal(t, ppks[f], ppk)
		})
	}
}

func TestInsecureParse_errors(t *testing.T) {
	testCases := []struct {
		file string
		msg  string
	}{
		{"invalid/invalid-base64.ppk", "illegal base64 data"},
		{"invalid/invalid-header.ppk", "invalid PPK file: unexpected header"},
		{"invalid/invalid-hex.ppk", "encoding/hex: invalid byte: "},
		{"invalid/long-private.ppk", "invalid PPK file"},
		{"invalid/missing-encryption.ppk", "invalid PPK file: missing required fields"},
		{"invalid/missing-private-key.ppk", "invalid PPK file: missing required fields"},
		{"invalid/missing-public-key.ppk", "invalid PPK file: missing required fields"},
		{"invalid/missing-type.ppk", "invalid PPK file: missing required fields"},
		{"invalid/missing-version.ppk", "invalid PPK file: missing required fields"},
		{"invalid/short-private.ppk", "unexpected EOF"},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			b, _ := os.ReadFile("testdata/" + tc.file)
			ppk, err := InsecureParse(b)

			assert.Nil(t, ppk)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestPPK_Decrypt(t *testing.T) {
	password := loadPassword()
	testCases := []struct {
		file       string
		password   []byte
		privateKey any
		err        error
	}{
		{"rsa-2048.ppk", NoPassphrase, keypairs["rsa-2048.ppk"], nil},
		{"rsa-2048-enc.ppk", password, keypairs["rsa-2048-enc.ppk"], nil},
		{"rsa-2048-enc.ppk", []byte("wrongP@ssw0rd"), nil, fmt.Errorf("corrupted data or incorrect password")},
	}
	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			b, _ := os.ReadFile("testdata/" + tc.file)
			ppk, _ := InsecureParse(b)

			kp, err := ppk.Decrypt(tc.password)

			if tc.privateKey == nil {
				assert.Nil(t, kp)
			} else {
				assert.Equal(t, tc.privateKey, kp.Private())
			}
			assert.Equal(t, tc.err, err)
		})
	}
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func b64Bytes(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var ppks = map[string]*PPK{
	"dsa-1024-enc.ppk": {
		Version:           3,
		Type:              "ssh-dss",
		Encryption:        AES256CBC,
		Comment:           "puTTY dsa-1024 (encrypted)",
		PublicBytes:       b64Bytes("AAAAB3NzaC1kc3MAAACBAPomLalQzuF8G3/+A9sWHvuHeU6ze3+0VBvPMPRzlVTtBbV9uaTtrjnYK3f79qDFIlyQQBLuElNCu3Nbbgmc+6miDnV9cv0mpXubxFEZe0U5vam+VnmTUAu+t/sVjsEZhx9+zTIiWu3eGu/P3Eum7j97o68Rj+US2ya7ttiEfzFFAAAAFQDtWIiOTSrdXx1H6zhIfFHvAb0y3wAAAIEAkHIeImIJ+V3f1fbpLqHujFA4w/SWcaF+C+A+YN9R0k9gbcCRuz0eK/CpeBqtci7yAXq26QLmtADvSebBM9umb5uWYuXRwk5BqaYMk9MkeFe7tIu0xpOyyyhrC6Xz6AlwUTVxDJSp3WIKpxbreycxFC0sEqX8M5061Z/BpGjBDR0AAACBANcAqQUa9v9q0E8/w6YvSefwwCHDFTWAaQD4BU5NXZXa6Msw4jyr1tLCAjg3KniI/537ATlPgmZZAqTg3oIi7uSCGLRv79AVEa4JvNPC62nIh+2PejXMqy2axLimN3LQQq/3dxtmDvbKvh9zg7CgpTZ4zNjO3P08PPKD4CCVbZWT"),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("459650e9f36a679951548b2d4bf26c71"),
		PrivateBytes:      b64Bytes("C1Qd2p8XaYdw50h9DmOszGPcIUgg5GIOT3aysRuYk+U="),
		MAC:               hexBytes("0af65d5dfbd7d5a1e2fdef2acf28d9834a4b167989f086f1c61e25404c0cdc77"),
	},
	"dsa-1024.ppk": {
		Version:      3,
		Type:         "ssh-dss",
		Encryption:   NoEncryption,
		Comment:      "puTTY dsa-1024",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAACBAPomLalQzuF8G3/+A9sWHvuHeU6ze3+0VBvPMPRzlVTtBbV9uaTtrjnYK3f79qDFIlyQQBLuElNCu3Nbbgmc+6miDnV9cv0mpXubxFEZe0U5vam+VnmTUAu+t/sVjsEZhx9+zTIiWu3eGu/P3Eum7j97o68Rj+US2ya7ttiEfzFFAAAAFQDtWIiOTSrdXx1H6zhIfFHvAb0y3wAAAIEAkHIeImIJ+V3f1fbpLqHujFA4w/SWcaF+C+A+YN9R0k9gbcCRuz0eK/CpeBqtci7yAXq26QLmtADvSebBM9umb5uWYuXRwk5BqaYMk9MkeFe7tIu0xpOyyyhrC6Xz6AlwUTVxDJSp3WIKpxbreycxFC0sEqX8M5061Z/BpGjBDR0AAACBANcAqQUa9v9q0E8/w6YvSefwwCHDFTWAaQD4BU5NXZXa6Msw4jyr1tLCAjg3KniI/537ATlPgmZZAqTg3oIi7uSCGLRv79AVEa4JvNPC62nIh+2PejXMqy2axLimN3LQQq/3dxtmDvbKvh9zg7CgpTZ4zNjO3P08PPKD4CCVbZWT"),
		PrivateBytes: b64Bytes("AAAAFAcB0wFbZmQgkCGUNR8IDxQUzBBG"),
		MAC:          hexBytes("568941bd2ad73579034a79780e33c625f63a0d52a74ef0ff6851d7a7d6911efe"),
	},
	"dsa-2048-enc.ppk": {
		Version:           3,
		Type:              "ssh-dss",
		Encryption:        AES256CBC,
		Comment:           "puTTY dsa-2048 (encrypted)",
		PublicBytes:       b64Bytes("AAAAB3NzaC1kc3MAAAEBAN/5G+eKaJyfIwpaB8/D8GpQwMKj64c3jQPa1+7rQgH6Z4+8gB7936WCglk71k2488b7yOSpYQoyJ3KyjJkS+R+F7N9amYlyI3DLfYDP5L2FbOJ7uhsd5Bb8OXv59m51j/4TvbkOz+7ADvt3M9GrkxOj9tbdGGLwVsXOy0joHpjZxkrNcVGRyXOgR7nVjAjd/ExuA9RYNznPgjUEhjG4jMNmZPPI6BLeCSOjw2iIv909XbsImdqWC/qAhWAoQhkO+9fsvrUBBK4vthjcf6SRRZN2TF+JLiQT/2ilpkew9OCY4b4UEHgLexEUuu/c7RDQyQKxvDU1vObgGIHIHym38B8AAAAVAKZV6uwKA89+mF+kudHLbqpDHkhdAAABAQCDOCjAfPr/j3C1nLdWRyVOdx/SKDtI1sqShOzoJMr46v0lrqkjKTBVYM1psBe1Irw3hcs+TCSp4XI8qO1LAr8y4B6/ohMU4+V5uQGzpImD50P/ctGrgG0Of6kO87wkeLw6SHMatThL98uTz5brWk0V+2uWwzdH2QBU5pTDeNeNZ8WkDwM+0vAKK9E7XPg5zfy+s0SY8LsTy5L99xAP0JJMpShtd8TaHX7m+6PLPsFlxG4swSC3XUEGiipBlaQCVE7OPZvcMC+ACbYQn0ThE+sfOMvn/aAKLh7OlH3mRFd4m7uo5b6l8JcXPe9wYPbQoNEEMV5ZAUejXS1+iVy7l6DMAAABAQC0zWJLKSNqQO4S1YPzUucy02d4ltDUvq+N1Iu3PCddCYUfyJE0T4gcW9snTF7/zxCp2lX/58cXejYxiAfLV1Orss/nmBOegaqbfYjd9y2PlMrxFCQIOQzCC3+qeuD+NSMh/i+MbYvcf5cWxL1MuS/+ng1NAZv3NsNvuJ09jrwKg5qEwfc2fwDQDfkN/dCwzq+Q/DpZCA02PIOwZpB/T5J5V1ZlCNOZ1Gp6JbpkQfkwurpN/zlCf7G6yUrH/xwEAddw9ViJpwdDjMwwgwpRL6h+JKjQJyusLONeFtAHbDJxt1L+aUCJXj8H9xNzpzpKj2gOCTC7L7/DL5Mpple73KqN"),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("c6089272ce253e42ef0e43e6fb31a7cd"),
		PrivateBytes:      b64Bytes("6h87HsPMmiGrz9DDd90nlYTAsVMGxVw5kkLMqXfBntI="),
		MAC:               hexBytes("a474cfd49b4b3835a59043d4a597c30348f45a70b17fab717d9da02e146bef89"),
	},
	"dsa-2048.ppk": {
		Version:      3,
		Type:         "ssh-dss",
		Encryption:   NoEncryption,
		Comment:      "puTTY dsa-2048",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAAEBAN/5G+eKaJyfIwpaB8/D8GpQwMKj64c3jQPa1+7rQgH6Z4+8gB7936WCglk71k2488b7yOSpYQoyJ3KyjJkS+R+F7N9amYlyI3DLfYDP5L2FbOJ7uhsd5Bb8OXv59m51j/4TvbkOz+7ADvt3M9GrkxOj9tbdGGLwVsXOy0joHpjZxkrNcVGRyXOgR7nVjAjd/ExuA9RYNznPgjUEhjG4jMNmZPPI6BLeCSOjw2iIv909XbsImdqWC/qAhWAoQhkO+9fsvrUBBK4vthjcf6SRRZN2TF+JLiQT/2ilpkew9OCY4b4UEHgLexEUuu/c7RDQyQKxvDU1vObgGIHIHym38B8AAAAVAKZV6uwKA89+mF+kudHLbqpDHkhdAAABAQCDOCjAfPr/j3C1nLdWRyVOdx/SKDtI1sqShOzoJMr46v0lrqkjKTBVYM1psBe1Irw3hcs+TCSp4XI8qO1LAr8y4B6/ohMU4+V5uQGzpImD50P/ctGrgG0Of6kO87wkeLw6SHMatThL98uTz5brWk0V+2uWwzdH2QBU5pTDeNeNZ8WkDwM+0vAKK9E7XPg5zfy+s0SY8LsTy5L99xAP0JJMpShtd8TaHX7m+6PLPsFlxG4swSC3XUEGiipBlaQCVE7OPZvcMC+ACbYQn0ThE+sfOMvn/aAKLh7OlH3mRFd4m7uo5b6l8JcXPe9wYPbQoNEEMV5ZAUejXS1+iVy7l6DMAAABAQC0zWJLKSNqQO4S1YPzUucy02d4ltDUvq+N1Iu3PCddCYUfyJE0T4gcW9snTF7/zxCp2lX/58cXejYxiAfLV1Orss/nmBOegaqbfYjd9y2PlMrxFCQIOQzCC3+qeuD+NSMh/i+MbYvcf5cWxL1MuS/+ng1NAZv3NsNvuJ09jrwKg5qEwfc2fwDQDfkN/dCwzq+Q/DpZCA02PIOwZpB/T5J5V1ZlCNOZ1Gp6JbpkQfkwurpN/zlCf7G6yUrH/xwEAddw9ViJpwdDjMwwgwpRL6h+JKjQJyusLONeFtAHbDJxt1L+aUCJXj8H9xNzpzpKj2gOCTC7L7/DL5Mpple73KqN"),
		PrivateBytes: b64Bytes("AAAAFH2OdOHeZ+8Zb1SfiM/vCYRuDj+W"),
		MAC:          hexBytes("82d589a28646034a9d9172c50641feccb2943125ea1840d6e63a31840021c8fe"),
	},
	"ecdsa-256-enc.ppk": {
		Version:           3,
		Type:              "ecdsa-sha2-nistp256",
		Encryption:        AES256CBC,
		Comment:           "puTTY ecdsa-256 (encrypted)",
		PublicBytes:       b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPttHuSNO/1n89v5LSGEfxbw4JXLzqUEC7eVHALJ0KM34fR+VLzt48ydtOkUv8lrOLBdrtqtuzQ8yKC8WHctpy4="),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("c43032c7920b77ef54e6f57b4eecc981"),
		PrivateBytes:      b64Bytes("fzjKsPh0EqU4yNeuK8HnXZarxRVfO3OYWCSEJHUbxfcPe4hNR4Eg1QLzVeTHi7zM"),
		MAC:               hexBytes("9132e52f5eabdbf26ac3fa89f19ed55a43b83bea25bce4197d6b370243cd6357"),
	},
	"ecdsa-256.ppk": {
		Version:      3,
		Type:         "ecdsa-sha2-nistp256",
		Encryption:   NoEncryption,
		Comment:      "puTTY ecdsa-256",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPttHuSNO/1n89v5LSGEfxbw4JXLzqUEC7eVHALJ0KM34fR+VLzt48ydtOkUv8lrOLBdrtqtuzQ8yKC8WHctpy4="),
		PrivateBytes: b64Bytes("AAAAIQCViqRACSeX7KD1W6G44hfdXhzHi8hUFo0yEQpXr1z9/w=="),
		MAC:          hexBytes("58c73cd010152b3b481e24861e21f62895d3d8c9ca4e62a94dbb71998280421e"),
	},
	"ecdsa-384-enc.ppk": {
		Version:           3,
		Type:              "ecdsa-sha2-nistp384",
		Encryption:        AES256CBC,
		Comment:           "puTTY ecdsa-384 (encrypted)",
		PublicBytes:       b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBE6Tlb6Q8swPZkSlZmHDg5J+Xly6rZWbG74WcJSzYn/t7JxY5sbfIKnnkiREyUHeBzFonkZUGB5f36oOjrCGR4RouigJk4ifjbxoYHzMbxPvCkRj3IoNBI9XmcZULFPEmg=="),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("14d89509913418195109109f9a0a0e6f"),
		PrivateBytes:      b64Bytes("w158FyxS7yVbuMk0k90pv45jzU0+yBO61HfA+6wqCVgoPoxzXnAYceNipS424FVrX7+kyak1Dm5r2QCbxa6vmA=="),
		MAC:               hexBytes("1fe047d462c2c66a35153496995ee2b4de5724ce55ba560717ad526c6e825beb"),
	},
	"ecdsa-384.ppk": {
		Version:      3,
		Type:         "ecdsa-sha2-nistp384",
		Encryption:   NoEncryption,
		Comment:      "puTTY ecdsa-384",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBE6Tlb6Q8swPZkSlZmHDg5J+Xly6rZWbG74WcJSzYn/t7JxY5sbfIKnnkiREyUHeBzFonkZUGB5f36oOjrCGR4RouigJk4ifjbxoYHzMbxPvCkRj3IoNBI9XmcZULFPEmg=="),
		PrivateBytes: b64Bytes("AAAAMCxb64zVF2gwmh5yyGlRKBztay5Ggx24bgJoMxDY/ymh66dHF/c6Z/mmgMiOWC773Q=="),
		MAC:          hexBytes("ffbfbf95bb5fd16ae0ac8276db6a2e16963faa8a7b853b4d05184c2c26f08e41"),
	},
	"ecdsa-521-enc.ppk": {
		Version:           3,
		Type:              "ecdsa-sha2-nistp521",
		Encryption:        AES256CBC,
		Comment:           "puTTY ecdsa-521 (encrypted)",
		PublicBytes:       b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAtSEn7qdkJ+oNH0WSG96QnfiBYHHCaD9VgxM2RpFHCcnpJPnUx2tjtdvZb70L/A8vGf3GByF0EL4zNpVo4h6cynwCRA6nu/pY09RYHOUZJrgWO6VKbP1Q3f+dcJwe2eO1vJAERzAuGm8HKSCHP8qO+Z4mA34PGa+/3tYZF+cC3CcubUA=="),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("841045bf37d80a4f2f08c22610eb9345"),
		PrivateBytes:      b64Bytes("Na8sGVt4qRMQV6tJh6pk1Kq/QW7LdxLIQIZvHlWiJkHwDx8zidagR9qqX6EtKLKq3dHNFYTS9hqwD/el1XF0hRqKkDfCmbDIBwfeEOCTHYs="),
		MAC:               hexBytes("7e7867a918caace88f90da7209fc62ba141533cf4efcfb6a24622fe71a4edf63"),
	},
	"ecdsa-521.ppk": {
		Version:      3,
		Type:         "ecdsa-sha2-nistp521",
		Encryption:   NoEncryption,
		Comment:      "puTTY ecdsa-521",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAtSEn7qdkJ+oNH0WSG96QnfiBYHHCaD9VgxM2RpFHCcnpJPnUx2tjtdvZb70L/A8vGf3GByF0EL4zNpVo4h6cynwCRA6nu/pY09RYHOUZJrgWO6VKbP1Q3f+dcJwe2eO1vJAERzAuGm8HKSCHP8qO+Z4mA34PGa+/3tYZF+cC3CcubUA=="),
		PrivateBytes: b64Bytes("AAAAQgFEK57o9wmY8I1kheHvSkPZygDZgqyH1uhr7tIs8VrE77bNPimAnUlISz+AjBbwzXEHSCsAAmy3I3+V9Qg3z74LRw=="),
		MAC:          hexBytes("f0ea3ad7a8fc28a876e1669f84ec9ca4888964d2abbd72c58d70db2c21310028"),
	},
	"ed25519-enc.ppk": {
		Version:           3,
		Type:              "ssh-ed25519",
		Encryption:        AES256CBC,
		Comment:           "puTTY ed25519 (encrypted)",
		PublicBytes:       b64Bytes("AAAAC3NzaC1lZDI1NTE5AAAAIKXhz/ItWgiKEwTKJIGU6XP4+AFvzq05LV8A+iF/9HzV"),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("3f71960871109cf11f7a4241be234c0b"),
		PrivateBytes:      b64Bytes("5PaAorvpa1z45OxwOSv0NvI9g6nqV4gAc6JuuJkBusIuRPQFKfBMcyQA1Kyc5g7l"),
		MAC:               hexBytes("de1bd997f07ad8c0eb80280d5ad66a0145406a2d3103bca8865aa555a3dd695c"),
	},
	"ed25519.ppk": {
		Version:      3,
		Type:         "ssh-ed25519",
		Encryption:   NoEncryption,
		Comment:      "puTTY ed25519",
		PublicBytes:  b64Bytes("AAAAC3NzaC1lZDI1NTE5AAAAIKXhz/ItWgiKEwTKJIGU6XP4+AFvzq05LV8A+iF/9HzV"),
		PrivateBytes: b64Bytes("AAAAIBnjxkeAibiWW7Xk2RkJgSpiQTVT6Xlurz0RfU595BMr"),
		MAC:          hexBytes("724fa7d0be21914c3b5d1b7ecb4064aeadc5430858a9a917d9342c3d0af82bae"),
	},
	"ed448-enc.ppk": {
		Version:           3,
		Type:              "ssh-ed448",
		Encryption:        AES256CBC,
		Comment:           "puTTY ed448 (encrypted)",
		PublicBytes:       b64Bytes("AAAACXNzaC1lZDQ0OAAAADnGZahDNfrN0VGeMpVqa8A1ykqrVFBtwfUqan71eRgXX0J8q4oxUu/msMKLnjDNheeaQnOmcGQuKQA="),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("b56b1d4abeff269b8d476cb7edf198c8"),
		PrivateBytes:      b64Bytes("UEZzHU0dNgMAphWeoYKZCD+QMtPnzmUPcPU7InBpeB+nosqC/nVI6rXB9fpfma7X1TcncAEuB0KzhEcf4phX3Q=="),
		MAC:               hexBytes("56d2630c2c40a22ad00d6ae1467a277dd41d230720a1778298609316987bf35d"),
	},
	"ed448.ppk": {
		Version:      3,
		Type:         "ssh-ed448",
		Encryption:   NoEncryption,
		Comment:      "puTTY ed448",
		PublicBytes:  b64Bytes("AAAACXNzaC1lZDQ0OAAAADnGZahDNfrN0VGeMpVqa8A1ykqrVFBtwfUqan71eRgXX0J8q4oxUu/msMKLnjDNheeaQnOmcGQuKQA="),
		PrivateBytes: b64Bytes("AAAAOU/C3RbhPHdIEk5tvIo/kTFHHt67/DM+mGUqMTKZvJD3rEF7cB6/ck1KpmecKSvos/FRFjFXV0o9AA=="),
		MAC:          hexBytes("97a02ad2ffea360f534d8c9f3b91a1bddf7d81df7b02c1a9bf30d5eff0797e33"),
	},
	"extra-whitespace.ppk": {
		Version:      3,
		Type:         "ecdsa-sha2-nistp384",
		Encryption:   NoEncryption,
		Comment:      "puTTY ecdsa",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBNdPq2JQmWH2M+RtBETesYQnjqa21lB9+hs1QCZxUjdHtrIshzCnNXBrMP8JrPN8FymtMjfMBOpyFVN1/uigCEJSE9HwRGAa1Foa8kAO4iqck+0mbEvVwfSk7YrVkuG1Hg=="),
		PrivateBytes: b64Bytes("AAAAMEmsfBEBDIsYyDhTWhbOsRo/28QfRdu8LqJ55UYkCTlf1GGhaYBp8E3OtFK+fI9x2Q=="),
		MAC:          hexBytes("5987c49c9320ed655e53dacb52008fff73da8736fe243939090761adcf59e780"),
	},
	"rsa-2048-enc.ppk": {
		Version:           3,
		Type:              "ssh-rsa",
		Encryption:        AES256CBC,
		Comment:           "puTTY rsa-2048 (encrypted)",
		PublicBytes:       b64Bytes("AAAAB3NzaC1yc2EAAAADAQABAAABAQCZ3KLLsr/D+j9zL8pKMWTfhnaCely8/AuZH1Sn6co+psaVVDGFyQZpz/1MI2yiN8svinctkqtfIgQZV4b0LaX8bjJ82KVuK6E1VQT6pYvbvbDa2BidcbmoTvpR+qz6oxNqyUpaLEEbxC0N59glsgDP3jPkbKEQSWp4nvAHYy80372W96e2swPWFaxH1N8g4/ILhs3Ph++FcUv3C+hM87r8GdyV1BpmvRRkmTA2Z6bNr3BqMkY2fN6b78DzfPl2g0NkYSqccRjJkL3bQozOt8vOfCBeFnm73BoEsr6HtZq4a192mIqBXzdcljQqlDzJh1lhcvsxOI39HXsjrwg8Nzv/"),
		KeyDerivation:     Argon2id,
		Argon2Memory:      8192,
		Argon2Passes:      21,
		Argon2Parallelism: 1,
		Argon2Salt:        hexBytes("8108d158c1221c82ebc2b84ff824fcf2"),
		PrivateBytes:      b64Bytes("QSTtp45SFDbSPEKxziWDR0YoMV8WqwpMlmVQNVhf2LO9MdNTdJQlCobe7QlV/tuQ7Om/uTJVEMX1Dq9ss8TvdS8513FLLlPGroL65tsF3/V0J7qOi9SXpkRCZ3R51/sDFiZ6nB5/f6N7GIaFDxI5t07NTDsN80VOUYbjs84O5AHgWtuR06cD1CQrt3eDZt+lDwODMfmCugoU8b9lu32nc4mYFqMG0Qf8jKfMp/t60wJj2CIgb23DrC0fCLtgjwZS7Rb3pdZ8fxKFjftwOZq6dQZefySQByRR69XV2uKXuOuNl5pILtwNJXefGXNPNnV3DHCGAi7kkINux1JMFpqiVXOJ6zVyNZj7JFetyXmIY2P67QO91Tz66nttJGCL9DJ9U0gEP/IgANzG4Ub/vt6IKb1rQpZB4l42Z35EmVkKBIpBA4186uss+0PMGWFIEniQi2Q0mHfavCx5I0apYqTaTKauD90Yvk/bO/X+ZRzGx2ZAYTfQqrQIE4Ni4Sha9tIT/eXHrecLHb+mkNnYhWtyrdbfs0jzqtzJ85z135TXSw9XKtbF0FeITdZCrimcRqGGWYN1wM9JBf/CFkVtH8bCPAFYkluhiA4aD35a3HEXfXArcNK89eJgrkb0C1tMHAQt8pPNmaSxUcNGIgh7VB49OlyFHUGqUYbjSBgUTpWdBdcZjNfqu6A3O4ppnletozs9T7Gs53YoKqtegdvXkgPgt5Y49AzJGYWZR8AKWMq19tFfBRgX6FitVCYfClUmlieeBRiA+8fZ7xKn5+2x5sUrCt2JOo+LsD7ZxfFmwTsYIa3u03MsA0Tslsh9Gl3PKvDedMZN/+Sm03EtqvQtY4D58leIhRQryzvYw3X42dIbyzw58RO3A63ZtQUGqNjST6oQ"),
		MAC:               hexBytes("ff20e5e5273f1e6df0d5d39b8dd162acd2249987c87ff92d265d2e8a58cb0906"),
	},
	"rsa-2048.ppk": {
		Version:      3,
		Type:         "ssh-rsa",
		Encryption:   NoEncryption,
		Comment:      "puTTY rsa-2048",
		PublicBytes:  b64Bytes("AAAAB3NzaC1yc2EAAAADAQABAAABAQCZ3KLLsr/D+j9zL8pKMWTfhnaCely8/AuZH1Sn6co+psaVVDGFyQZpz/1MI2yiN8svinctkqtfIgQZV4b0LaX8bjJ82KVuK6E1VQT6pYvbvbDa2BidcbmoTvpR+qz6oxNqyUpaLEEbxC0N59glsgDP3jPkbKEQSWp4nvAHYy80372W96e2swPWFaxH1N8g4/ILhs3Ph++FcUv3C+hM87r8GdyV1BpmvRRkmTA2Z6bNr3BqMkY2fN6b78DzfPl2g0NkYSqccRjJkL3bQozOt8vOfCBeFnm73BoEsr6HtZq4a192mIqBXzdcljQqlDzJh1lhcvsxOI39HXsjrwg8Nzv/"),
		PrivateBytes: b64Bytes("AAABAD7bio6ZagqQc9eFEKma4FEJR+UqRDTY64wU5qrqsjtCOyLKkKjNZZdY52xxlHH5RUMY2HN/1g85gF8yCOo8s/Eau/mRMJR/so5tO2mCtE6DgnsFiZjY2zZNfap8NKr4cHhR39RS/A5x6M4jh4Ru4jIJ3z1Uu8BBngPFOt5pwOFiXEhuy7206E3De/1tBuJyQk7jNALFf60W4vtiaGi0l67jS3cqCc1NFEo/4CiOF0hXKwrfZyN1ulFoHTkKtVNLlT/TCX+U7579ROTx1hyq5hPx3X9i74brTyHk9NEggN77ZcKEXIfptxkj3oE/ftePAVnqHEtKnuLFakLMdPYWYIEAAACBANKwtOBTozi0KXapqHBVeOaEgrKNJegXajtx5lFBYnaWvIj8XeZiaPtEPfOoie+BjIaw616gfDELM3pgYTrJuCqki9AfzUPZHvbJfXzi4xrWs+yqmPv29VOhfs+jX20jxbGnDwc6F/3z97MS/3r0MB/ZoBFO8/VGV7lW7YT6yR2hAAAAgQC680/DAMNbz5mek1Iyo3pzczp29Fi2OlBETXxLumFvz2laAFRJ8C77+F5ZhXzg563FbYbBnlT+WW1xzP6UJTPPJoV2w5ApbO1GdwnRiX2UKRnTCpdp00E+2eEpciPxHll8VxlibCUjKRBniHbd9AjedTjp8msNHySiuQ1lK3u1nwAAAIA38rcEYOKjfwJDASdHE6zAJkyrpYPeDLgeRyhsU61zf1GYP0bbYrx9umksKKPzzM+GzqJ7twRjGzmC62RBEuPXPAYWt5MHl+tDVAY+2mSXOTpWQDLgmwUUsWY8robf4xerWl+g25xpnVssip1HV13vjsNDJDN3RDSCXJCK14dxHg=="),
		MAC:          hexBytes("09119d6eca748aca43b191696d2652e97efce97f3c05f8a6a0ebac54ab294cca"),
	},
	"v2-dsa-1024-enc.ppk": {
		Version:      2,
		Type:         "ssh-dss",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 dsa-1024 (encrypted)",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAACBAPomLalQzuF8G3/+A9sWHvuHeU6ze3+0VBvPMPRzlVTtBbV9uaTtrjnYK3f79qDFIlyQQBLuElNCu3Nbbgmc+6miDnV9cv0mpXubxFEZe0U5vam+VnmTUAu+t/sVjsEZhx9+zTIiWu3eGu/P3Eum7j97o68Rj+US2ya7ttiEfzFFAAAAFQDtWIiOTSrdXx1H6zhIfFHvAb0y3wAAAIEAkHIeImIJ+V3f1fbpLqHujFA4w/SWcaF+C+A+YN9R0k9gbcCRuz0eK/CpeBqtci7yAXq26QLmtADvSebBM9umb5uWYuXRwk5BqaYMk9MkeFe7tIu0xpOyyyhrC6Xz6AlwUTVxDJSp3WIKpxbreycxFC0sEqX8M5061Z/BpGjBDR0AAACBANcAqQUa9v9q0E8/w6YvSefwwCHDFTWAaQD4BU5NXZXa6Msw4jyr1tLCAjg3KniI/537ATlPgmZZAqTg3oIi7uSCGLRv79AVEa4JvNPC62nIh+2PejXMqy2axLimN3LQQq/3dxtmDvbKvh9zg7CgpTZ4zNjO3P08PPKD4CCVbZWT"),
		PrivateBytes: b64Bytes("dE5csgZMVHI2cJKD5d2Q4qTxc+eGB3kgeGw+qSiETJM="),
		MAC:          hexBytes("5e7ac790b53b8727e337f641108d2e7d2ee37baa"),
	},
	"v2-dsa-1024.ppk": {
		Version:      2,
		Type:         "ssh-dss",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 dsa-1024",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAACBAPomLalQzuF8G3/+A9sWHvuHeU6ze3+0VBvPMPRzlVTtBbV9uaTtrjnYK3f79qDFIlyQQBLuElNCu3Nbbgmc+6miDnV9cv0mpXubxFEZe0U5vam+VnmTUAu+t/sVjsEZhx9+zTIiWu3eGu/P3Eum7j97o68Rj+US2ya7ttiEfzFFAAAAFQDtWIiOTSrdXx1H6zhIfFHvAb0y3wAAAIEAkHIeImIJ+V3f1fbpLqHujFA4w/SWcaF+C+A+YN9R0k9gbcCRuz0eK/CpeBqtci7yAXq26QLmtADvSebBM9umb5uWYuXRwk5BqaYMk9MkeFe7tIu0xpOyyyhrC6Xz6AlwUTVxDJSp3WIKpxbreycxFC0sEqX8M5061Z/BpGjBDR0AAACBANcAqQUa9v9q0E8/w6YvSefwwCHDFTWAaQD4BU5NXZXa6Msw4jyr1tLCAjg3KniI/537ATlPgmZZAqTg3oIi7uSCGLRv79AVEa4JvNPC62nIh+2PejXMqy2axLimN3LQQq/3dxtmDvbKvh9zg7CgpTZ4zNjO3P08PPKD4CCVbZWT"),
		PrivateBytes: b64Bytes("AAAAFAcB0wFbZmQgkCGUNR8IDxQUzBBG"),
		MAC:          hexBytes("ebddce60d9349b3050592db49264811ad40df10c"),
	},
	"v2-dsa-2048-enc.ppk": {
		Version:      2,
		Type:         "ssh-dss",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 dsa-2048 (encrypted)",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAAEBAN/5G+eKaJyfIwpaB8/D8GpQwMKj64c3jQPa1+7rQgH6Z4+8gB7936WCglk71k2488b7yOSpYQoyJ3KyjJkS+R+F7N9amYlyI3DLfYDP5L2FbOJ7uhsd5Bb8OXv59m51j/4TvbkOz+7ADvt3M9GrkxOj9tbdGGLwVsXOy0joHpjZxkrNcVGRyXOgR7nVjAjd/ExuA9RYNznPgjUEhjG4jMNmZPPI6BLeCSOjw2iIv909XbsImdqWC/qAhWAoQhkO+9fsvrUBBK4vthjcf6SRRZN2TF+JLiQT/2ilpkew9OCY4b4UEHgLexEUuu/c7RDQyQKxvDU1vObgGIHIHym38B8AAAAVAKZV6uwKA89+mF+kudHLbqpDHkhdAAABAQCDOCjAfPr/j3C1nLdWRyVOdx/SKDtI1sqShOzoJMr46v0lrqkjKTBVYM1psBe1Irw3hcs+TCSp4XI8qO1LAr8y4B6/ohMU4+V5uQGzpImD50P/ctGrgG0Of6kO87wkeLw6SHMatThL98uTz5brWk0V+2uWwzdH2QBU5pTDeNeNZ8WkDwM+0vAKK9E7XPg5zfy+s0SY8LsTy5L99xAP0JJMpShtd8TaHX7m+6PLPsFlxG4swSC3XUEGiipBlaQCVE7OPZvcMC+ACbYQn0ThE+sfOMvn/aAKLh7OlH3mRFd4m7uo5b6l8JcXPe9wYPbQoNEEMV5ZAUejXS1+iVy7l6DMAAABAQC0zWJLKSNqQO4S1YPzUucy02d4ltDUvq+N1Iu3PCddCYUfyJE0T4gcW9snTF7/zxCp2lX/58cXejYxiAfLV1Orss/nmBOegaqbfYjd9y2PlMrxFCQIOQzCC3+qeuD+NSMh/i+MbYvcf5cWxL1MuS/+ng1NAZv3NsNvuJ09jrwKg5qEwfc2fwDQDfkN/dCwzq+Q/DpZCA02PIOwZpB/T5J5V1ZlCNOZ1Gp6JbpkQfkwurpN/zlCf7G6yUrH/xwEAddw9ViJpwdDjMwwgwpRL6h+JKjQJyusLONeFtAHbDJxt1L+aUCJXj8H9xNzpzpKj2gOCTC7L7/DL5Mpple73KqN"),
		PrivateBytes: b64Bytes("NUtwsIoG1IpmMDsXm0WbU2mJRFSinlZJ57iJBpI/O34="),
		MAC:          hexBytes("6cef25ef4f0c019049f3809316c64a64dde80753"),
	},
	"v2-dsa-2048.ppk": {
		Version:      2,
		Type:         "ssh-dss",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 dsa-2048",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAAEBAN/5G+eKaJyfIwpaB8/D8GpQwMKj64c3jQPa1+7rQgH6Z4+8gB7936WCglk71k2488b7yOSpYQoyJ3KyjJkS+R+F7N9amYlyI3DLfYDP5L2FbOJ7uhsd5Bb8OXv59m51j/4TvbkOz+7ADvt3M9GrkxOj9tbdGGLwVsXOy0joHpjZxkrNcVGRyXOgR7nVjAjd/ExuA9RYNznPgjUEhjG4jMNmZPPI6BLeCSOjw2iIv909XbsImdqWC/qAhWAoQhkO+9fsvrUBBK4vthjcf6SRRZN2TF+JLiQT/2ilpkew9OCY4b4UEHgLexEUuu/c7RDQyQKxvDU1vObgGIHIHym38B8AAAAVAKZV6uwKA89+mF+kudHLbqpDHkhdAAABAQCDOCjAfPr/j3C1nLdWRyVOdx/SKDtI1sqShOzoJMr46v0lrqkjKTBVYM1psBe1Irw3hcs+TCSp4XI8qO1LAr8y4B6/ohMU4+V5uQGzpImD50P/ctGrgG0Of6kO87wkeLw6SHMatThL98uTz5brWk0V+2uWwzdH2QBU5pTDeNeNZ8WkDwM+0vAKK9E7XPg5zfy+s0SY8LsTy5L99xAP0JJMpShtd8TaHX7m+6PLPsFlxG4swSC3XUEGiipBlaQCVE7OPZvcMC+ACbYQn0ThE+sfOMvn/aAKLh7OlH3mRFd4m7uo5b6l8JcXPe9wYPbQoNEEMV5ZAUejXS1+iVy7l6DMAAABAQC0zWJLKSNqQO4S1YPzUucy02d4ltDUvq+N1Iu3PCddCYUfyJE0T4gcW9snTF7/zxCp2lX/58cXejYxiAfLV1Orss/nmBOegaqbfYjd9y2PlMrxFCQIOQzCC3+qeuD+NSMh/i+MbYvcf5cWxL1MuS/+ng1NAZv3NsNvuJ09jrwKg5qEwfc2fwDQDfkN/dCwzq+Q/DpZCA02PIOwZpB/T5J5V1ZlCNOZ1Gp6JbpkQfkwurpN/zlCf7G6yUrH/xwEAddw9ViJpwdDjMwwgwpRL6h+JKjQJyusLONeFtAHbDJxt1L+aUCJXj8H9xNzpzpKj2gOCTC7L7/DL5Mpple73KqN"),
		PrivateBytes: b64Bytes("AAAAFH2OdOHeZ+8Zb1SfiM/vCYRuDj+W"),
		MAC:          hexBytes("4d0e5dbf11a3e2bbca6ce0d1c5ad15af8d4622b5"),
	},
	"v2-dsa-enc.ppk": {
		Version:      2,
		Type:         "ssh-dss",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 dsa (encrypted)",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAAEBAO8zr1aXeOLPaV81YeLaT3GKE9H5hJC+XYn8dXYqpcMalFzNCu+4seZhX34Jp3L+3h8htXvaH2t9TVZquAVR5lH53TnUyZXlwsWla4vAEuBPtAI2+WMTpyHfFdyZ7mzDbnytQ7FV8kliMwQrGXxQhn7RgRw4I7ubI7s8uBTW7YW/5PRBtclaW21zlYx9T4UkFFI3DYJhxpg3SAvlDBjXNOq2ezt/Z50U2tUf1tjOTohBMfSbfMox11GUYEqtXN8kAE96ix/0pJN9nTKWfggiOkb7Np5WnOd4nenYGJok35n917cuiBbIgpYLfg9X7QOs9vnqtndezqMQ75g724afYIsAAAAVAPoe7fawmIs1icFl0RQZwOVY/39PAAABAQDUgEs6mCVtd+Mg7MT5238O9W4Kw9Op79Sspn7caKaHXgvgn7Wf/CYv+78oAXOQIU2EvVKojJkssFqAPcbjSu1lYEEJ00alWTTyT4yQ9LhLuBLdmpNaXYj05BHwzh7LuDVv7CkWb4WVLLKoxBjiobCsmYprTGdgik67Dts7LdLCxMWesoafliOnF8Pe0KRen3CJLNCX+OPbCK8e2I0B5TeYIkVBn2/JFDamPkVFH9n/7p3pUrBmnwj6nSO7G1u4doN5ThkRXYv4InKatczjbqeoORLOCqS6BdvXKQoQN0o2g7IkqfZ513MnztCK/vP42PjdRoPzFy5UIDZZPv3v8CtbAAABAAiHfoKbaQj9leEZ1mHq8Nafy8b5jGKdcRYpV9LOXQYIoKrU9HpZYWwCXyQ1PSprg6vO2UvWTxt++BGhHQIt9uzGjS7STv7LyPeH/7tPwxb1Jz8J6sRI5CpxQdlCcTHzDNVHtI6/zK2EDPzDdBajCT4L/EpLjhEF4ftzWtaDkonAPHT303CHflNh9b0NDaddNqD1GlKk+zjcgBo/3RzjtWaGzmy8gxNFcC60o013OfI2ASe8hpwY0Q0VZLBJSjDKbzYa3YF+Zytid6ATo7MC+r5GbYy4sjnc+z6M21j2EI5Dq9NaIvaW27gFVxLumcVmguBa2gETnNUQlCtH/I85Etw="),
		PrivateBytes: b64Bytes("ZXSCRJWVv0H8Zz8JKcCEXCT1UU20PduWrll/998+S88="),
		MAC:          hexBytes("39ab70e71f06aeed091800ed8c1d904e57134f07"),
	},
	"v2-dsa.ppk": {
		Version:      2,
		Type:         "ssh-dss",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 dsa",
		PublicBytes:  b64Bytes("AAAAB3NzaC1kc3MAAAEBAO8zr1aXeOLPaV81YeLaT3GKE9H5hJC+XYn8dXYqpcMalFzNCu+4seZhX34Jp3L+3h8htXvaH2t9TVZquAVR5lH53TnUyZXlwsWla4vAEuBPtAI2+WMTpyHfFdyZ7mzDbnytQ7FV8kliMwQrGXxQhn7RgRw4I7ubI7s8uBTW7YW/5PRBtclaW21zlYx9T4UkFFI3DYJhxpg3SAvlDBjXNOq2ezt/Z50U2tUf1tjOTohBMfSbfMox11GUYEqtXN8kAE96ix/0pJN9nTKWfggiOkb7Np5WnOd4nenYGJok35n917cuiBbIgpYLfg9X7QOs9vnqtndezqMQ75g724afYIsAAAAVAPoe7fawmIs1icFl0RQZwOVY/39PAAABAQDUgEs6mCVtd+Mg7MT5238O9W4Kw9Op79Sspn7caKaHXgvgn7Wf/CYv+78oAXOQIU2EvVKojJkssFqAPcbjSu1lYEEJ00alWTTyT4yQ9LhLuBLdmpNaXYj05BHwzh7LuDVv7CkWb4WVLLKoxBjiobCsmYprTGdgik67Dts7LdLCxMWesoafliOnF8Pe0KRen3CJLNCX+OPbCK8e2I0B5TeYIkVBn2/JFDamPkVFH9n/7p3pUrBmnwj6nSO7G1u4doN5ThkRXYv4InKatczjbqeoORLOCqS6BdvXKQoQN0o2g7IkqfZ513MnztCK/vP42PjdRoPzFy5UIDZZPv3v8CtbAAABAAiHfoKbaQj9leEZ1mHq8Nafy8b5jGKdcRYpV9LOXQYIoKrU9HpZYWwCXyQ1PSprg6vO2UvWTxt++BGhHQIt9uzGjS7STv7LyPeH/7tPwxb1Jz8J6sRI5CpxQdlCcTHzDNVHtI6/zK2EDPzDdBajCT4L/EpLjhEF4ftzWtaDkonAPHT303CHflNh9b0NDaddNqD1GlKk+zjcgBo/3RzjtWaGzmy8gxNFcC60o013OfI2ASe8hpwY0Q0VZLBJSjDKbzYa3YF+Zytid6ATo7MC+r5GbYy4sjnc+z6M21j2EI5Dq9NaIvaW27gFVxLumcVmguBa2gETnNUQlCtH/I85Etw="),
		PrivateBytes: b64Bytes("AAAAFQCwWbQ7CKRGoo7/s+RE7urBeXM95A=="),
		MAC:          hexBytes("da3c994939cc0ca3f5f7ec56ae28f8fa2be11d51"),
	},
	"v2-ecdsa-256-enc.ppk": {
		Version:      2,
		Type:         "ecdsa-sha2-nistp256",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 ecdsa-256 (encrypted)",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPttHuSNO/1n89v5LSGEfxbw4JXLzqUEC7eVHALJ0KM34fR+VLzt48ydtOkUv8lrOLBdrtqtuzQ8yKC8WHctpy4="),
		PrivateBytes: b64Bytes("tF6YaMjSW2/mwP6l0PXFiP4o8pMF0fubBCMl/P9chWvCfeJPPEK6g8vUNSziYhvv"),
		MAC:          hexBytes("7c05f1c957851160a5a48c8ca7d7ca9ad5d4207b"),
	},
	"v2-ecdsa-256.ppk": {
		Version:      2,
		Type:         "ecdsa-sha2-nistp256",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 ecdsa-256",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPttHuSNO/1n89v5LSGEfxbw4JXLzqUEC7eVHALJ0KM34fR+VLzt48ydtOkUv8lrOLBdrtqtuzQ8yKC8WHctpy4="),
		PrivateBytes: b64Bytes("AAAAIQCViqRACSeX7KD1W6G44hfdXhzHi8hUFo0yEQpXr1z9/w=="),
		MAC:          hexBytes("94c7475829f80fe77418b59f969fe8ebb49f4507"),
	},
	"v2-ecdsa-384-enc.ppk": {
		Version:      2,
		Type:         "ecdsa-sha2-nistp384",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 ecdsa-384 (encrypted)",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBE6Tlb6Q8swPZkSlZmHDg5J+Xly6rZWbG74WcJSzYn/t7JxY5sbfIKnnkiREyUHeBzFonkZUGB5f36oOjrCGR4RouigJk4ifjbxoYHzMbxPvCkRj3IoNBI9XmcZULFPEmg=="),
		PrivateBytes: b64Bytes("ZT8+p9ZDKZ216z0rY1slhigeHmdYaiwDrXqA8ZZfw6Py2x1GBJ5zzNTx/xruSavkdPg7z1auAmv+sDsW+NlJwg=="),
		MAC:          hexBytes("3884e0be379c52a0ee0fcef9589d7d3c6e60dfb3"),
	},
	"v2-ecdsa-384.ppk": {
		Version:      2,
		Type:         "ecdsa-sha2-nistp384",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 ecdsa-384",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBE6Tlb6Q8swPZkSlZmHDg5J+Xly6rZWbG74WcJSzYn/t7JxY5sbfIKnnkiREyUHeBzFonkZUGB5f36oOjrCGR4RouigJk4ifjbxoYHzMbxPvCkRj3IoNBI9XmcZULFPEmg=="),
		PrivateBytes: b64Bytes("AAAAMCxb64zVF2gwmh5yyGlRKBztay5Ggx24bgJoMxDY/ymh66dHF/c6Z/mmgMiOWC773Q=="),
		MAC:          hexBytes("94afdeb1da64989756baf3efee2ef6e22c9c9af9"),
	},
	"v2-ecdsa-521-enc.ppk": {
		Version:      2,
		Type:         "ecdsa-sha2-nistp521",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 ecdsa-521 (encrypted)",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAtSEn7qdkJ+oNH0WSG96QnfiBYHHCaD9VgxM2RpFHCcnpJPnUx2tjtdvZb70L/A8vGf3GByF0EL4zNpVo4h6cynwCRA6nu/pY09RYHOUZJrgWO6VKbP1Q3f+dcJwe2eO1vJAERzAuGm8HKSCHP8qO+Z4mA34PGa+/3tYZF+cC3CcubUA=="),
		PrivateBytes: b64Bytes("+866UyshjOqWDpY+uzfWzYyr36C0Vz72OTDUVcywwldzuJVu+3jDx163Mv8vvYq9yxK8nF6u6jt8T0vvvo0/rrMb1RNLFGm+EXJwJypnQz0="),
		MAC:          hexBytes("145ec57c9d13c992b386dff35dc29c71de391821"),
	},
	"v2-ecdsa-521.ppk": {
		Version:      2,
		Type:         "ecdsa-sha2-nistp521",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 ecdsa-521",
		PublicBytes:  b64Bytes("AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAtSEn7qdkJ+oNH0WSG96QnfiBYHHCaD9VgxM2RpFHCcnpJPnUx2tjtdvZb70L/A8vGf3GByF0EL4zNpVo4h6cynwCRA6nu/pY09RYHOUZJrgWO6VKbP1Q3f+dcJwe2eO1vJAERzAuGm8HKSCHP8qO+Z4mA34PGa+/3tYZF+cC3CcubUA=="),
		PrivateBytes: b64Bytes("AAAAQgFEK57o9wmY8I1kheHvSkPZygDZgqyH1uhr7tIs8VrE77bNPimAnUlISz+AjBbwzXEHSCsAAmy3I3+V9Qg3z74LRw=="),
		MAC:          hexBytes("918243ee08be0280bcf35496b2cc0f72f233d927"),
	},
	"v2-ed25519-enc.ppk": {
		Version:      2,
		Type:         "ssh-ed25519",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 ed25519 (encrypted)",
		PublicBytes:  b64Bytes("AAAAC3NzaC1lZDI1NTE5AAAAIKXhz/ItWgiKEwTKJIGU6XP4+AFvzq05LV8A+iF/9HzV"),
		PrivateBytes: b64Bytes("Nuh6OsGcDJOkq/OqhvPxuGWMlTaKUidstEX59zGLEM14+YH5CESBQbtGO82nUyX2"),
		MAC:          hexBytes("849138a1341798fa1d4abee78a790fae2a2adce1"),
	},
	"v2-ed25519.ppk": {
		Version:      2,
		Type:         "ssh-ed25519",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 ed25519",
		PublicBytes:  b64Bytes("AAAAC3NzaC1lZDI1NTE5AAAAIKXhz/ItWgiKEwTKJIGU6XP4+AFvzq05LV8A+iF/9HzV"),
		PrivateBytes: b64Bytes("AAAAIBnjxkeAibiWW7Xk2RkJgSpiQTVT6Xlurz0RfU595BMr"),
		MAC:          hexBytes("49588301852af77753557ad4b4916f70d6d57022"),
	},
	"v2-ed448-enc.ppk": {
		Version:      2,
		Type:         "ssh-ed448",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 ed448 (encrypted)",
		PublicBytes:  b64Bytes("AAAACXNzaC1lZDQ0OAAAADnGZahDNfrN0VGeMpVqa8A1ykqrVFBtwfUqan71eRgXX0J8q4oxUu/msMKLnjDNheeaQnOmcGQuKQA="),
		PrivateBytes: b64Bytes("XR8VDIitaAn5wDfSCel9wZVnomn7HzxCIqTHatruVpbwK7EOkcUctwQVBWuBJoMvDolV2Agpfpil0Vr7ceDUPA=="),
		MAC:          hexBytes("18990cc7a170abfe1f8d28d0dccdc40a05d04329"),
	},
	"v2-ed448.ppk": {
		Version:      2,
		Type:         "ssh-ed448",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 ed448",
		PublicBytes:  b64Bytes("AAAACXNzaC1lZDQ0OAAAADnGZahDNfrN0VGeMpVqa8A1ykqrVFBtwfUqan71eRgXX0J8q4oxUu/msMKLnjDNheeaQnOmcGQuKQA="),
		PrivateBytes: b64Bytes("AAAAOU/C3RbhPHdIEk5tvIo/kTFHHt67/DM+mGUqMTKZvJD3rEF7cB6/ck1KpmecKSvos/FRFjFXV0o9AA=="),
		MAC:          hexBytes("b6ae44ff3bfc0ef6468925730092003d4c790db2"),
	},
	"v2-rsa-2048-enc.ppk": {
		Version:      2,
		Type:         "ssh-rsa",
		Encryption:   AES256CBC,
		Comment:      "puTTY v2 rsa-2048 (encrypted)",
		PublicBytes:  b64Bytes("AAAAB3NzaC1yc2EAAAADAQABAAABAQCZ3KLLsr/D+j9zL8pKMWTfhnaCely8/AuZH1Sn6co+psaVVDGFyQZpz/1MI2yiN8svinctkqtfIgQZV4b0LaX8bjJ82KVuK6E1VQT6pYvbvbDa2BidcbmoTvpR+qz6oxNqyUpaLEEbxC0N59glsgDP3jPkbKEQSWp4nvAHYy80372W96e2swPWFaxH1N8g4/ILhs3Ph++FcUv3C+hM87r8GdyV1BpmvRRkmTA2Z6bNr3BqMkY2fN6b78DzfPl2g0NkYSqccRjJkL3bQozOt8vOfCBeFnm73BoEsr6HtZq4a192mIqBXzdcljQqlDzJh1lhcvsxOI39HXsjrwg8Nzv/"),
		PrivateBytes: b64Bytes("SXbbFDhZKtycfBx1E9IL93ZCb79i55ZkMbZMj+1F7OK04eyTUCOvUhnON0XMPR9fz1TnWML7B4Co1UJ5N0SLZi5js5B+e2jHWxV6B7e75CGk0dGwxonjf9aW0f7Rmvu1rhDzNYIIhUEOQLDqyHNsTKBHSv/f/cCXUZM6vySvYFN3oGq9goyNbc7rRdyPQiYoZgr0fU3B+9qFZ88sj3bISS8LLdx/uCassjvsCaxzMX5U8hohNzuydWAWtWuNPMknSAzMg2QWbRaQRpkBd5Pnqr5Xhn33MAg47vP0EaQXLtFbMdedc7Aziwois90JyIrhSBMLhyr7r00zUFo5gp5v6fTGqYGPwppOQzn0pzWK2LdInSraRz9r+LUoAylMywUhXlScBwCGGOLtm9t9r7OqnEMCZLTb0XVA+y6tuQgy0ExRPNqV5vFGkyAtmq1YvQgUo3M7WeS0yt0EdC4PTa400FxHhzNy78wGFhO5GE8c4DjPHPSR52OMMn4JMe9AP3Tv4yBNef83WxqRTqjgxsYnaIqcPQyvIpRNJBq/sTtzPPyXvrqMIE1nQ34Z7flkE7bo3lD6AUwgR4nGXnAgK3SB/sxAcW9vfdKUEIVrUfTxRjoiurWygr+s4c8oP6ulo5JFADJxjNFxFzLaadjytlC9tySoFzseo4cEvPpAgc1irQdBGrIztKOhHdXMrGoMUG5Fkli16MPjG6ZpfaEK4QQfwFjQJYNVwpO//7+OteGw2Gl8xIT2Y7Wrh2TAT5H5IYThIV4Te7rV3mI9KbmF5E8QeNqJbVWmU2gaWgRv755IJ0S6FkBWQyovqrv9joZpxYdLRSXf26lo2xXKT7T6uT/IA8ZoiTencBeeYinePmdDpzndvfF3QR3s7wvWc+M3Ah5g"),
		MAC:          hexBytes("b8ae90449bf6ce8d24772d53acdb614a8bbddfc0"),
	},
	"v2-rsa-2048.ppk": {
		Version:      2,
		Type:         "ssh-rsa",
		Encryption:   NoEncryption,
		Comment:      "puTTY v2 rsa-2048",
		PublicBytes:  b64Bytes("AAAAB3NzaC1yc2EAAAADAQABAAABAQCZ3KLLsr/D+j9zL8pKMWTfhnaCely8/AuZH1Sn6co+psaVVDGFyQZpz/1MI2yiN8svinctkqtfIgQZV4b0LaX8bjJ82KVuK6E1VQT6pYvbvbDa2BidcbmoTvpR+qz6oxNqyUpaLEEbxC0N59glsgDP3jPkbKEQSWp4nvAHYy80372W96e2swPWFaxH1N8g4/ILhs3Ph++FcUv3C+hM87r8GdyV1BpmvRRkmTA2Z6bNr3BqMkY2fN6b78DzfPl2g0NkYSqccRjJkL3bQozOt8vOfCBeFnm73BoEsr6HtZq4a192mIqBXzdcljQqlDzJh1lhcvsxOI39HXsjrwg8Nzv/"),
		PrivateBytes: b64Bytes("AAABAD7bio6ZagqQc9eFEKma4FEJR+UqRDTY64wU5qrqsjtCOyLKkKjNZZdY52xxlHH5RUMY2HN/1g85gF8yCOo8s/Eau/mRMJR/so5tO2mCtE6DgnsFiZjY2zZNfap8NKr4cHhR39RS/A5x6M4jh4Ru4jIJ3z1Uu8BBngPFOt5pwOFiXEhuy7206E3De/1tBuJyQk7jNALFf60W4vtiaGi0l67jS3cqCc1NFEo/4CiOF0hXKwrfZyN1ulFoHTkKtVNLlT/TCX+U7579ROTx1hyq5hPx3X9i74brTyHk9NEggN77ZcKEXIfptxkj3oE/ftePAVnqHEtKnuLFakLMdPYWYIEAAACBANKwtOBTozi0KXapqHBVeOaEgrKNJegXajtx5lFBYnaWvIj8XeZiaPtEPfOoie+BjIaw616gfDELM3pgYTrJuCqki9AfzUPZHvbJfXzi4xrWs+yqmPv29VOhfs+jX20jxbGnDwc6F/3z97MS/3r0MB/ZoBFO8/VGV7lW7YT6yR2hAAAAgQC680/DAMNbz5mek1Iyo3pzczp29Fi2OlBETXxLumFvz2laAFRJ8C77+F5ZhXzg563FbYbBnlT+WW1xzP6UJTPPJoV2w5ApbO1GdwnRiX2UKRnTCpdp00E+2eEpciPxHll8VxlibCUjKRBniHbd9AjedTjp8msNHySiuQ1lK3u1nwAAAIA38rcEYOKjfwJDASdHE6zAJkyrpYPeDLgeRyhsU61zf1GYP0bbYrx9umksKKPzzM+GzqJ7twRjGzmC62RBEuPXPAYWt5MHl+tDVAY+2mSXOTpWQDLgmwUUsWY8robf4xerWl+g25xpnVssip1HV13vjsNDJDN3RDSCXJCK14dxHg=="),
		MAC:          hexBytes("c534eb060e89b186f5d60c4b084051979cafc5aa"),
	},
}

var keypairs = map[string]crypto.PrivateKey{
	"dsa-1024.ppk":         dsa1024,
	"dsa-1024-enc.ppk":     dsa1024,
	"dsa-2048.ppk":         dsa2048,
	"dsa-2048-enc.ppk":     dsa2048,
	"ecdsa-256.ppk":        loadOpenSSHPrivateKey("id_ecdsa-256"),
	"ecdsa-256-enc.ppk":    loadOpenSSHPrivateKey("id_ecdsa-256"),
	"ecdsa-384.ppk":        loadOpenSSHPrivateKey("id_ecdsa-384"),
	"ecdsa-384-enc.ppk":    loadOpenSSHPrivateKey("id_ecdsa-384"),
	"ecdsa-521.ppk":        loadOpenSSHPrivateKey("id_ecdsa-521"),
	"ecdsa-521-enc.ppk":    loadOpenSSHPrivateKey("id_ecdsa-521"),
	"ed25519.ppk":          loadOpenSSHPrivateKey("id_ed25519"),
	"ed25519-enc.ppk":      loadOpenSSHPrivateKey("id_ed25519"),
	"rsa-2048.ppk":         loadOpenSSHPrivateKey("id_rsa-2048"),
	"rsa-2048-enc.ppk":     loadOpenSSHPrivateKey("id_rsa-2048"),
	"v2-ecdsa-256.ppk":     loadOpenSSHPrivateKey("id_ecdsa-256"),
	"v2-ecdsa-256-enc.ppk": loadOpenSSHPrivateKey("id_ecdsa-256"),
	"v2-ecdsa-384.ppk":     loadOpenSSHPrivateKey("id_ecdsa-384"),
	"v2-ecdsa-384-enc.ppk": loadOpenSSHPrivateKey("id_ecdsa-384"),
	"v2-ecdsa-521.ppk":     loadOpenSSHPrivateKey("id_ecdsa-521"),
	"v2-ecdsa-521-enc.ppk": loadOpenSSHPrivateKey("id_ecdsa-521"),
	"v2-ed25519.ppk":       loadOpenSSHPrivateKey("id_ed25519"),
	"v2-ed25519-enc.ppk":   loadOpenSSHPrivateKey("id_ed25519"),
	"v2-rsa-2048.ppk":      loadOpenSSHPrivateKey("id_rsa-2048"),
	"v2-rsa-2048-enc.ppk":  loadOpenSSHPrivateKey("id_rsa-2048"),
}

func loadOpenSSHPrivateKey(f string) crypto.PrivateKey {
	data, err := os.ReadFile("testdata/" + f)
	if err != nil {
		panic(err)
	}
	k, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		panic(err)
	}
	if edk, ok := k.(*ed25519.PrivateKey); ok {
		return *edk
	}
	return k
}

var dsa1024 = &dsa.PrivateKey{
	PublicKey: dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: bigInt("175660695824421458782883231858410328994990972767894207260607221802794228935053531823970966360255700776238924785963384031234605906538796560444527402741049492760570626145603910987051286942388302595282053826789390596810243853131924806230751697217491048138866888711269377148315166118607037003460819482295247253829"),
			Q: bigInt("1355005173956276606338272835556284160986723463903"),
			G: bigInt("101433270799635330343793736457679851051076368100374713553137429362745150693921214788736700254201392192149432727108079456625652989667787184091441185707637217945020251588694935423395531994509834305619950098325860077694970879567195469837871960760320458951468697304963604320101701539803432945483421541018374311197"),
		},
		Y: bigInt("150979945436436212152326169665226437788227020979957965885732028520379493167745516505323231503831667354692601030789701910803876923379228054738757705799064864056854989397852901768306321698798987839919279779393145150341678890530817019979162947476799317748166691011914744782869125415210109440916658606517521323411"),
	},
	X: bigInt("40003617295070768342620342301359831900471693382"),
}

var dsa2048 = &dsa.PrivateKey{
	PublicKey: dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: bigInt("28273982234526787901214915970333553546011528472907922926784877270588096213945070508481334205798175112988430262618994427122111146497516032047093726593185228560387898560013287143171139581612760018439778705423732382879460663424714824245629219392233527462747028170866698454418757967576407482836648995285409022654089242753092569875521743008295668536385109922576447591974723594544636985869409985310253783261086304429174624563470251489165863742309998565572481659379822349665778936062942952764537364554643847757948729730705670705134850076825509537297764260288175310605459926587149633196536017603341049528666975711114993070111"),
			Q: bigInt("949608495893491154566043650363114766513328769117"),
			G: bigInt("16564911077867882501985171517608544710619333662511682155117475531728949647713508940939135720018211474320437657391316723552590364727323118422147422616131724820577188159005238511608602483563977468477951700876755002131440070347013193696523899103063436894154887233566148476996937335344205537631522727316335905721763302960541005991822706516817644744249759412898311724349578723243592637896873618002189024297915581719746985696540017399691448929851404956810264529714286022557562709624784721946525226432321333215172284614477304371726635099844343696530364215610871615569003712158307884430688104250598992922086433575326707065036"),
		},
		Y: bigInt("22824173498956871363565842192568000936636510793165072418139555750712969968877446540227959957353218487470215138856350465772462391013603686067530449051880411528359765153604698721678752504771257398135858767347042876750145175802972174951187919695499334139840883183581836163892741232086363184198423262323961541635180761030269564816341823972594575293519143369524590477069709599060149442970710070428625120880594063575193895468485895472395014584691697777102830848626728898536661349540541596840603560198079022548049533883352541739054631062847644243574917381130719873225242187430574839108920191877515726222686212556993316301453"),
	},
	X: bigInt("716800734055500201566741230226344279924565491606"),
}

func bigInt(s string) *big.Int {
	i, _ := big.NewInt(0).SetString(s, 10)
	return i
}
