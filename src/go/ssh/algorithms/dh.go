// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// RFC 3526 Oakley group primes.
var (
	oakley2048 *big.Int // Group 14
	oakley4096 *big.Int // Group 16
)

func init() {
	oakley2048, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D6"+
			"70C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE"+
			"39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9D"+
			"E2BCBF6955817183995497CEA956AE515D2261898FA05101"+
			"5728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

	oakley4096, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D6"+
			"70C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE"+
			"39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9D"+
			"E2BCBF6955817183995497CEA956AE515D2261898FA05101"+
			"5728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64E"+
			"CFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7A"+
			"BF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF"+
			"12FFA06D98A0864D87602733EC86A64521F2B18177B200CB"+
			"BE117577A615D6C770988C0BAD946E208E24FA074E5AB314"+
			"3DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D78"+
			"8719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2"+
			"583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA62"+
			"87C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1"+
			"F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA99"+
			"3B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93406319"+
			"9FFFFFFFFFFFFFFFF", 16)
}

// NewDHGroup14SHA256 creates a DH group 14 (2048-bit) key exchange algorithm with SHA-256.
func NewDHGroup14SHA256() *KeyExchangeAlgorithm {
	return &KeyExchangeAlgorithm{
		Name:              "diffie-hellman-group14-sha256",
		KeySizeInBits:     2048,
		HashAlgorithmName: "SHA-256",
		HashDigestLength:  32,
		createFunc: func() (KeyExchange, error) {
			return newDHKeyExchange(oakley2048, sha256.New)
		},
	}
}

// NewDHGroup16SHA512 creates a DH group 16 (4096-bit) key exchange algorithm with SHA-512.
func NewDHGroup16SHA512() *KeyExchangeAlgorithm {
	return &KeyExchangeAlgorithm{
		Name:              "diffie-hellman-group16-sha512",
		KeySizeInBits:     4096,
		HashAlgorithmName: "SHA-512",
		HashDigestLength:  64,
		createFunc: func() (KeyExchange, error) {
			return newDHKeyExchange(oakley4096, sha512.New)
		},
	}
}

// dhKeyExchange is a stateful DH key exchange instance.
type dhKeyExchange struct {
	p    *big.Int
	g    *big.Int
	x    *big.Int // private exponent
	hash hash.Hash
}

func newDHKeyExchange(p *big.Int, hashFunc func() hash.Hash) (*dhKeyExchange, error) {
	// Generate random exponent (80 bytes = 640 bits, same as C#).
	xBytes := make([]byte, 80)
	if _, err := rand.Read(xBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random exponent: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)

	return &dhKeyExchange{
		p:    p,
		g:    big.NewInt(2),
		x:    x,
		hash: hashFunc(),
	}, nil
}

func (kex *dhKeyExchange) DigestLength() int {
	return kex.hash.Size()
}

func (kex *dhKeyExchange) StartKeyExchange() ([]byte, error) {
	// y = g^x mod p
	y := new(big.Int).Exp(kex.g, kex.x, kex.p)
	return sshio.BigIntToSSHBytes(y), nil
}

func (kex *dhKeyExchange) DecryptKeyExchange(exchangeValue []byte) ([]byte, error) {
	// Parse the remote party's public value from SSH mpint bytes.
	f := sshio.SSHBytesToBigInt(exchangeValue)

	// Validate the peer's public value per RFC 4253 Section 8:
	// the value must satisfy 2 <= f <= p-2 to prevent small subgroup attacks.
	two := big.NewInt(2)
	pMinusTwo := new(big.Int).Sub(kex.p, two)
	if f.Cmp(two) < 0 || f.Cmp(pMinusTwo) > 0 {
		return nil, fmt.Errorf("invalid DH public value: must be in range [2, p-2]")
	}

	// z = f^x mod p (shared secret)
	z := new(big.Int).Exp(f, kex.x, kex.p)
	return sshio.BigIntToSSHBytes(z), nil
}

func (kex *dhKeyExchange) Sign(data []byte) ([]byte, error) {
	kex.hash.Reset()
	kex.hash.Write(data)
	return kex.hash.Sum(nil), nil
}
