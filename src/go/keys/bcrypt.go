// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

// bcrypt PBKDF implementation for OpenSSH key encryption.
// This is the bcrypt-based key derivation function used by OpenSSH,
// NOT the standard bcrypt password hashing.

import (
	"crypto/sha512"
	"encoding/binary"
)

// bcryptPbkdf derives key material from a password using the bcrypt PBKDF algorithm.
// This matches the OpenSSH implementation of bcrypt_pbkdf, which distributes output
// bytes in a strided (non-linear) fashion that differs from standard PBKDF2.
func bcryptPbkdf(password, salt []byte, rounds, keyLen int) []byte {
	numBlocks := (keyLen + 31) / 32 // bcrypt output = 32 bytes
	stride := numBlocks
	key := make([]byte, keyLen)

	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	for block := 1; block <= numBlocks; block++ {
		// SHA-512(salt || uint32(block))
		h.Reset()
		h.Write(salt)
		blockBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(blockBytes, uint32(block))
		h.Write(blockBytes)
		shasalt := h.Sum(nil)

		out := bcryptHash(shapass, shasalt)
		result := make([]byte, 32)
		copy(result, out)

		for i := 1; i < rounds; i++ {
			h.Reset()
			h.Write(out)
			shasalt = h.Sum(nil)

			out = bcryptHash(shapass, shasalt)
			for j := range result {
				result[j] ^= out[j]
			}
		}

		// OpenSSH deviation: distribute output bytes in strided pattern.
		// Byte i from block goes to position i*stride + (block-1).
		for i := 0; i < 32; i++ {
			dest := i*stride + (block - 1)
			if dest >= keyLen {
				break
			}
			key[dest] = result[i]
		}
	}

	return key
}

// bcryptHash performs one bcrypt hash operation on shapass and shasalt.
// It uses the Blowfish cipher internally. This is the "bcrypt_hash" function from OpenSSH.
func bcryptHash(shapass, shasalt []byte) []byte {
	// Initialize Blowfish with the "OxychromaticBlowworkerGiggling" ctext.
	bf := newBlowfish()

	// Expand key with salt and password.
	bf.expandKeyWithSalt(shasalt, shapass)

	for i := 0; i < 64; i++ {
		bf.expandKey(shasalt)
		bf.expandKey(shapass)
	}

	// "OxychromaticBlowfishSwatDynamworkerGiggling\x00" = ciphertext constant
	cdata := []uint32{
		0x4f787963, 0x68726f6d, 0x61746963, 0x426c6f77,
		0x66697368, 0x53776174, 0x44796e61, 0x6d697465,
	}

	for i := 0; i < 64; i++ {
		for j := 0; j < len(cdata); j += 2 {
			bf.encrypt(&cdata[j], &cdata[j+1])
		}
	}

	out := make([]byte, 32)
	for i, v := range cdata {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}

// blowfish implements the Blowfish block cipher for bcrypt operations.
type blowfish struct {
	p [18]uint32
	s [4][256]uint32
}

func newBlowfish() *blowfish {
	bf := &blowfish{}
	copy(bf.p[:], p0[:])
	copy(bf.s[0][:], s0[:])
	copy(bf.s[1][:], s1[:])
	copy(bf.s[2][:], s2[:])
	copy(bf.s[3][:], s3[:])
	return bf
}

func (bf *blowfish) encrypt(l, r *uint32) {
	xl, xr := *l, *r
	for i := 0; i < 16; i += 2 {
		xl ^= bf.p[i]
		xr ^= bf.f(xl)
		xr ^= bf.p[i+1]
		xl ^= bf.f(xr)
	}
	xl ^= bf.p[16]
	xr ^= bf.p[17]
	*l = xr
	*r = xl
}

func (bf *blowfish) f(x uint32) uint32 {
	a := bf.s[0][byte(x>>24)]
	b := bf.s[1][byte(x>>16)]
	c := bf.s[2][byte(x>>8)]
	d := bf.s[3][byte(x)]
	return ((a + b) ^ c) + d
}

func (bf *blowfish) expandKey(key []byte) {
	j := 0
	for i := 0; i < 18; i++ {
		var data uint32
		for k := 0; k < 4; k++ {
			data = (data << 8) | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		bf.p[i] ^= data
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		bf.encrypt(&l, &r)
		bf.p[i] = l
		bf.p[i+1] = r
	}

	for i := 0; i < 4; i++ {
		for j := 0; j < 256; j += 2 {
			bf.encrypt(&l, &r)
			bf.s[i][j] = l
			bf.s[i][j+1] = r
		}
	}
}

func (bf *blowfish) expandKeyWithSalt(salt, key []byte) {
	j := 0
	for i := 0; i < 18; i++ {
		var data uint32
		for k := 0; k < 4; k++ {
			data = (data << 8) | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		bf.p[i] ^= data
	}

	var l, r uint32
	sj := 0
	for i := 0; i < 18; i += 2 {
		l ^= readBigEndianFromCyclic(salt, &sj)
		r ^= readBigEndianFromCyclic(salt, &sj)
		bf.encrypt(&l, &r)
		bf.p[i] = l
		bf.p[i+1] = r
	}

	for i := 0; i < 4; i++ {
		for j := 0; j < 256; j += 2 {
			l ^= readBigEndianFromCyclic(salt, &sj)
			r ^= readBigEndianFromCyclic(salt, &sj)
			bf.encrypt(&l, &r)
			bf.s[i][j] = l
			bf.s[i][j+1] = r
		}
	}
}

func readBigEndianFromCyclic(data []byte, pos *int) uint32 {
	var result uint32
	for i := 0; i < 4; i++ {
		result = (result << 8) | uint32(data[*pos])
		*pos++
		if *pos >= len(data) {
			*pos = 0
		}
	}
	return result
}
