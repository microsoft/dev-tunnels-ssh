// Copyright (c) Microsoft Corporation. All rights reserved.

package sshio

import "math/big"

// BigIntToSSHBytes converts a *big.Int to SSH mpint wire format bytes.
//
// Per RFC 4251 section 5, an mpint is stored as a two's complement big-endian
// integer with the minimum number of bytes. Positive values with the high bit
// set in the most significant byte are padded with a leading 0x00 byte to
// distinguish them from negative values.
//
// Returns a single 0x00 byte for zero (the caller should write uint32(0)
// with no data bytes for the wire format).
func BigIntToSSHBytes(n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return []byte{0}
	}

	if n.Sign() > 0 {
		b := n.Bytes() // unsigned big-endian, no leading zeros
		if b[0]&0x80 != 0 {
			// Prepend zero byte so the value isn't interpreted as negative.
			return append([]byte{0x00}, b...)
		}
		return b
	}

	// Negative: two's complement representation.
	// Compute abs(n) - 1, then complement all bits.
	abs := new(big.Int).Abs(n)
	abs.Sub(abs, big.NewInt(1))
	absBytes := abs.Bytes()

	if len(absBytes) == 0 {
		// n == -1: abs(n)-1 == 0, complemented is 0xFF
		return []byte{0xFF}
	}

	result := make([]byte, len(absBytes))
	for i, b := range absBytes {
		result[i] = ^b
	}

	// Ensure the high bit is set to indicate a negative number.
	if result[0]&0x80 == 0 {
		result = append([]byte{0xFF}, result...)
	}

	return result
}

// SSHBytesToBigInt converts SSH mpint wire format bytes to a *big.Int.
//
// The input is interpreted as a signed two's complement big-endian integer
// per RFC 4251. If the high bit of the first byte is set, the value is negative.
func SSHBytesToBigInt(data []byte) *big.Int {
	if len(data) == 0 {
		return new(big.Int)
	}

	n := new(big.Int)
	if data[0]&0x80 != 0 {
		// Negative number: complement all bits, interpret as positive, add 1, negate.
		complemented := make([]byte, len(data))
		for i, b := range data {
			complemented[i] = ^b
		}
		n.SetBytes(complemented)
		n.Add(n, big.NewInt(1))
		n.Neg(n)
	} else {
		// Positive number. SetBytes handles leading zeros correctly.
		n.SetBytes(data)
	}
	return n
}
