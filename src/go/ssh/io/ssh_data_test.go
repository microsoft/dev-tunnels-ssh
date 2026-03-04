// Copyright (c) Microsoft Corporation. All rights reserved.

package sshio

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"
)

func TestRoundTripByte(t *testing.T) {
	values := []byte{0, 1, 42, 127, 128, 255}
	for _, v := range values {
		w := NewSSHDataWriter(make([]byte, 0))
		_ = w.WriteByte(v)

		r := NewSSHDataReader(w.ToBuffer())
		got, err := r.ReadByte()
		if err != nil {
			t.Fatalf("ReadByte(%d) error: %v", v, err)
		}
		if got != v {
			t.Errorf("byte round-trip: got %d, want %d", got, v)
		}
		if r.Available() != 0 {
			t.Errorf("expected 0 available, got %d", r.Available())
		}
	}
}

func TestRoundTripBoolean(t *testing.T) {
	for _, v := range []bool{true, false} {
		w := NewSSHDataWriter(make([]byte, 0))
		w.WriteBoolean(v)

		r := NewSSHDataReader(w.ToBuffer())
		got, err := r.ReadBoolean()
		if err != nil {
			t.Fatalf("ReadBoolean(%v) error: %v", v, err)
		}
		if got != v {
			t.Errorf("bool round-trip: got %v, want %v", got, v)
		}
	}
}

func TestRoundTripUInt32(t *testing.T) {
	values := []uint32{0, 1, 255, 256, 65535, 65536, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}
	for _, v := range values {
		w := NewSSHDataWriter(make([]byte, 0))
		w.WriteUInt32(v)

		buf := w.ToBuffer()
		if len(buf) != 4 {
			t.Fatalf("uint32 buffer length: got %d, want 4", len(buf))
		}

		r := NewSSHDataReader(buf)
		got, err := r.ReadUInt32()
		if err != nil {
			t.Fatalf("ReadUInt32(%d) error: %v", v, err)
		}
		if got != v {
			t.Errorf("uint32 round-trip: got %d, want %d", got, v)
		}
	}
}

func TestUInt32BigEndian(t *testing.T) {
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteUInt32(0x01020304)
	buf := w.ToBuffer()
	expected := []byte{0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(buf, expected) {
		t.Errorf("uint32 big-endian: got %v, want %v", buf, expected)
	}
}

func TestRoundTripUInt64(t *testing.T) {
	values := []uint64{
		0, 1, 0xFF, 0x100, 0xFFFF, 0x10000,
		0xFFFFFFFF, 0x100000000,
		0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
		0xFFFFFFFFFFFFFFFF,
	}
	for _, v := range values {
		w := NewSSHDataWriter(make([]byte, 0))
		w.WriteUInt64(v)

		buf := w.ToBuffer()
		if len(buf) != 8 {
			t.Fatalf("uint64 buffer length: got %d, want 8", len(buf))
		}

		r := NewSSHDataReader(buf)
		got, err := r.ReadUInt64()
		if err != nil {
			t.Fatalf("ReadUInt64(%d) error: %v", v, err)
		}
		if got != v {
			t.Errorf("uint64 round-trip: got %d, want %d", got, v)
		}
	}
}

func TestUInt64BigEndian(t *testing.T) {
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteUInt64(0x0102030405060708)
	buf := w.ToBuffer()
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(buf, expected) {
		t.Errorf("uint64 big-endian: got %v, want %v", buf, expected)
	}
}

func TestRoundTripString(t *testing.T) {
	values := []string{"", "hello", "test string with spaces", "日本語"}
	for _, v := range values {
		w := NewSSHDataWriter(make([]byte, 0))
		w.WriteString(v)

		r := NewSSHDataReader(w.ToBuffer())
		got, err := r.ReadString()
		if err != nil {
			t.Fatalf("ReadString(%q) error: %v", v, err)
		}
		if got != v {
			t.Errorf("string round-trip: got %q, want %q", got, v)
		}
	}
}

func TestStringWireFormat(t *testing.T) {
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteString("test")
	buf := w.ToBuffer()
	// uint32 length (4) + "test" bytes
	expected := []byte{0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't'}
	if !bytes.Equal(buf, expected) {
		t.Errorf("string wire format: got %v, want %v", buf, expected)
	}
}

func TestRoundTripBinary(t *testing.T) {
	values := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x01, 0x02, 0x03, 0x04},
		bytes.Repeat([]byte{0xAB}, 256),
	}
	for i, v := range values {
		w := NewSSHDataWriter(make([]byte, 0))
		w.WriteBinary(v)

		r := NewSSHDataReader(w.ToBuffer())
		got, err := r.ReadBinary()
		if err != nil {
			t.Fatalf("ReadBinary(case %d) error: %v", i, err)
		}
		if !bytes.Equal(got, v) {
			t.Errorf("binary round-trip case %d: got %v, want %v", i, got, v)
		}
	}
}

func TestRoundTripNameList(t *testing.T) {
	tests := []struct {
		name string
		list []string
	}{
		{"empty", []string{}},
		{"single", []string{"ssh-rsa"}},
		{"multiple", []string{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"}},
		{"algorithms", []string{"aes256-ctr", "aes256-cbc", "aes128-ctr"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewSSHDataWriter(make([]byte, 0))
			w.WriteList(tt.list)

			r := NewSSHDataReader(w.ToBuffer())
			got, err := r.ReadList()
			if err != nil {
				t.Fatalf("ReadList error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.list) {
				t.Errorf("name-list round-trip: got %v, want %v", got, tt.list)
			}
		})
	}
}

func TestNameListWireFormat(t *testing.T) {
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteList([]string{"a", "b", "c"})
	buf := w.ToBuffer()
	// uint32 length (5) + "a,b,c"
	expected := []byte{0x00, 0x00, 0x00, 0x05, 'a', ',', 'b', ',', 'c'}
	if !bytes.Equal(buf, expected) {
		t.Errorf("name-list wire format: got %v, want %v", buf, expected)
	}
}

func TestRoundTripBigInt(t *testing.T) {
	tests := []struct {
		name  string
		value *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"one", big.NewInt(1)},
		{"small positive", big.NewInt(42)},
		{"127", big.NewInt(127)},
		{"128 (needs leading zero)", big.NewInt(128)},
		{"255 (needs leading zero)", big.NewInt(255)},
		{"256", big.NewInt(256)},
		{"large positive", new(big.Int).SetBytes([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF})},
		{"positive with high bit", new(big.Int).SetBytes([]byte{0x80, 0x00, 0x00, 0x01})},
		{"negative one", big.NewInt(-1)},
		{"negative small", big.NewInt(-128)},
		{"negative large", big.NewInt(-256)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewSSHDataWriter(make([]byte, 0))
			w.WriteBigInt(tt.value)

			r := NewSSHDataReader(w.ToBuffer())
			got, err := r.ReadBigInt()
			if err != nil {
				t.Fatalf("ReadBigInt error: %v", err)
			}
			if got.Cmp(tt.value) != 0 {
				t.Errorf("BigInt round-trip: got %s, want %s", got.String(), tt.value.String())
			}
		})
	}
}

func TestBigIntLeadingZeroPadding(t *testing.T) {
	// Value 0x80 (128) must be encoded as 0x00 0x80 in SSH mpint format
	// to avoid being interpreted as negative.
	v := big.NewInt(128)
	data := BigIntToSSHBytes(v)
	if len(data) != 2 || data[0] != 0x00 || data[1] != 0x80 {
		t.Errorf("BigInt 128 encoding: got %v, want [0x00 0x80]", data)
	}

	// Value 0x7F (127) should NOT have a leading zero byte.
	v = big.NewInt(127)
	data = BigIntToSSHBytes(v)
	if len(data) != 1 || data[0] != 0x7F {
		t.Errorf("BigInt 127 encoding: got %v, want [0x7F]", data)
	}
}

func TestBigIntZeroWireFormat(t *testing.T) {
	// Zero mpint: uint32 length = 0, no data bytes.
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteBigInt(big.NewInt(0))
	buf := w.ToBuffer()
	expected := []byte{0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(buf, expected) {
		t.Errorf("BigInt zero wire format: got %v, want %v", buf, expected)
	}
}

func TestBigIntLargeValue(t *testing.T) {
	// Test with a DH-sized big integer (256 bytes).
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	// Ensure high bit is set to test leading zero padding.
	b[0] = 0xFF
	v := new(big.Int).SetBytes(b)

	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteBigInt(v)

	r := NewSSHDataReader(w.ToBuffer())
	got, err := r.ReadBigInt()
	if err != nil {
		t.Fatalf("ReadBigInt large value error: %v", err)
	}
	if got.Cmp(v) != 0 {
		t.Error("BigInt large value round-trip failed")
	}
}

func TestRoundTripMultipleTypes(t *testing.T) {
	// Write multiple types in sequence, then read them all back.
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteByte(42)
	w.WriteBoolean(true)
	w.WriteUInt32(12345678)
	w.WriteUInt64(9876543210)
	w.WriteString("hello world")
	w.WriteBinary([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	w.WriteList([]string{"ssh-rsa", "ecdsa-sha2-nistp256"})
	w.WriteBigInt(big.NewInt(123456789))

	r := NewSSHDataReader(w.ToBuffer())

	b, err := r.ReadByte()
	if err != nil {
		t.Fatal(err)
	}
	if b != 42 {
		t.Errorf("byte: got %d, want 42", b)
	}

	boolVal, err := r.ReadBoolean()
	if err != nil {
		t.Fatal(err)
	}
	if !boolVal {
		t.Error("boolean: got false, want true")
	}

	u32, err := r.ReadUInt32()
	if err != nil {
		t.Fatal(err)
	}
	if u32 != 12345678 {
		t.Errorf("uint32: got %d, want 12345678", u32)
	}

	u64, err := r.ReadUInt64()
	if err != nil {
		t.Fatal(err)
	}
	if u64 != 9876543210 {
		t.Errorf("uint64: got %d, want 9876543210", u64)
	}

	str, err := r.ReadString()
	if err != nil {
		t.Fatal(err)
	}
	if str != "hello world" {
		t.Errorf("string: got %q, want %q", str, "hello world")
	}

	bin, err := r.ReadBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bin, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("binary: got %v, want [0xDE 0xAD 0xBE 0xEF]", bin)
	}

	list, err := r.ReadList()
	if err != nil {
		t.Fatal(err)
	}
	expectedList := []string{"ssh-rsa", "ecdsa-sha2-nistp256"}
	if !reflect.DeepEqual(list, expectedList) {
		t.Errorf("list: got %v, want %v", list, expectedList)
	}

	bigInt, err := r.ReadBigInt()
	if err != nil {
		t.Fatal(err)
	}
	if bigInt.Cmp(big.NewInt(123456789)) != 0 {
		t.Errorf("bigint: got %s, want 123456789", bigInt.String())
	}

	if r.Available() != 0 {
		t.Errorf("expected 0 available bytes, got %d", r.Available())
	}
}

func TestReadPastEndOfBuffer(t *testing.T) {
	r := NewSSHDataReader([]byte{})

	_, err := r.ReadByte()
	if err == nil {
		t.Error("expected error reading byte from empty buffer")
	}

	_, err = r.ReadUInt32()
	if err == nil {
		t.Error("expected error reading uint32 from empty buffer")
	}

	_, err = r.ReadUInt64()
	if err == nil {
		t.Error("expected error reading uint64 from empty buffer")
	}
}

func TestReadPartialBuffer(t *testing.T) {
	// Buffer has 2 bytes, try to read uint32 (needs 4).
	r := NewSSHDataReader([]byte{0x01, 0x02})

	_, err := r.ReadUInt32()
	if err == nil {
		t.Error("expected error reading uint32 from 2-byte buffer")
	}
}

func TestWriterAutoExpands(t *testing.T) {
	// Start with zero-capacity buffer and write lots of data.
	w := NewSSHDataWriter(make([]byte, 0))
	for i := 0; i < 1000; i++ {
		w.WriteUInt32(uint32(i))
	}
	buf := w.ToBuffer()
	if len(buf) != 4000 {
		t.Errorf("expected 4000 bytes, got %d", len(buf))
	}

	// Verify all values read back correctly.
	r := NewSSHDataReader(buf)
	for i := 0; i < 1000; i++ {
		v, err := r.ReadUInt32()
		if err != nil {
			t.Fatalf("ReadUInt32 at %d: %v", i, err)
		}
		if v != uint32(i) {
			t.Errorf("at %d: got %d, want %d", i, v, i)
		}
	}
}

func TestWriteUInt32At(t *testing.T) {
	buf := make([]byte, 8)
	WriteUInt32At(buf, 0, 0x01020304)
	WriteUInt32At(buf, 4, 0x05060708)
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(buf, expected) {
		t.Errorf("WriteUInt32At: got %v, want %v", buf, expected)
	}
}

func TestWriteRawBytes(t *testing.T) {
	w := NewSSHDataWriter(make([]byte, 0))
	w.Write([]byte{0x01, 0x02, 0x03})
	w.Write([]byte{0x04, 0x05})
	buf := w.ToBuffer()
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(buf, expected) {
		t.Errorf("Write raw: got %v, want %v", buf, expected)
	}
}

func TestWriteRandom(t *testing.T) {
	w := NewSSHDataWriter(make([]byte, 0))
	w.WriteRandom(16)
	buf := w.ToBuffer()
	if len(buf) != 16 {
		t.Errorf("WriteRandom length: got %d, want 16", len(buf))
	}
	// Verify it's not all zeros (statistically impossible for 16 random bytes).
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("WriteRandom produced all zeros")
	}
}
