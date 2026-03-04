// Copyright (c) Microsoft Corporation. All rights reserved.

package helpers

// MockRandom provides a deterministic random byte source for reproducible tests.
// It generates a repeating sequence of bytes based on a seed value.
type MockRandom struct {
	seed  byte
	state byte
}

// NewMockRandom creates a new deterministic random source with the given seed.
func NewMockRandom(seed byte) *MockRandom {
	return &MockRandom{seed: seed, state: seed}
}

// Read fills the buffer with deterministic pseudo-random bytes.
// It always fills the entire buffer and returns len(p), nil.
// This satisfies io.Reader for use as a random source in tests.
func (m *MockRandom) Read(p []byte) (int, error) {
	for i := range p {
		// Simple linear congruential generator for deterministic output.
		m.state = m.state*7 + 13
		p[i] = m.state
	}
	return len(p), nil
}

// Reset restores the random source to its initial seed state.
func (m *MockRandom) Reset() {
	m.state = m.seed
}

// GenerateDeterministicBytes returns n bytes of deterministic data using the given seed.
// This is a convenience function for generating test data patterns.
func GenerateDeterministicBytes(seed byte, n int) []byte {
	m := NewMockRandom(seed)
	buf := make([]byte, n)
	m.Read(buf)
	return buf
}
