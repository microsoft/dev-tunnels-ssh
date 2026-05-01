// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// ecdsaSignature is the ASN.1 structure returned by Go's ecdsa.SignASN1.
type ecdsaSignature struct {
	R, S *big.Int
}

// EcdsaKeyPair implements KeyPair for ECDSA keys.
type EcdsaKeyPair struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	comment    string
	algorithm  string         // e.g., "ecdsa-sha2-nistp256"
	curve      elliptic.Curve // P-256, P-384, or P-521
	curveName  string         // e.g., "nistp256"
	hashAlgo   crypto.Hash
}

// generateEcdsaKeyPair generates a new ECDSA key pair for the specified algorithm.
func generateEcdsaKeyPair(algorithmName string) (*EcdsaKeyPair, error) {
	curve, curveName, hashAlgo, err := ecdsaCurveForAlgorithm(algorithmName)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	return &EcdsaKeyPair{
		privateKey: key,
		publicKey:  &key.PublicKey,
		algorithm:  algorithmName,
		curve:      curve,
		curveName:  curveName,
		hashAlgo:   hashAlgo,
	}, nil
}

// NewEcdsaKeyPair creates a new EcdsaKeyPair from an existing crypto/ecdsa private key.
func NewEcdsaKeyPair(privateKey *ecdsa.PrivateKey) (*EcdsaKeyPair, error) {
	algorithmName, curveName, hashAlgo, err := ecdsaAlgorithmForCurve(privateKey.Curve)
	if err != nil {
		return nil, err
	}
	return &EcdsaKeyPair{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		algorithm:  algorithmName,
		curve:      privateKey.Curve,
		curveName:  curveName,
		hashAlgo:   hashAlgo,
	}, nil
}

// NewEcdsaKeyPairFromPublicKey creates a public-key-only EcdsaKeyPair from a crypto/ecdsa public key.
func NewEcdsaKeyPairFromPublicKey(pubKey *ecdsa.PublicKey) (*EcdsaKeyPair, error) {
	algorithmName, curveName, hashAlgo, err := ecdsaAlgorithmForCurve(pubKey.Curve)
	if err != nil {
		return nil, err
	}
	return &EcdsaKeyPair{
		publicKey: pubKey,
		algorithm: algorithmName,
		curve:     pubKey.Curve,
		curveName: curveName,
		hashAlgo:  hashAlgo,
	}, nil
}

func ecdsaCurveForAlgorithm(algorithmName string) (elliptic.Curve, string, crypto.Hash, error) {
	switch algorithmName {
	case AlgoPKEcdsaSha2P256:
		return elliptic.P256(), "nistp256", crypto.SHA256, nil
	case AlgoPKEcdsaSha2P384:
		return elliptic.P384(), "nistp384", crypto.SHA384, nil
	case AlgoPKEcdsaSha2P521:
		return elliptic.P521(), "nistp521", crypto.SHA512, nil
	default:
		return nil, "", 0, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithmName)
	}
}

func ecdsaAlgorithmForCurve(curve elliptic.Curve) (string, string, crypto.Hash, error) {
	switch curve {
	case elliptic.P256():
		return AlgoPKEcdsaSha2P256, "nistp256", crypto.SHA256, nil
	case elliptic.P384():
		return AlgoPKEcdsaSha2P384, "nistp384", crypto.SHA384, nil
	case elliptic.P521():
		return AlgoPKEcdsaSha2P521, "nistp521", crypto.SHA512, nil
	default:
		return "", "", 0, fmt.Errorf("unsupported ECDSA curve: %v", curve.Params().Name)
	}
}

// KeyAlgorithmName returns the SSH algorithm name (e.g., "ecdsa-sha2-nistp256").
func (k *EcdsaKeyPair) KeyAlgorithmName() string {
	return k.algorithm
}

// HasPrivateKey returns true if this key pair includes a private key.
func (k *EcdsaKeyPair) HasPrivateKey() bool {
	return k.privateKey != nil
}

// Comment returns the key comment.
func (k *EcdsaKeyPair) Comment() string {
	return k.comment
}

// SetComment sets the key comment.
func (k *EcdsaKeyPair) SetComment(comment string) {
	k.comment = comment
}

// GetPublicKeyBytes returns the ECDSA public key in SSH wire format.
// Format: [string algorithm][string curve-name][binary 0x04||X||Y]
func (k *EcdsaKeyPair) GetPublicKeyBytes() ([]byte, error) {
	if k.publicKey == nil {
		return nil, fmt.Errorf("key is not present")
	}

	// Marshal the public key point as uncompressed: 0x04 || X || Y
	pointBytes := elliptic.Marshal(k.curve, k.publicKey.X, k.publicKey.Y)

	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	writer.WriteString(k.algorithm)
	writer.WriteString(k.curveName)
	writer.WriteBinary(pointBytes)
	return writer.ToBuffer(), nil
}

// SetPublicKeyBytes imports an ECDSA public key from SSH wire format bytes.
func (k *EcdsaKeyPair) SetPublicKeyBytes(data []byte) error {
	reader := sshio.NewSSHDataReader(data)

	algorithmName, err := reader.ReadString()
	if err != nil {
		return fmt.Errorf("failed to read algorithm name: %w", err)
	}

	curve, curveName, hashAlgo, err := ecdsaCurveForAlgorithm(algorithmName)
	if err != nil {
		return fmt.Errorf("invalid ECDSA key algorithm: %s", algorithmName)
	}

	readCurveName, err := reader.ReadString()
	if err != nil {
		return fmt.Errorf("failed to read curve name: %w", err)
	}
	if readCurveName != curveName {
		return fmt.Errorf("curve name %s does not match algorithm %s (%s)",
			readCurveName, algorithmName, curveName)
	}

	pointBytes, err := reader.ReadBinary()
	if err != nil {
		return fmt.Errorf("failed to read public key point: %w", err)
	}

	x, y := elliptic.Unmarshal(curve, pointBytes)
	if x == nil {
		return fmt.Errorf("invalid ECDSA public key point")
	}

	k.publicKey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	k.privateKey = nil
	k.algorithm = algorithmName
	k.curve = curve
	k.curveName = curveName
	k.hashAlgo = hashAlgo
	return nil
}

// Sign signs data using the ECDSA private key.
// The signature is returned in SSH format: [mpint r][mpint s].
func (k *EcdsaKeyPair) Sign(data []byte) ([]byte, error) {
	if k.privateKey == nil {
		return nil, fmt.Errorf("private key is required for signing")
	}

	h := k.hashAlgo.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Sign using ASN.1 DER format, then parse to get r, s
	derSig, err := ecdsa.SignASN1(rand.Reader, k.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign failed: %w", err)
	}

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	// Write r and s as SSH mpints
	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	writer.WriteBigInt(sig.R)
	writer.WriteBigInt(sig.S)
	return writer.ToBuffer(), nil
}

// Verify verifies an ECDSA signature over data.
// The signature is expected in SSH format: [mpint r][mpint s].
func (k *EcdsaKeyPair) Verify(data, signature []byte) (bool, error) {
	if k.publicKey == nil {
		return false, fmt.Errorf("public key is required for verification")
	}

	// Parse r and s from SSH mpint format
	reader := sshio.NewSSHDataReader(signature)
	r, err := reader.ReadBigInt()
	if err != nil {
		return false, fmt.Errorf("failed to read signature r: %w", err)
	}
	s, err := reader.ReadBigInt()
	if err != nil {
		return false, fmt.Errorf("failed to read signature s: %w", err)
	}

	h := k.hashAlgo.New()
	h.Write(data)
	digest := h.Sum(nil)

	return ecdsa.Verify(k.publicKey, digest, r, s), nil
}

// PublicKey returns the underlying crypto/ecdsa public key.
func (k *EcdsaKeyPair) PublicKey() *ecdsa.PublicKey {
	return k.publicKey
}

// PrivateKey returns the underlying crypto/ecdsa private key, or nil.
func (k *EcdsaKeyPair) PrivateKey() *ecdsa.PrivateKey {
	return k.privateKey
}
