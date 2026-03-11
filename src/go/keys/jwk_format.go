// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// jwkKey represents a JSON Web Key (RFC 7517).
type jwkKey struct {
	Kty     string `json:"kty"`
	Crv     string `json:"crv,omitempty"`
	N       string `json:"n,omitempty"`
	E       string `json:"e,omitempty"`
	D       string `json:"d,omitempty"`
	P       string `json:"p,omitempty"`
	Q       string `json:"q,omitempty"`
	Dp      string `json:"dp,omitempty"`
	Dq      string `json:"dq,omitempty"`
	Qi      string `json:"qi,omitempty"`
	X       string `json:"x,omitempty"`
	Y       string `json:"y,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// importJwk imports a key from JWK (JSON Web Key) format.
func importJwk(data []byte) (ssh.KeyPair, error) {
	var jwk jwkKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	var kp ssh.KeyPair
	var err error

	switch jwk.Kty {
	case "RSA":
		kp, err = importJwkRsa(&jwk)
	case "EC":
		kp, err = importJwkEc(&jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", jwk.Kty)
	}

	if err != nil {
		return nil, err
	}

	if jwk.Comment != "" {
		kp.SetComment(jwk.Comment)
	}

	return kp, nil
}

// importJwkRsa imports an RSA key from JWK format.
func importJwkRsa(jwk *jwkKey) (ssh.KeyPair, error) {
	n, err := base64urlDecodeBigInt(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'n': %w", err)
	}
	eBytes, err := base64urlDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'e': %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)

	if jwk.D == "" {
		// Public key only.
		pubKey := &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}
		kp := ssh.NewRsaKeyPairFromPublicKey(pubKey)
		return kp, nil
	}

	// Private key.
	d, err := base64urlDecodeBigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'd': %w", err)
	}
	p, err := base64urlDecodeBigInt(jwk.P)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'p': %w", err)
	}
	q, err := base64urlDecodeBigInt(jwk.Q)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'q': %w", err)
	}

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	privKey.Precompute()

	return ssh.NewRsaKeyPair(privKey, rsaAlgorithmForKeySize(n.BitLen()))
}

// importJwkEc imports an ECDSA key from JWK format.
func importJwkEc(jwk *jwkKey) (ssh.KeyPair, error) {
	curve, err := jwkCurve(jwk.Crv)
	if err != nil {
		return nil, err
	}

	x, err := base64urlDecodeBigInt(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'x': %w", err)
	}
	y, err := base64urlDecodeBigInt(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'y': %w", err)
	}

	if jwk.D == "" {
		// Public key only.
		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
		return ssh.NewEcdsaKeyPairFromPublicKey(pubKey)
	}

	// Private key.
	d, err := base64urlDecodeBigInt(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK 'd': %w", err)
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return ssh.NewEcdsaKeyPair(privKey)
}

// exportJwk exports a key in JWK (JSON Web Key) format.
func exportJwk(key ssh.KeyPair) ([]byte, error) {
	var jwk *jwkKey
	var err error

	switch k := key.(type) {
	case *ssh.RsaKeyPair:
		jwk, err = exportJwkRsa(k)
	case *ssh.EcdsaKeyPair:
		jwk, err = exportJwkEc(k)
	default:
		return nil, fmt.Errorf("unsupported key type for JWK export: %T", key)
	}

	if err != nil {
		return nil, err
	}

	if key.Comment() != "" {
		jwk.Comment = key.Comment()
	}

	data, err := json.MarshalIndent(jwk, "", "\t")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	data = append(data, '\n')
	return data, nil
}

// exportJwkRsa exports an RSA key in JWK format.
func exportJwkRsa(key *ssh.RsaKeyPair) (*jwkKey, error) {
	pubKey := key.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	jwk := &jwkKey{
		Kty: "RSA",
		N:   base64urlEncodeBigInt(pubKey.N),
		E:   base64urlEncode(big.NewInt(int64(pubKey.E)).Bytes()),
	}

	privKey := key.PrivateKey()
	if privKey != nil {
		jwk.D = base64urlEncodeBigInt(privKey.D)
		jwk.P = base64urlEncodeBigInt(privKey.Primes[0])
		jwk.Q = base64urlEncodeBigInt(privKey.Primes[1])
		jwk.Dp = base64urlEncodeBigInt(privKey.Precomputed.Dp)
		jwk.Dq = base64urlEncodeBigInt(privKey.Precomputed.Dq)
		jwk.Qi = base64urlEncodeBigInt(privKey.Precomputed.Qinv)
	}

	return jwk, nil
}

// exportJwkEc exports an ECDSA key in JWK format.
func exportJwkEc(key *ssh.EcdsaKeyPair) (*jwkKey, error) {
	pubKey := key.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	crv := jwkCurveName(pubKey.Curve)
	byteLen := (pubKey.Curve.Params().BitSize + 7) / 8

	jwk := &jwkKey{
		Kty: "EC",
		Crv: crv,
		X:   base64urlEncodePadded(pubKey.X.Bytes(), byteLen),
		Y:   base64urlEncodePadded(pubKey.Y.Bytes(), byteLen),
	}

	privKey := key.PrivateKey()
	if privKey != nil {
		jwk.D = base64urlEncodePadded(privKey.D.Bytes(), byteLen)
	}

	return jwk, nil
}

// jwkCurve returns the elliptic.Curve for a JWK curve name.
// Supports both SSH-style names (nistp256) and standard JWK names (P-256).
func jwkCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256", "nistp256":
		return elliptic.P256(), nil
	case "P-384", "nistp384":
		return elliptic.P384(), nil
	case "P-521", "nistp521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported JWK curve: %s", crv)
	}
}

// jwkCurveName returns the JWK curve name for an elliptic curve.
// Uses standard names per RFC 7518 Section 6.2.1.1.
func jwkCurveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "unknown"
	}
}

// base64urlEncode encodes bytes to base64url without padding.
func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64urlEncodePadded encodes bytes to base64url, left-padding to targetLen.
func base64urlEncodePadded(data []byte, targetLen int) string {
	if len(data) < targetLen {
		padded := make([]byte, targetLen)
		copy(padded[targetLen-len(data):], data)
		data = padded
	}
	return base64urlEncode(data)
}

// base64urlEncodeBigInt encodes a big.Int to base64url without padding.
func base64urlEncodeBigInt(n *big.Int) string {
	return base64urlEncode(n.Bytes())
}

// base64urlDecode decodes base64url data (with or without padding).
func base64urlDecode(s string) ([]byte, error) {
	// Try raw first, then padded.
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// base64urlDecodeBigInt decodes a base64url-encoded big.Int.
func base64urlDecodeBigInt(s string) (*big.Int, error) {
	data, err := base64urlDecode(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

// isJwkFormat checks if data looks like a JWK JSON object.
func isJwkFormat(data []byte) bool {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}
	_, hasKty := obj["kty"]
	return hasKty
}
