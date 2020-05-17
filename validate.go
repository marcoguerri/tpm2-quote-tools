package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
)

// SubjectPublicKeyInfo reproduces the ASN struct according to
// RFC5480 https://tools.ietf.org/html/rfc5480, SubjectPublicKeyInfo)
// Used to parse the .pem pub key file produced by tpm2_createak.
// Supports only P256 EC keys.
type SubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ECKeyPairValidation contains information acquired from the validation of the keypair
type ECKeyPairValidation struct {
	X     *big.Int
	Y     *big.Int
	Priv  *big.Int
	Valid bool
}

// Load private/public EC keypair from pem file and hex string
func loadKeys(privKey, pubKeyPath string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	pk, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read public key file: %v", err)
	}

	block, _ := pem.Decode([]byte(pk))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pki := SubjectPublicKeyInfo{}
	if _, err = asn1.Unmarshal(block.Bytes, &pki); err != nil {
		return nil, nil, fmt.Errorf("could not parse pkInfo: %v", err)
	}

	bitstring := pki.PublicKey.RightAlign()
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, bitstring)
	if x == nil {
		return nil, nil, fmt.Errorf("could not unmarshal bitstring extracted from pem file")
	}
	ecPub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	D := big.NewInt(0)
	if strings.HasPrefix(privKey, "0x") {
		b, err := hex.DecodeString(privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("could not decode private key hex string: %v", err)
		}

		D = big.NewInt(0).SetBytes(b)
	} else {
		var success bool
		D, success = D.SetString(privKey, 10)
		if !success {
			return nil, nil, fmt.Errorf("could not set big int from decimal string representation")
		}
	}

	ecPriv := ecdsa.PrivateKey{
		PublicKey: ecPub,
		D:         D,
	}
	return &ecPriv, &ecPub, nil
}

func validateKeypair(privKey, pubKeyPath string) (*ECKeyPairValidation, error) {

	var message = []byte("Ed elli avea del cul fatto trombetta")

	if len(privKey) == 0 {
		return nil, fmt.Errorf("private key is required")
	}
	if len(pubKeyPath) == 0 {
		return nil, fmt.Errorf("public key path is required")
	}
	ecPriv, ecPub, err := loadKeys(privKey, pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("could not load keys: %v", err)
	}

	hasher := sha256.New()
	n, err := hasher.Write(message)
	if n != len(message) {
		return nil, fmt.Errorf("byte written less than expected: %d < %d", n, len(message))
	}

	if err != nil {
		return nil, err
	}

	hash := hasher.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, ecPriv, hash)
	if err != nil {
		return nil, fmt.Errorf("could not sign message for validation: %v", err)
	}
	valid := ecdsa.Verify(ecPub, hash, r, s)

	if !valid {
		return &ECKeyPairValidation{X: ecPub.X, Y: ecPub.Y, Priv: ecPriv.D, Valid: false}, nil
	}
	return &ECKeyPairValidation{X: ecPub.X, Y: ecPub.Y, Priv: ecPriv.D, Valid: valid}, nil
}
