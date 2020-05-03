package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
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

// Load private/public EC keypair from pem file and hex string
func loadKeys(pubPath string, priv string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {

	pk, err := ioutil.ReadFile(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read public key file: %w", err)
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
	if strings.HasPrefix(priv, "0x") {
		b, err := hex.DecodeString(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("could not decode private key hex string: %w", err)
		}

		D = big.NewInt(0).SetBytes(b)
	} else {
		var success bool
		D, success = D.SetString(priv, 10)
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

// Validates private/public EC keypair
func validate(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) (bool, error) {

	var message = []byte("Ed elli avea del cul fatto trombetta")

	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)

	r, s, err := ecdsa.Sign(bytes.NewReader(hash), priv, hash)
	if err != nil {
		return false, fmt.Errorf("could not sign message for validation: %v", err)
	}

	valid := ecdsa.Verify(pub, hash, r, s)
	if !valid {
		return false, nil
	}
	return true, nil
}

func main() {

	var priv, pubPath string

	flag.StringVar(&priv, "priv", "", "hex representation of the private key")
	flag.StringVar(&pubPath, "pubPath", "", "path of the public key file in pem format")
	flag.Parse()

	if len(priv) == 0 {
		log.Fatalf("private key is required")
	}

	if len(pubPath) == 0 {
		log.Fatalf("public key path is required")
	}

	ecPriv, ecPub, err := loadKeys(pubPath, priv)
	if err != nil {
		log.Fatalf("could not load keys: %w", err)

	}
	log.Printf("X: %x\n", ecPub.X)
	log.Printf("Y: %x\n", ecPub.Y)
	log.Printf("Priv: %d\n", ecPriv.D)

	valid, err := validate(ecPriv, ecPub)
	if err != nil {
		log.Fatalf("could not validate private/public keypair: %w", err)
	}
	if valid {
		log.Printf("OK!")
		os.Exit(0)
	} else {
		log.Printf("NOT OK!")
		os.Exit(1)
	}
}
