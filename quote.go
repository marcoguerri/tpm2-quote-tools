/*
 * tpm2-quote-tools
 *
 * Copyright (C) 2020 Marco Guerri <marco.guerri.dev@fastmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Every piece of information produced and signed by the TPM follows the
// TPMS_ATTEST structure (Trusted Platform Module Library, Part 2: Structures, 10.12.8).
// Whether the blob contains data produced by TPM2_Quote is indicated by TPMI_ST_ATTEST
// structure, which should have a value of TPM_ST_ATTEST_QUOTE.
//
// If the blob is a quote, what we are interested in is the TPMU_ATTEST structure.
// Fields of the structure
// magic 				TPM_GENERATED
// type 				TPMI_ST_ATTEST
// qualifiedSigner 		TPM2B_NAME
// extraData 			TPM2B_DATA
// clockInfo 			TPMS_CLOCK_INFO
// firmwareVersion    	UINT64
// [type]attested		TPMU_ATTEST
//
// With a TPM_ST_ATTEST_QUOTE selector, TPMU_ATTEST is structured as follows:
// pcrSelect TPML_PCR_SELECTION
// pcrDigest TPM2B_DIGEST

type ecdsaSignature struct {
	SigR, SigS *big.Int
}

func (s *ecdsaSignature) R() *big.Int {
	return s.SigR
}

func (s *ecdsaSignature) S() *big.Int {
	return s.SigS
}

type algo uint16

const (
	tpmAlgSha1   algo = 0x4
	tpmAlgSha256      = 0xB
	tpmAlgSm3256      = 0x12
	tpmAlgNull        = 0x10
)

func (a algo) String() string {
	if a == tpmAlgSha1 {
		return "sha1"
	} else if a == tpmAlgSha256 {
		return "sha256"
	} else if a == tpmAlgSm3256 {
		return "sm3 256"
	} else if a == tpmAlgNull {
		return "null"
	} else {
		return "unknown"
	}
}

// magic field, TPM_GENERATED
type magic uint32

func (m *magic) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("0x%x", *m)
	return json.Marshal(s)
}

func (m *magic) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, *m)
	return b.Bytes(), nil
}

// type, TPMI_ST_ATTEST
type stType uint16

func (t *stType) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("0x%x", *t)
	return json.Marshal(s)
}

func (t *stType) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, *t)
	return b.Bytes(), nil
}

// buffer
type buffer []byte

func (b buffer) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("0x%x", b)
	return json.Marshal(s)
}

func (b buffer) Equal(rhs []byte) bool {
	return bytes.Equal(rhs, b)
}

func (b buffer) MarshalBinary() ([]byte, error) {
	buff := make([]byte, len(b))
	copy(buff, b)
	return buff, nil
}

// firmwareVersion
type firmwareVersion uint64

func (f *firmwareVersion) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("0x%x", *f)
	return json.Marshal(s)
}

func (f *firmwareVersion) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, *f)
	return b.Bytes(), nil
}

// pcrSelect represents a bitfield of pcrs which are selected for the quote
type pcrSelect []byte

func (p pcrSelect) AsSlice() []int {
	pcrs := make([]int, 0)
	for i := 0; i < len(p); i++ {
		for j := uint8(0); j < 8; j++ {
			if p[i]&(uint8(0x1)<<j) != 0x0 {
				pcrs = append(pcrs, i*8+int(j))
			}
		}
	}
	return pcrs
}

func (p pcrSelect) MarshalJSON() ([]byte, error) {
	pcrsIndexes := p.AsSlice()
	pcrs := make([]string, 0)
	for _, index := range pcrsIndexes {
		pcrs = append(pcrs, fmt.Sprintf("%d", index))
	}
	return json.Marshal(strings.Join(pcrs, ","))
}

func (p pcrSelect) MarshalBinary() ([]byte, error) {
	buff := make([]byte, len(p))
	copy(buff, p)
	return buff, nil
}

// tpmsPcrSelection
type tpmsPcrSelection struct {
	Hash         algo
	SizeofSelect uint8
	PcrSelect    pcrSelect
}

func (p tpmsPcrSelection) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, p.Hash)
	binary.Write(&b, binary.BigEndian, p.SizeofSelect)
	pcrSelect, _ := p.PcrSelect.MarshalBinary()
	b.Write(pcrSelect)
	return b.Bytes(), nil
}

// tpmlPcrSelection
type tpmlPcrSelection struct {
	Count        uint32
	PcrSelection tpmsPcrSelection
}

func (s *tpmlPcrSelection) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, s.Count)
	pcrSelection, _ := s.PcrSelection.MarshalBinary()
	b.Write(pcrSelection)
	return b.Bytes(), nil
}

type tpm2bName struct {
	Size uint16
	Name buffer
}

func (n *tpm2bName) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, n.Size)
	name, _ := n.Name.MarshalBinary()
	b.Write(name)
	return b.Bytes(), nil
}

type tpm2bData struct {
	Size   uint16
	Buffer buffer
}

func (n *tpm2bData) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, n.Size)
	buff, _ := n.Buffer.MarshalBinary()
	b.Write(buff)
	return b.Bytes(), nil
}

type tpm2bDigest struct {
	Size   uint16
	Buffer buffer
}

func (d *tpm2bDigest) Equal(rhs []byte) bool {
	return d.Buffer.Equal(rhs)
}

func (d *tpm2bDigest) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, d.Size)
	buff, _ := d.Buffer.MarshalBinary()
	b.Write(buff)
	return b.Bytes(), nil
}

type tpmsCockInfo struct {
	Clock        uint64
	ResetCount   uint32
	RestartCount uint32
	YesNo        uint8
}

func (n *tpmsCockInfo) MarshalBinary() ([]byte, error) {
	buff := bytes.Buffer{}
	binary.Write(&buff, binary.BigEndian, n)
	return buff.Bytes(), nil
}

type tpmsQuoteInfo struct {
	PcrSelect tpmlPcrSelection
	PcrDigest tpm2bDigest
}

func (i *tpmsQuoteInfo) MarshalBinary() ([]byte, error) {
	pcrSelect, _ := i.PcrSelect.MarshalBinary()
	pcrDigest, _ := i.PcrDigest.MarshalBinary()
	return append(pcrSelect, pcrDigest...), nil
}

const (
	tpmGeneratedValue = 0xff544347
	stAttestQuote     = 0x8018
)

type quote struct {
	Magic           magic
	StType          stType
	QualifiedSigner tpm2bName
	ExtraData       tpm2bData
	ClockInfo       tpmsCockInfo
	FirmwareVersion firmwareVersion
	QuoteInfo       tpmsQuoteInfo
}

func (q *quote) MarshalBinary() ([]byte, error) {
	serialization, _ := q.Magic.MarshalBinary()
	stType, _ := q.StType.MarshalBinary()
	qualifiedSigner, _ := q.QualifiedSigner.MarshalBinary()
	extraData, _ := q.ExtraData.MarshalBinary()
	clockInfo, _ := q.ClockInfo.MarshalBinary()
	firmwareVersion, _ := q.FirmwareVersion.MarshalBinary()
	quoteInfo, _ := q.QuoteInfo.MarshalBinary()

	serialization = append(serialization, stType...)
	serialization = append(serialization, qualifiedSigner...)
	serialization = append(serialization, extraData...)
	serialization = append(serialization, clockInfo...)
	serialization = append(serialization, firmwareVersion...)
	serialization = append(serialization, quoteInfo...)
	return serialization, nil
}

func readQuote(quotePath string) (*quote, error) {

	quoteFile, err := os.Open(quotePath)
	if err != nil {
		return nil, fmt.Errorf("could not read quote file: %v", err)
	}
	defer func() {
		if err := quoteFile.Close(); err != nil {
			log.Printf("could not close quote file: %v", err)
		}
	}()

	q := quote{}
	// magic
	if binary.Read(quoteFile, binary.BigEndian, &q.Magic); err != nil {
		return nil, fmt.Errorf("could not read magic number from quote file")
	}
	if q.Magic != tpmGeneratedValue {
		return nil,

			fmt.Errorf("quote doesn't start with TPM_GENERATED_VALUE: %x", q.Magic)
	}

	// type
	if binary.Read(quoteFile, binary.BigEndian, &q.StType); err != nil {
		return nil, fmt.Errorf("could not read structure tag type from quote file")
	}
	if q.StType != stAttestQuote {
		return nil, fmt.Errorf("quote doest contain TPM_ST_ATTEST_QUOTE tag: %x", q.StType)
	}

	// qualifiedSigner
	if binary.Read(quoteFile, binary.BigEndian, &q.QualifiedSigner.Size); err != nil {
		return nil, fmt.Errorf("couldn't read qualifiedSigner size: %v", err)
	}
	q.QualifiedSigner.Name = make([]byte, q.QualifiedSigner.Size)
	if binary.Read(quoteFile, binary.BigEndian, &q.QualifiedSigner.Name); err != nil {
		return nil, fmt.Errorf("could not read qualifiedSigner")
	}

	// extraData
	if binary.Read(quoteFile, binary.BigEndian, &q.ExtraData.Size); err != nil {
		return nil, fmt.Errorf("couldn't read extraData size: %v", err)
	}
	q.ExtraData.Buffer = make([]byte, q.ExtraData.Size)
	if binary.Read(quoteFile, binary.BigEndian, &q.ExtraData.Buffer); err != nil {
		return nil, fmt.Errorf("could not read extraData")
	}

	// clockInfo
	if binary.Read(quoteFile, binary.BigEndian, &q.ClockInfo); err != nil {
		return nil, fmt.Errorf("couldn't read clock info: %v", err)
	}

	// firmwareVersion
	if binary.Read(quoteFile, binary.BigEndian, &q.FirmwareVersion); err != nil {
		return nil, fmt.Errorf("couldn't read firmware version: %v", err)
	}

	// PcrSelect.Count
	pcrSelect := &q.QuoteInfo.PcrSelect
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelect.Count); err != nil {
		return nil, fmt.Errorf("couldn't read PcrSelect Count: %v", err)
	}
	// PcrSelect.PcrSelection.Hash
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelect.PcrSelection.Hash); err != nil {
		return nil, fmt.Errorf("couldn't read PcrSelection Hash: %v", err)
	}

	// PcrSelection.SizeofSelect
	pcrSelection := &q.QuoteInfo.PcrSelect.PcrSelection
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelection.SizeofSelect); err != nil {
		return nil, fmt.Errorf("couldn't read SizeofSelect: %v", err)
	}
	q.QuoteInfo.PcrSelect.PcrSelection.PcrSelect = make([]byte, pcrSelection.SizeofSelect)
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelection.PcrSelect); err != nil {
		return nil, fmt.Errorf("couldn't read PcrSelect: %v", err)
	}

	pcrDigest := &q.QuoteInfo.PcrDigest
	// PcrDigest.Size
	if binary.Read(quoteFile, binary.BigEndian, &pcrDigest.Size); err != nil {
		return nil, fmt.Errorf("couldn't read quoteInfo.pcrDigest.size: %v", err)
	}
	q.QuoteInfo.PcrDigest.Buffer = make([]byte, pcrDigest.Size)
	if binary.Read(quoteFile, binary.BigEndian, &pcrDigest.Buffer); err != nil {
		return nil, fmt.Errorf("couldn't read PcrDigest buffer: %v", err)
	}
	return &q, nil
}

func validateQuote(quote *quote, sigPath, privKey, pubKeyPath, pcrReadPath string) (bool, error) {

	if quote.QuoteInfo.PcrSelect.PcrSelection.Hash != tpmAlgSha256 {
		return false, fmt.Errorf("only tpmAlgSha256 supported, but %s found", quote.QuoteInfo.PcrSelect.PcrSelection.Hash.String())
	}

	quoteSerialized, _ := quote.MarshalBinary()
	hash := sha256.Sum256(quoteSerialized)

	log.Debugf("sha256sum calculated from quote: 0x%s", hex.EncodeToString(hash[:]))

	// Deserialize the signature
	log.Debugf("reading signature file at %s", sigPath)
	sigRaw, err := ioutil.ReadFile(sigPath)
	if err != nil {
		return false, fmt.Errorf("could not read file containig signature: %v", err)
	}

	sig := ecdsaSignature{}
	if _, err = asn1.Unmarshal(sigRaw, &sig); err != nil {
		return false, fmt.Errorf("could not parse signature: %v", err)
	}
	log.Debugf("ecdsa signature, r: %s, s: %s", sig.R().String(), sig.S().String())

	_, ecPub, err := loadKeys(privKey, pubKeyPath)
	log.Debugf("validating quote signature with ecPub, X: %s, Y: %s", ecPub.X.String(), ecPub.Y.String())
	if err != nil {
		return false, fmt.Errorf("could not load keys: %v", err)
	}

	valid := ecdsa.Verify(ecPub, hash[:], sig.R(), sig.S())

	if valid {
		log.Debugf("signature OK")
	} else {
		return false, nil
	}

	log.Debugf("validating pcr hash against %s", pcrReadPath)

	pcrsSelection := quote.QuoteInfo.PcrSelect.PcrSelection.PcrSelect.AsSlice()
	expectedDigest, err := calculatePcrDigest(pcrReadPath, pcrsSelection)
	if err != nil {
		return false, fmt.Errorf("could not calculate expected digest from pcr file: %v", err)
	}

	quoteDigest, err := quote.QuoteInfo.PcrDigest.Buffer.MarshalBinary()
	if err != nil {
		return false, fmt.Errorf("could not extract raw digest from quote")
	}

	if quote.QuoteInfo.PcrDigest.Buffer.Equal(expectedDigest) {
		log.Debugf("digest match: 0x%s == 0x%s", hex.EncodeToString(expectedDigest), hex.EncodeToString(quoteDigest))
		return true, nil
	}

	log.Debugf("mismatching quoted digest: expected 0x%s, found 0x%s", hex.EncodeToString(expectedDigest), quoteDigest)

	return valid, nil
}

func calculatePcrDigest(pcrReadPath string, pcrs []int) ([]byte, error) {

	log.Debugf("reading pcr file at %s", pcrReadPath)
	file, err := os.Open(pcrReadPath)
	if err != nil {
		return nil, fmt.Errorf("could not read pcr file: %v", err)
	}
	defer file.Close()

	r := regexp.MustCompile(`([0-9]+)\s?: 0x([0-9A-F]+)`)

	buffer := make([]byte, 0)

	sha256Map := make(map[int64][]byte)

	var pcrMap map[int64][]byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		matches := r.FindStringSubmatch(str)

		if strings.HasPrefix(str, "sha1") {
			pcrMap = nil
			continue
		}
		if strings.HasPrefix(str, "sha256") {
			pcrMap = sha256Map
			continue
		}
		if len(matches) != 3 {
			log.Debugf("unexpected match %s", str)
			continue
		}

		if pcrMap == nil {
			continue
		}

		pcrValue, err := hex.DecodeString(matches[2])
		if err != nil {
			return nil, fmt.Errorf("could not decode pcr value: %s", matches[2])
		}
		pcrIndex, err := strconv.ParseInt(matches[1], 16, 10)
		if err != nil {
			return nil, fmt.Errorf("could not parse pcr register number")
		}

		log.Debugf("pcr file: found [%d] : [0x%s]", pcrIndex, hex.EncodeToString(pcrValue))
		pcrMap[pcrIndex] = pcrValue
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("could not read pcr file: %v", err)
	}

	for _, pcrIndex := range pcrs {
		if _, ok := sha256Map[int64(pcrIndex)]; !ok {
			return nil, fmt.Errorf("pcr index %d not present in sha256 map", pcrIndex)
		}
		buffer = append(buffer, sha256Map[int64(pcrIndex)]...)
	}
	sum := sha256.Sum256(buffer)
	return sum[:], nil
}

func forgeQuote(quote *quote, pcrReadPath, privKey, pubKeyPath, sigOutPath, quoteOutPath string) error {

	pcrsSelection := quote.QuoteInfo.PcrSelect.PcrSelection.PcrSelect.AsSlice()
	pcrHash, err := calculatePcrDigest(pcrReadPath, pcrsSelection)
	if err != nil {
		return err
	}

	quote.QuoteInfo.PcrDigest.Buffer = buffer(pcrHash)
	quoteSerialized, _ := quote.MarshalBinary()
	quoteHash := sha256.Sum256(quoteSerialized)

	log.Debugf("signing 0x%s", hex.EncodeToString(quoteHash[:]))
	ecPriv, _, err := loadKeys(privKey, pubKeyPath)
	if err != nil {
		return fmt.Errorf("could not load private key for signature: %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, ecPriv, quoteHash[:])
	if err != nil {
		return fmt.Errorf("could not sign quote hash: %v", err)
	}

	sig := ecdsaSignature{SigR: r, SigS: s}
	sigMarshalled, err := asn1.Marshal(sig)
	if err != nil {
		return fmt.Errorf("could not marshal signature: %v", err)
	}

	log.Debugf("calculated signature, r: %s, s: %s", sig.R().String(), sig.S().String())

	err = ioutil.WriteFile(sigOutPath, sigMarshalled, 0644)
	if err != nil {
		return fmt.Errorf("could not write signature: %v", err)
	}
	err = ioutil.WriteFile(quoteOutPath, quoteSerialized, 0644)
	if err != nil {
		return fmt.Errorf("could not write quote: %v", err)
	}
	return nil
}
