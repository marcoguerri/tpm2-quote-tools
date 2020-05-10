package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type algo uint16

const (
	tpmAlgSha1   algo = 0x4
	tpmAlgSha256      = 0xB
	tpmAlgSm3256      = 0x12
	tpmAlgNull        = 0x10
)

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

type buffer []byte

func (b *buffer) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("0x%x", *b)
	return json.Marshal(s)
}

func (b *buffer) MarshalBinary() ([]byte, error) {
	buff := make([]byte, len(*b))
	copy(buff, *b)
	return buff, nil
}

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

type pcrSelect []byte

func (p *pcrSelect) MarshalJSON() ([]byte, error) {
	pcrs := make([]string, 0)
	for i := 0; i < len(*p); i++ {
		for j := uint8(0); j < 8; j++ {
			if (*p)[i]&(uint8(0x1)<<j) != 0x0 {
				pcrs = append(pcrs, fmt.Sprintf("%d", i*8+int(j)))
			}
		}
	}
	return json.Marshal(strings.Join(pcrs, ","))
}

func (p *pcrSelect) MarshalBinary() ([]byte, error) {
	buff := make([]byte, len(*p))
	copy(buff, *p)
	return buff, nil
}

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
func readQuote(quotePath string) (*quote, error) {

	if len(quotePath) == 0 {
		return nil, fmt.Errorf("quote path not specified")
	}

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

	// PcrSelect->Count
	pcrSelect := &q.QuoteInfo.PcrSelect
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelect.Count); err != nil {
		return nil, fmt.Errorf("couldn't read PcrSelect Count: %v", err)
	}
	// PcrSelect->PcrSelection->Hash
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelect.PcrSelection.Hash); err != nil {
		return nil, fmt.Errorf("couldn't read PcrSelection Hash: %v", err)
	}

	// PcrSelection->SizeofSelect
	pcrSelection := &q.QuoteInfo.PcrSelect.PcrSelection
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelection.SizeofSelect); err != nil {
		return nil, fmt.Errorf("couldn't read SizeofSelect: %v", err)
	}
	q.QuoteInfo.PcrSelect.PcrSelection.PcrSelect = make([]byte, pcrSelection.SizeofSelect)
	if binary.Read(quoteFile, binary.BigEndian, &pcrSelection.PcrSelect); err != nil {
		return nil, fmt.Errorf("couldn't read PcrSelect: %v", err)
	}

	pcrDigest := &q.QuoteInfo.PcrDigest
	// PcrDigest->Size
	if binary.Read(quoteFile, binary.BigEndian, &pcrDigest.Size); err != nil {
		return nil, fmt.Errorf("couldn't read quoteInfo.pcrDigest.size: %v", err)
	}
	q.QuoteInfo.PcrDigest.Buffer = make([]byte, pcrDigest.Size)
	if binary.Read(quoteFile, binary.BigEndian, &pcrDigest.Buffer); err != nil {
		return nil, fmt.Errorf("couldn't read PcrDigest buffer: %v", err)
	}
	return &q, nil
}

func validateQuote(quote *quote, sigPath string) (bool, error) {
	quoteSerialized, _ := quote.MarshalBinary()
	sum := sha256.Sum256(quoteSerialized)
	fmt.Printf("SHA reconstructed quote: %x\n", sum)
	return false, nil
}

func calculatePcrDigest(pcrReadPath string) ([]byte, error) {

	if len(pcrReadPath) == 0 {
		return nil, fmt.Errorf("pcr read path not specified")
	}

	file, err := os.Open(pcrReadPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	r := regexp.MustCompile(`([0-9]+)\s?: 0x([0-9A-F]+)`)

	buffer := make([]byte, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		str := scanner.Text()
		matches := r.FindStringSubmatch(str)
		if strings.HasPrefix(str, "sha") {
			continue
		}
		if len(matches) != 3 {
			return nil, fmt.Errorf("unexpected match: %s", str)
		}
		pcrHex, err := hex.DecodeString(matches[2])
		if err != nil {
			return nil, fmt.Errorf("could not decode pcr value: %s", matches[2])
		}
		if len(pcrHex) != 32 {
			continue
		}
		pcrValue, err := strconv.ParseInt(matches[1], 16, 10)
		if err != nil {
			return nil, fmt.Errorf("could not parse pcr register number")
		}
		if pcrValue == 0 || pcrValue == 1 || pcrValue == 2 || pcrValue == 3 {
			buffer = append(buffer, pcrHex...)
		}
	}
	sum := sha256.Sum256(buffer)
	log.Printf("Hash: %x\n", sum)

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if err != nil {
		return nil, fmt.Errorf("could not read pcr file: %v", err)
	}
	return sum[:], nil
}
