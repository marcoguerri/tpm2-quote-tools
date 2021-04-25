# tpm2-quote-tools
This is a simple tool to read and manipulate TPM2 quotes. It was written while experimenting with [tpmfail](https://tpm.fail/). It supports the following commands:

* Validating an EC keypair, where the pub key is serialized according to RFC5480 and the priv key is provided with its integer representation
* Validating a TPM quote, given a PCR file reading
* Tampering a quote, based on a modified PCR file

It assumes to be working with a NIST P-256 Curve.

### P-256 assumption

The assumption to be working with P-256 comes from the fact that the `SubjectPublicKeyInfo` structure
produced by tpm2-tools (at least version 4.0-rc2, which was the one I used to extract 
[ak.pub](https://github.com/marcoguerri/tpm2-quote-tools/blob/master/data/ak.pub) and experiment with tpmfail) 
doesn't seem  to be fully compliant with PKIX and cannot be unmarshalled with `ParsePKIXPublicKey`.

PKIX (RFC5280) requires the following format:
```
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}
```

`ParsePKIXPublicKey` is failing with "failed to parse ECDSA parameters as named curve",
which seems to be deriving from trying to extract the curve type from
 `Algorithm.Parameters.FullBytes` in the `pkix.AlgorithmIdentifier` object. In particular,
from [x509.go](https://golang.org/src/crypto/x509/x509.go):

```
case ECDSA:
        paramsData := keyData.Algorithm.Parameters.FullBytes
        namedCurveOID := new(asn1.ObjectIdentifier)
        rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
        if err != nil {
            return nil, errors.New("x509: failed to parse ECDSA parameters as named curve")
        }
```

where `namedCurveOID` is eventually used to build the right curse, e.g. `elliptic.P256(). This
problem should be coming solely from the tooling, but I haven't investigated it further.


### Validate ECDSA keypair
```
 ./tpm2-quote-tools validateKeypair -privKey 123.... --pubKeyPath ak.pub
{
  "X": 83480738740571363643324029101585429304839996582896622312114556128429276170770,
  "Y": 31332509983944448906473882585486887031546885874433110787215501175612644198303,
  "Priv": 123...,
  "Valid": true
 }
 ```
 
 
 ## Validate quote
 `validateQuote` command does only basic validation of the signature of the quote and the PCR register digest.
 ```
 ./tpm2-quote-tools -debug validateQuote  -pcrReadPath pcrs -quotePath quote.out -sigPath sig.out -pubKeyPath ak.pub  -privKey 123...
{
  "Magic": "0xff544347",
  "StType": "0x8018",
  "QualifiedSigner": {
   "Size": 34,
   "Name": "0x000bc0cae8498b1672f3a59465d1c7550186e7bb854ebe1c73d32a63fcd381be7116"
  },
  "ExtraData": {
   "Size": 3,
   "Buffer": "0xabc123"
  },
  "ClockInfo": {
   "Clock": 579462030,
   "ResetCount": 6,
   "RestartCount": 0,
   "YesNo": 1
  },
  "FirmwareVersion": "...",
  "QuoteInfo": {
   "PcrSelect": {
    "Count": 1,
    "PcrSelection": {
     "Hash": 11,
     "SizeofSelect": 3,
     "PcrSelect": "0,1,2,3"
    }
   },
   "PcrDigest": {
    "Size": 32,
    "Buffer": "0xb54daa5a817ddda5e6ff7a533dd639b9294c8ebd163d15a09142d046c3c4dca7"
   }
  }
 }
DEBU[0000] sha256sum calculated from quote: 0x36508eca394ce64c4eca8eca1557137db8b185465054044c192f2ca00afe066d 
DEBU[0000] reading signature file at sig.out      
DEBU[0000] ecdsa signature, r: 111363902270336560310064823465267952429958334463429462940652152104343902580681, s: 38244762622328238605270552925184855082267863709725176991353603896491389561246 
DEBU[0000] validating quote signature with ecPub, X: 83480738740571363643324029101585429304839996582896622312114556128429276170770, Y: 31332509983944448906473882585486887031546885874433110787215501175612644198303 
DEBU[0000] signature OK                                 
DEBU[0000] validating pcr hash against pcrs
DEBU[0000] reading pcr file at pcrs
DEBU[0000] pcr file: found [0] : [...] 
DEBU[0000] pcr file: found [1] : [...] 
[...]
DEBU[0000] digest match: 0xb54daa5a817ddda5e6ff7a533dd639b9294c8ebd163d15a09142d046c3c4dca7 == 0xb54daa5a817ddda5e6ff7a533dd639b9294c8ebd163d15a09142d046c3c4dca7 
OK
```

## Tamper quote
Tamper quote can be used to modify the PCR digest in an existing quote, based on a modified pcr file, and re-calculate the signature.
```
./tpm2-quote-tools -debug forgeQuote -pcrReadPath pcrs.forged -privKey 123...
2358 -pubKeyPath ak.pub -quotePath quote.out -sigOutPath sigForged.out -quoteOutPath quoteForged.out
DEBU[0000] reading pcr file at pcrs.forged              
DEBU[0000] pcr file: found [0] : [...] 
DEBU[0000] pcr file: found [1] : [...] 
[...]
DEBU[0000] signing 0x3f3b56ce242c9daaaa59812bdf9f30421048e333f4e44089860748e7769edb89 
DEBU[0000] calculated signature, r: 108360506779383934389187539972624208747061077985692324975265347036204466096619, s: 111915589499407566637626902186915864276073926565433784980906979210501747227395
```


The tampered quote can be then validated with `validateQuote` command:
```
./tpm2-quote-tools -debug validateQuote  -pcrReadPath pcrs.forged -quotePath quoteForged.out -sigPath sigForged.out -pubKeyPath data/ak.pub -privKey 123...               
{
  "Magic": "0xff544347",
  "StType": "0x8018",
  "QualifiedSigner": {
   "Size": 34,
   "Name": "0x000bc0cae8498b1672f3a59465d1c7550186e7bb854ebe1c73d32a63fcd381be7116"
  },
  "ExtraData": {
   "Size": 3,
   "Buffer": "0xabc123"
  },
  "ClockInfo": {
   "Clock": 579462030,
   "ResetCount": 6,
   "RestartCount": 0,
   "YesNo": 1
  },
  "FirmwareVersion": "0x49000444a01164",
  "QuoteInfo": {
   "PcrSelect": {
    "Count": 1,
    "PcrSelection": {
     "Hash": 11,
     "SizeofSelect": 3,
     "PcrSelect": "0,1,2,3"
    }
   },
   "PcrDigest": {
    "Size": 32,
    "Buffer": "0x2987d731e24966251ceceab7d7102124cd8e2bc44c4b9c6104e33d7d07e961ef"
   }
  }
 }
DEBU[0000] sha256sum calculated from quote: 0x3f3b56ce242c9daaaa59812bdf9f30421048e333f4e44089860748e7769edb89 
DEBU[0000] reading signature file at sigForged.out      
DEBU[0000] ecdsa signature, r: 108360506779383934389187539972624208747061077985692324975265347036204466096619, s: 111915589499407566637626902186915864276073926565433784980906979210501747227395 
DEBU[0000] validating quote signature with ecPub, X: 83480738740571363643324029101585429304839996582896622312114556128429276170770, Y: 31332509983944448906473882585486887031546885874433110787215501175612644198303 
DEBU[0000] signature OK                                 
DEBU[0000] validating pcr hash against pcrs.forged      
DEBU[0000] reading pcr file at pcrs.forged              
DEBU[0000] pcr file: found [0] : [...] 
DEBU[0000] pcr file: found [1] : [...] 
DEBU[0000] digest match: 0x2987d731e24966251ceceab7d7102124cd8e2bc44c4b9c6104e33d7d07e961ef == 0x2987d731e24966251ceceab7d7102124cd8e2bc44c4b9c6104e33d7d07e961ef 
OK
```
