// Package cms provides CMS (Cryptographic Message Syntax) support for PDF signatures.
package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sort"
	"time"
)

// OIDs for CMS and signature algorithms
var (
	// Content types
	OIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// Digest algorithms
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature algorithms
	OIDRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Signed attributes
	OIDContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// Certificate extensions
	OIDSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// Common errors
var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrMissingCertificate   = errors.New("missing certificate")
)

// AlgorithmIdentifier represents an algorithm identifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// ContentInfo represents a CMS ContentInfo structure.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// SignedData represents a CMS SignedData structure.
type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0,set"`
	CRLs             []asn1.RawValue `asn1:"optional,implicit,tag:1"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

// EncapsulatedContentInfo represents encapsulated content.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// SignerInfo represents a signer's information.
// Note: SID is IssuerAndSerialNumber directly (not wrapped in SignerIdentifier)
// because SignerIdentifier is a CHOICE in ASN.1, not a SEQUENCE.
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,implicit,tag:0,set"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      []Attribute `asn1:"optional,implicit,tag:1,set"`
}

// SignerInfoRaw is used for parsing to capture raw signed attributes bytes.
type SignerInfoRaw struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// SignedDataRaw is used for parsing to capture raw signer info.
type SignedDataRaw struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0,set"`
	CRLs             []asn1.RawValue `asn1:"optional,implicit,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// SignerIdentifier identifies the signer.
type SignerIdentifier struct {
	IssuerAndSerialNumber IssuerAndSerialNumber `asn1:"optional"`
	SubjectKeyIdentifier  []byte                `asn1:"optional,implicit,tag:0"`
}

// IssuerAndSerialNumber identifies a certificate by issuer and serial.
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute represents a CMS attribute.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// SigningCertificateV2 represents the signing certificate attribute.
type SigningCertificateV2 struct {
	Certs []ESSCertIDv2
}

// ESSCertIDv2 represents a certificate identifier.
type ESSCertIDv2 struct {
	HashAlgorithm AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  IssuerSerial `asn1:"optional"`
}

// IssuerSerial identifies a certificate by issuer and serial.
type IssuerSerial struct {
	Issuer       GeneralNames
	SerialNumber *big.Int
}

// GeneralNames represents a sequence of GeneralName.
type GeneralNames struct {
	Names []asn1.RawValue
}

// SignatureAlgorithm represents a signature algorithm with its hash.
type SignatureAlgorithm struct {
	DigestAlgorithm    asn1.ObjectIdentifier
	SignatureAlgorithm asn1.ObjectIdentifier
	Hash               crypto.Hash
}

// Common signature algorithms
var (
	SHA256WithRSA = SignatureAlgorithm{
		DigestAlgorithm:    OIDSHA256,
		SignatureAlgorithm: OIDSHA256WithRSA,
		Hash:               crypto.SHA256,
	}
	SHA384WithRSA = SignatureAlgorithm{
		DigestAlgorithm:    OIDSHA384,
		SignatureAlgorithm: OIDSHA384WithRSA,
		Hash:               crypto.SHA384,
	}
	SHA512WithRSA = SignatureAlgorithm{
		DigestAlgorithm:    OIDSHA512,
		SignatureAlgorithm: OIDSHA512WithRSA,
		Hash:               crypto.SHA512,
	}
	SHA256WithECDSA = SignatureAlgorithm{
		DigestAlgorithm:    OIDSHA256,
		SignatureAlgorithm: OIDECDSAWithSHA256,
		Hash:               crypto.SHA256,
	}
	SHA384WithECDSA = SignatureAlgorithm{
		DigestAlgorithm:    OIDSHA384,
		SignatureAlgorithm: OIDECDSAWithSHA384,
		Hash:               crypto.SHA384,
	}
	SHA512WithECDSA = SignatureAlgorithm{
		DigestAlgorithm:    OIDSHA512,
		SignatureAlgorithm: OIDECDSAWithSHA512,
		Hash:               crypto.SHA512,
	}
)

// CMSBuilder builds CMS signed data structures.
type CMSBuilder struct {
	Certificate          *x509.Certificate
	CertChain            []*x509.Certificate
	PrivateKey           crypto.Signer
	Algorithm            SignatureAlgorithm
	SigningTime          time.Time
	PrecomputedSignature []byte // For remote signing (CSC, etc.)
}

// NewCMSBuilder creates a new CMS builder.
func NewCMSBuilder(cert *x509.Certificate, key crypto.Signer, alg SignatureAlgorithm) *CMSBuilder {
	return &CMSBuilder{
		Certificate: cert,
		PrivateKey:  key,
		Algorithm:   alg,
		SigningTime: time.Now().UTC(),
	}
}

// SetCertificateChain sets the certificate chain.
func (b *CMSBuilder) SetCertificateChain(chain []*x509.Certificate) {
	b.CertChain = chain
}

// SetSigningTime sets the signing time.
func (b *CMSBuilder) SetSigningTime(t time.Time) {
	b.SigningTime = t.UTC()
}

// SetPrecomputedSignature sets a pre-computed signature from a remote signer.
// When set, the Sign method will use this instead of computing the signature locally.
func (b *CMSBuilder) SetPrecomputedSignature(sig []byte) {
	b.PrecomputedSignature = sig
}

// SignedAttributesForSigning returns signed attributes and the DER-encoded SET
// bytes used for signature generation.
func (b *CMSBuilder) SignedAttributesForSigning(data []byte) ([]Attribute, []byte, error) {
	h := b.getHash()
	h.Write(data)
	messageDigest := h.Sum(nil)

	signedAttrs, err := b.buildSignedAttributes(messageDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build signed attributes: %w", err)
	}

	signedAttrs = derSortAttributes(signedAttrs)

	signedAttrsBytes, err := asn1.Marshal(signedAttrs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal signed attributes: %w", err)
	}

	signedAttrsBytes[0] = 0x31 // SET tag

	return signedAttrs, signedAttrsBytes, nil
}

// Sign creates a CMS signature for the given data.
func (b *CMSBuilder) Sign(data []byte) ([]byte, error) {
	signedAttrs, signedAttrsBytes, err := b.SignedAttributesForSigning(data)
	if err != nil {
		return nil, err
	}

	h := b.getHash()
	h.Write(signedAttrsBytes)
	attrDigest := h.Sum(nil)

	// Get signature - either precomputed or compute locally
	var signature []byte
	if b.PrecomputedSignature != nil {
		signature = b.PrecomputedSignature
	} else {
		var err error
		signature, err = b.signDigest(attrDigest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %w", err)
		}
	}

	// Build SignerInfo
	signerInfo := SignerInfo{
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer:       asn1.RawValue{FullBytes: b.Certificate.RawIssuer},
			SerialNumber: b.Certificate.SerialNumber,
		},
		DigestAlgorithm: AlgorithmIdentifier{
			Algorithm:  b.Algorithm.DigestAlgorithm,
			Parameters: asn1.RawValue{Tag: 5}, // NULL
		},
		SignedAttrs: signedAttrs,
		SignatureAlgorithm: AlgorithmIdentifier{
			Algorithm:  b.Algorithm.SignatureAlgorithm,
			Parameters: signatureAlgorithmParameters(b.Algorithm.SignatureAlgorithm),
		},
		Signature: signature,
	}

	// Build SignedData
	signedData := SignedData{
		Version: 1,
		DigestAlgorithms: []AlgorithmIdentifier{
			{
				Algorithm:  b.Algorithm.DigestAlgorithm,
				Parameters: asn1.RawValue{Tag: 5},
			},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
			// No encapsulated content for detached signature
		},
		SignerInfos: []SignerInfo{signerInfo},
	}

	// Add certificates
	signedData.Certificates = append(signedData.Certificates,
		asn1.RawValue{FullBytes: b.Certificate.Raw})
	for _, cert := range b.CertChain {
		signedData.Certificates = append(signedData.Certificates,
			asn1.RawValue{FullBytes: cert.Raw})
	}

	// Marshal SignedData
	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	// Wrap in ContentInfo
	contentInfo := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedDataBytes},
	}

	return asn1.Marshal(contentInfo)
}

func signatureAlgorithmParameters(oid asn1.ObjectIdentifier) asn1.RawValue {
	switch {
	case oid.Equal(OIDSHA256WithRSA),
		oid.Equal(OIDSHA384WithRSA),
		oid.Equal(OIDSHA512WithRSA):
		return asn1.RawValue{Tag: 5} // NULL
	default:
		return asn1.RawValue{} // omit
	}
}

// buildSignedAttributes builds the signed attributes.
func (b *CMSBuilder) buildSignedAttributes(messageDigest []byte) ([]Attribute, error) {
	var attrs []Attribute

	// Content type attribute
	contentTypeValue, _ := asn1.Marshal(OIDData)
	attrs = append(attrs, Attribute{
		Type:   OIDContentType,
		Values: []asn1.RawValue{{FullBytes: contentTypeValue}},
	})

	// Message digest attribute
	digestValue, _ := asn1.Marshal(messageDigest)
	attrs = append(attrs, Attribute{
		Type:   OIDMessageDigest,
		Values: []asn1.RawValue{{FullBytes: digestValue}},
	})

	// Signing time attribute
	signingTimeValue, _ := asn1.Marshal(b.SigningTime)
	attrs = append(attrs, Attribute{
		Type:   OIDSigningTime,
		Values: []asn1.RawValue{{FullBytes: signingTimeValue}},
	})

	// Signing certificate v2 attribute (ESS-signing-certificate-v2)
	certHash := b.hashCertificate()
	issuerSerial := IssuerSerial{
		Issuer: GeneralNames{
			Names: []asn1.RawValue{
				{
					Class:      asn1.ClassContextSpecific,
					Tag:        4, // directoryName
					IsCompound: true,
					Bytes:      b.Certificate.RawIssuer,
				},
			},
		},
		SerialNumber: b.Certificate.SerialNumber,
	}
	signingCert := SigningCertificateV2{
		Certs: []ESSCertIDv2{
			{
				HashAlgorithm: AlgorithmIdentifier{
					Algorithm:  b.Algorithm.DigestAlgorithm,
					Parameters: asn1.RawValue{Tag: 5},
				},
				CertHash:     certHash,
				IssuerSerial: issuerSerial,
			},
		},
	}
	signingCertValue, _ := asn1.Marshal(signingCert)
	attrs = append(attrs, Attribute{
		Type:   OIDSigningCertificateV2,
		Values: []asn1.RawValue{{FullBytes: signingCertValue}},
	})

	return attrs, nil
}

// getHash returns the hash function for the algorithm.
func (b *CMSBuilder) getHash() hash.Hash {
	switch b.Algorithm.Hash {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

// hashCertificate computes the certificate hash.
func (b *CMSBuilder) hashCertificate() []byte {
	h := b.getHash()
	h.Write(b.Certificate.Raw)
	return h.Sum(nil)
}

// signDigest signs the digest with the private key.
func (b *CMSBuilder) signDigest(digest []byte) ([]byte, error) {
	switch key := b.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, b.Algorithm.Hash, digest)
	default:
		return b.PrivateKey.Sign(rand.Reader, digest, b.Algorithm.Hash)
	}
}

// ParseCMSSignature parses a CMS signed data structure.
func ParseCMSSignature(data []byte) (*SignedData, error) {
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("expected SignedData, got %v", contentInfo.ContentType)
	}

	var signedData SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	return &signedData, nil
}

// VerifyCMSSignature verifies a CMS signature against the data.
func VerifyCMSSignature(cmsData, signedContent []byte) error {
	// Parse using raw types to preserve signed attributes bytes
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(cmsData, &contentInfo); err != nil {
		return fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(OIDSignedData) {
		return fmt.Errorf("expected SignedData, got %v", contentInfo.ContentType)
	}

	var signedDataRaw SignedDataRaw
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedDataRaw); err != nil {
		return fmt.Errorf("failed to parse SignedData: %w", err)
	}

	if len(signedDataRaw.SignerInfos) == 0 {
		return fmt.Errorf("no signer infos")
	}

	// Parse signer info using raw type to get raw signed attributes
	var signerInfoRaw SignerInfoRaw
	if _, err := asn1.Unmarshal(signedDataRaw.SignerInfos[0].FullBytes, &signerInfoRaw); err != nil {
		return fmt.Errorf("failed to parse SignerInfo: %w", err)
	}

	// Get signer certificate
	var signerCert *x509.Certificate
	for _, certRaw := range signedDataRaw.Certificates {
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			continue
		}

		// Match by issuer and serial number
		if signerInfoRaw.SID.SerialNumber != nil {
			if cert.SerialNumber.Cmp(signerInfoRaw.SID.SerialNumber) == 0 {
				signerCert = cert
				break
			}
		}
	}

	if signerCert == nil {
		return ErrMissingCertificate
	}

	// Verify message digest
	h, err := getHashFromOID(signerInfoRaw.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	h.Write(signedContent)
	computedDigest := h.Sum(nil)

	// Parse signed attributes to find message digest
	// The FullBytes includes the implicit [0] tag wrapping a SEQUENCE of Attributes
	// We need to parse the content (Bytes) as a SEQUENCE of Attributes
	var signedAttrs []Attribute
	if len(signerInfoRaw.SignedAttrs.Bytes) > 0 {
		// Bytes is the content without the implicit [0] tag
		// It's a SEQUENCE of Attribute, but we need to parse as slice
		rest := signerInfoRaw.SignedAttrs.Bytes
		for len(rest) > 0 {
			var attr Attribute
			var err error
			rest, err = asn1.Unmarshal(rest, &attr)
			if err != nil {
				return fmt.Errorf("failed to parse signed attribute: %w", err)
			}
			signedAttrs = append(signedAttrs, attr)
		}
	}

	var foundDigest []byte
	for _, attr := range signedAttrs {
		if attr.Type.Equal(OIDMessageDigest) && len(attr.Values) > 0 {
			if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &foundDigest); err == nil {
				break
			}
		}
	}

	if foundDigest == nil {
		return fmt.Errorf("message digest attribute not found")
	}

	if !equalBytes(computedDigest, foundDigest) {
		return fmt.Errorf("message digest mismatch")
	}

	// Re-marshal signed attributes to produce the exact same bytes as during signing
	// During signing: asn1.Marshal([]Attribute) produces SEQUENCE, then tag changed to SET (0x31)
	// We need to do the same here for verification
	signedAttrsBytes, err := asn1.Marshal(signedAttrs)
	if err != nil {
		return fmt.Errorf("failed to marshal signed attributes for verification: %w", err)
	}
	signedAttrsBytes[0] = 0x31 // SET tag (same as during signing)

	h, _ = getHashFromOID(signerInfoRaw.DigestAlgorithm.Algorithm)
	h.Write(signedAttrsBytes)
	attrDigest := h.Sum(nil)

	// Verify with certificate public key
	hashType := getHashType(signerInfoRaw.DigestAlgorithm.Algorithm)
	if err := verifySignature(signerCert.PublicKey, hashType, attrDigest, signerInfoRaw.Signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// getHashFromOID returns a hash function for the given OID.
func getHashFromOID(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(OIDSHA256):
		return sha256.New(), nil
	case oid.Equal(OIDSHA384):
		return sha512.New384(), nil
	case oid.Equal(OIDSHA512):
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, oid)
	}
}

// getHashType returns the crypto.Hash for the given OID.
func getHashType(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(OIDSHA384):
		return crypto.SHA384
	case oid.Equal(OIDSHA512):
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// verifySignature verifies a signature using the public key.
func verifySignature(pub interface{}, hashType crypto.Hash, digest, sig []byte) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, hashType, digest, sig)
	default:
		return fmt.Errorf("%w: unsupported key type", ErrUnsupportedAlgorithm)
	}
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// derSortAttributes sorts attributes by their DER encoding.
// This ensures consistent ordering as Go's asn1 package sorts SET elements.
func derSortAttributes(attrs []Attribute) []Attribute {
	// Marshal each attribute to get its DER encoding
	type attrWithDER struct {
		attr Attribute
		der  []byte
	}
	attrsWithDER := make([]attrWithDER, len(attrs))
	for i, attr := range attrs {
		der, _ := asn1.Marshal(attr)
		attrsWithDER[i] = attrWithDER{attr: attr, der: der}
	}

	// Sort by DER encoding (lexicographic comparison)
	sort.Slice(attrsWithDER, func(i, j int) bool {
		return bytes.Compare(attrsWithDER[i].der, attrsWithDER[j].der) < 0
	})

	// Extract sorted attributes
	result := make([]Attribute, len(attrs))
	for i, awd := range attrsWithDER {
		result[i] = awd.attr
	}
	return result
}

// GetSignerCertificates extracts signer certificates from CMS data.
func GetSignerCertificates(cmsData []byte) ([]*x509.Certificate, error) {
	signedData, err := ParseCMSSignature(cmsData)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, certRaw := range signedData.Certificates {
		cert, err := x509.ParseCertificate(certRaw.FullBytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// GetSigningTime extracts the signing time from CMS data.
func GetSigningTime(cmsData []byte) (time.Time, error) {
	signedData, err := ParseCMSSignature(cmsData)
	if err != nil {
		return time.Time{}, err
	}

	if len(signedData.SignerInfos) == 0 {
		return time.Time{}, fmt.Errorf("no signer infos")
	}

	for _, attr := range signedData.SignerInfos[0].SignedAttrs {
		if attr.Type.Equal(OIDSigningTime) && len(attr.Values) > 0 {
			var signingTime time.Time
			if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &signingTime); err == nil {
				return signingTime, nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("signing time not found")
}

// OID for RFC 3161 timestamp token attribute
var OIDTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// TSTInfo represents the TSTInfo structure from RFC 3161
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	// Other fields omitted for simplicity
}

// MessageImprint represents the hash of the timestamped data
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// GetTimestampTime extracts the timestamp time from an RFC 3161 timestamp token in the CMS data.
// Returns zero time if no timestamp is present.
func GetTimestampTime(cmsData []byte) (time.Time, error) {
	// Parse using raw types to get unsigned attributes
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(cmsData, &contentInfo); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	if !contentInfo.ContentType.Equal(OIDSignedData) {
		return time.Time{}, fmt.Errorf("expected SignedData, got %v", contentInfo.ContentType)
	}

	var signedDataRaw SignedDataRaw
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedDataRaw); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	if len(signedDataRaw.SignerInfos) == 0 {
		return time.Time{}, fmt.Errorf("no signer infos")
	}

	// Parse signer info to get unsigned attributes
	var signerInfoRaw SignerInfoRaw
	if _, err := asn1.Unmarshal(signedDataRaw.SignerInfos[0].FullBytes, &signerInfoRaw); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse SignerInfo: %w", err)
	}

	// Parse unsigned attributes
	if len(signerInfoRaw.UnsignedAttrs.Bytes) == 0 {
		return time.Time{}, fmt.Errorf("no unsigned attributes (no timestamp)")
	}

	// Parse unsigned attributes
	rest := signerInfoRaw.UnsignedAttrs.Bytes
	for len(rest) > 0 {
		var attr Attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			break
		}

		// Check if this is the timestamp token attribute
		if attr.Type.Equal(OIDTimeStampToken) && len(attr.Values) > 0 {
			// The value is a ContentInfo containing a SignedData (the timestamp token)
			return parseTimestampToken(attr.Values[0].FullBytes)
		}
	}

	return time.Time{}, fmt.Errorf("timestamp token not found")
}

// parseTimestampToken parses an RFC 3161 timestamp token and returns the generation time.
func parseTimestampToken(tokenData []byte) (time.Time, error) {
	// Parse the outer ContentInfo
	var tsContentInfo ContentInfo
	if _, err := asn1.Unmarshal(tokenData, &tsContentInfo); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp ContentInfo: %w", err)
	}

	if !tsContentInfo.ContentType.Equal(OIDSignedData) {
		return time.Time{}, fmt.Errorf("timestamp token is not SignedData")
	}

	// Parse the SignedData
	var tsSignedData SignedData
	if _, err := asn1.Unmarshal(tsContentInfo.Content.Bytes, &tsSignedData); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp SignedData: %w", err)
	}

	// The encapsulated content is the TSTInfo
	if !tsSignedData.EncapContentInfo.EContentType.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}) {
		return time.Time{}, fmt.Errorf("unexpected timestamp content type")
	}

	// Parse the TSTInfo
	var tstInfoBytes []byte
	if _, err := asn1.Unmarshal(tsSignedData.EncapContentInfo.EContent.Bytes, &tstInfoBytes); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse TSTInfo bytes: %w", err)
	}

	var tstInfo TSTInfo
	if _, err := asn1.Unmarshal(tstInfoBytes, &tstInfo); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse TSTInfo: %w", err)
	}

	return tstInfo.GenTime, nil
}

// HasTimestamp checks if the CMS data contains an RFC 3161 timestamp token.
func HasTimestamp(cmsData []byte) bool {
	_, err := GetTimestampTime(cmsData)
	return err == nil
}
