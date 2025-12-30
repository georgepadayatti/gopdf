// Package crypt provides PDF encryption and decryption.
// This file implements PDF MAC (Message Authentication Code) as per ISO 32004.
package crypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// PDF MAC related errors
var (
	ErrPdfMacValidation     = errors.New("PDF MAC validation error")
	ErrPdfMacInvalidMAC     = errors.New("PDF MAC token has invalid MAC")
	ErrPdfMacMissingData    = errors.New("missing required PDF MAC data")
	ErrPdfMacInvalidDigest  = errors.New("document digest mismatch")
	ErrPdfMacUnsupportedAlg = errors.New("unsupported MAC algorithm")
)

// AllowedMDAlgorithms specifies permissible message digest algorithms for PDF MAC tokens.
var AllowedMDAlgorithms = map[string]bool{
	"sha256":   true,
	"sha3_256": true,
	"sha384":   true,
	"sha3_384": true,
	"sha512":   true,
	"sha3_512": true,
	"shake256": true,
}

// ISO32004 OIDs
var (
	// OID for PDF MAC integrity info content type: 1.0.32004.1.0
	OIDPdfMacIntegrityInfo = asn1.ObjectIdentifier{1, 0, 32004, 1, 0}
	// OID for PDF MAC wrap KDF: 1.0.32004.1.1
	OIDPdfMacWrapKDF = asn1.ObjectIdentifier{1, 0, 32004, 1, 1}
	// OID for PDF MAC data attribute: 1.0.32004.1.2
	OIDPdfMacData = asn1.ObjectIdentifier{1, 0, 32004, 1, 2}
	// OID for HMAC-SHA256
	OIDHmacSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	// OID for AES-256 key wrap
	OIDAes256Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
	// OID for AuthenticatedData content type
	OIDAuthenticatedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 2}
)

// PdfMacIntegrityInfo represents the encapsulated content in a PDF MAC token.
// ASN.1 structure:
//
//	PdfMacIntegrityInfo ::= SEQUENCE {
//	    version         INTEGER,
//	    dataDigest      OCTET STRING,
//	    signatureDigest [0] IMPLICIT OCTET STRING OPTIONAL
//	}
type PdfMacIntegrityInfo struct {
	Version         int
	DataDigest      []byte
	SignatureDigest []byte `asn1:"optional,tag:0"`
}

// MACLocation indicates where the MAC is stored in the PDF.
type MACLocation string

const (
	// MACLocationStandalone indicates MAC is in AuthCode dictionary.
	MACLocationStandalone MACLocation = "/Standalone"
	// MACLocationAttachedToSig indicates MAC is attached to a signature.
	MACLocationAttachedToSig MACLocation = "/AttachedToSig"
)

// PdfMacTokenHandler creates and validates PDF MAC tokens.
type PdfMacTokenHandler struct {
	macKEK      []byte // MAC key encryption key
	mdAlgorithm string // Message digest algorithm
}

// NewPdfMacTokenHandler creates a new PDF MAC token handler.
func NewPdfMacTokenHandler(macKEK []byte, mdAlgorithm string) *PdfMacTokenHandler {
	return &PdfMacTokenHandler{
		macKEK:      macKEK,
		mdAlgorithm: mdAlgorithm,
	}
}

// NewPdfMacTokenHandlerFromKeyMaterial derives the handler from file encryption key and salt.
func NewPdfMacTokenHandlerFromKeyMaterial(fileEncryptionKey, kdfSalt []byte, mdAlgorithm string) (*PdfMacTokenHandler, error) {
	macKEK, err := DeriveMacKEK(fileEncryptionKey, kdfSalt)
	if err != nil {
		return nil, err
	}

	return &PdfMacTokenHandler{
		macKEK:      macKEK,
		mdAlgorithm: mdAlgorithm,
	}, nil
}

// DeriveMacKEK derives the MAC key encryption key using HKDF.
// Uses HKDF-SHA256 with salt and info="PDFMAC".
func DeriveMacKEK(fileEncryptionKey, kdfSalt []byte) ([]byte, error) {
	// HKDF with SHA-256
	hkdfReader := hkdf.New(sha256.New, fileEncryptionKey, kdfSalt, []byte("PDFMAC"))

	macKEK := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, macKEK); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}

	return macKEK, nil
}

// MDAlgorithm returns the message digest algorithm.
func (h *PdfMacTokenHandler) MDAlgorithm() string {
	return h.mdAlgorithm
}

// GetHashFunc returns the hash function for the configured algorithm.
func (h *PdfMacTokenHandler) GetHashFunc() (func() hash.Hash, error) {
	return GetHashFunc(h.mdAlgorithm)
}

// GetHashFunc returns a hash function constructor for the given algorithm name.
func GetHashFunc(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "sha256":
		return sha256.New, nil
	case "sha384":
		return sha512.New384, nil
	case "sha512":
		return sha512.New, nil
	case "sha3_256":
		return sha3.New256, nil
	case "sha3_384":
		return sha3.New384, nil
	case "sha3_512":
		return sha3.New512, nil
	case "shake256":
		return func() hash.Hash { return sha3.NewShake256() }, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrPdfMacUnsupportedAlg, algorithm)
	}
}

// ComputeMAC computes HMAC-SHA256 of the given data.
func (h *PdfMacTokenHandler) ComputeMAC(macKey, data []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// DetermineTokenSize calculates the size of a PDF MAC token.
func (h *PdfMacTokenHandler) DetermineTokenSize(includeSignatureDigest bool) (int, error) {
	hashFunc, err := h.GetHashFunc()
	if err != nil {
		return 0, err
	}

	// Create dummy hash
	hasher := hashFunc()
	dummyHash := make([]byte, hasher.Size())

	var sigDigest []byte
	if includeSignatureDigest {
		sigDigest = dummyHash
	}

	token, err := h.BuildPdfMacToken(dummyHash, sigDigest, true)
	if err != nil {
		return 0, err
	}

	return len(token), nil
}

// BuildPdfMacToken builds a PDF MAC token (CMS AuthenticatedData).
func (h *PdfMacTokenHandler) BuildPdfMacToken(documentDigest, signatureDigest []byte, dryRun bool) ([]byte, error) {
	// Generate or use dummy MAC key
	var macKey []byte
	if dryRun {
		macKey = make([]byte, 32)
	} else {
		macKey = make([]byte, 32)
		if _, err := rand.Read(macKey); err != nil {
			return nil, err
		}
	}

	// Wrap the MAC key
	wrappedKey, err := aesKeyWrap(h.macKEK, macKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap MAC key: %w", err)
	}

	// Build the message (PdfMacIntegrityInfo)
	messageBytes, messageDigest, err := h.formatMessage(documentDigest, signatureDigest)
	if err != nil {
		return nil, err
	}

	// Build authenticated attributes
	authAttrs, err := h.formatAuthAttrs(messageDigest)
	if err != nil {
		return nil, err
	}

	// Compute MAC over auth attrs
	mac := h.ComputeMAC(macKey, authAttrs)

	// Build AuthenticatedData
	authData, err := h.formatAuthData(wrappedKey, messageBytes, authAttrs, mac)
	if err != nil {
		return nil, err
	}

	// Wrap in ContentInfo
	return h.wrapInContentInfo(authData)
}

// formatMessage creates the PdfMacIntegrityInfo and computes its digest.
func (h *PdfMacTokenHandler) formatMessage(documentDigest, signatureDigest []byte) ([]byte, []byte, error) {
	integrityInfo := PdfMacIntegrityInfo{
		Version:         0,
		DataDigest:      documentDigest,
		SignatureDigest: signatureDigest,
	}

	messageBytes, err := asn1.Marshal(integrityInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal integrity info: %w", err)
	}

	hashFunc, err := h.GetHashFunc()
	if err != nil {
		return nil, nil, err
	}

	hasher := hashFunc()
	hasher.Write(messageBytes)
	messageDigest := hasher.Sum(nil)

	return messageBytes, messageDigest, nil
}

// formatAuthAttrs creates the authenticated attributes.
func (h *PdfMacTokenHandler) formatAuthAttrs(messageDigest []byte) ([]byte, error) {
	// Content-Type attribute
	contentTypeAttr := CMSAttribute{
		Type:  OIDContentType,
		Value: asn1.RawValue{FullBytes: mustMarshal(OIDPdfMacIntegrityInfo)},
	}

	// Message-Digest attribute
	messageDigestAttr := CMSAttribute{
		Type:  OIDMessageDigest,
		Value: asn1.RawValue{FullBytes: mustMarshal(messageDigest)},
	}

	// CMS Algorithm Protection attribute
	algoProtection := CMSAlgorithmProtection{
		DigestAlgorithm: AlgorithmIdentifier{Algorithm: getDigestOID(h.mdAlgorithm)},
		MacAlgorithm:    &AlgorithmIdentifier{Algorithm: OIDHmacSHA256},
	}
	algoProtBytes, _ := asn1.Marshal(algoProtection)
	algoProtAttr := CMSAttribute{
		Type:  OIDCMSAlgorithmProtection,
		Value: asn1.RawValue{FullBytes: algoProtBytes},
	}

	attrs := []CMSAttribute{contentTypeAttr, messageDigestAttr, algoProtAttr}

	// Marshal as SET OF (for MAC computation)
	return asn1.Marshal(attrs)
}

// formatAuthData creates the AuthenticatedData structure.
func (h *PdfMacTokenHandler) formatAuthData(wrappedKey, messageBytes, authAttrs, mac []byte) ([]byte, error) {
	// Build PasswordRecipientInfo
	pwri := PasswordRecipientInfo{
		Version:      0,
		EncryptedKey: wrappedKey,
		KeyDerivationAlgorithm: AlgorithmIdentifier{
			Algorithm: OIDPdfMacWrapKDF,
		},
		KeyEncryptionAlgorithm: AlgorithmIdentifier{
			Algorithm: OIDAes256Wrap,
		},
	}

	pwriBytes, err := asn1.Marshal(pwri)
	if err != nil {
		return nil, err
	}

	// Build AuthenticatedData
	authData := AuthenticatedData{
		Version: 0,
		RecipientInfos: []asn1.RawValue{
			{Tag: 3, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: pwriBytes},
		},
		MacAlgorithm:    AlgorithmIdentifier{Algorithm: OIDHmacSHA256},
		DigestAlgorithm: AlgorithmIdentifier{Algorithm: getDigestOID(h.mdAlgorithm)},
		EncapContentInfo: EncapsulatedContentInfo{
			ContentType: OIDPdfMacIntegrityInfo,
			Content:     messageBytes,
		},
		AuthAttrs: asn1.RawValue{FullBytes: authAttrs},
		Mac:       mac,
	}

	return asn1.Marshal(authData)
}

// wrapInContentInfo wraps AuthenticatedData in a ContentInfo.
func (h *PdfMacTokenHandler) wrapInContentInfo(authData []byte) ([]byte, error) {
	ci := ContentInfo{
		ContentType: OIDAuthenticatedData,
		Content:     asn1.RawValue{FullBytes: authData},
	}
	return asn1.Marshal(ci)
}

// ValidatePdfMacToken validates a PDF MAC token.
func (h *PdfMacTokenHandler) ValidatePdfMacToken(tokenData, documentDigest, signatureDigest []byte) error {
	// Parse ContentInfo
	var ci ContentInfo
	if _, err := asn1.Unmarshal(tokenData, &ci); err != nil {
		return fmt.Errorf("failed to parse MAC token: %w", err)
	}

	if !ci.ContentType.Equal(OIDAuthenticatedData) {
		return fmt.Errorf("%w: expected AuthenticatedData content type", ErrPdfMacValidation)
	}

	// Parse AuthenticatedData
	var authData AuthenticatedData
	if _, err := asn1.Unmarshal(ci.Content.FullBytes, &authData); err != nil {
		return fmt.Errorf("failed to parse AuthenticatedData: %w", err)
	}

	// Retrieve MAC key
	macKey, err := h.retrieveMacKey(authData.RecipientInfos)
	if err != nil {
		return err
	}

	// Verify MAC
	computedMAC := h.ComputeMAC(macKey, authData.AuthAttrs.FullBytes)
	if !hmac.Equal(computedMAC, authData.Mac) {
		return ErrPdfMacInvalidMAC
	}

	// Validate authenticated attributes
	if err := h.validateAuthAttrs(authData); err != nil {
		return err
	}

	// Validate encapsulated content
	return h.validateEncapContent(authData.EncapContentInfo, documentDigest, signatureDigest)
}

// retrieveMacKey retrieves and unwraps the MAC key from recipient infos.
func (h *PdfMacTokenHandler) retrieveMacKey(recipientInfos []asn1.RawValue) ([]byte, error) {
	if len(recipientInfos) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one RecipientInfo", ErrPdfMacValidation)
	}

	// Parse PasswordRecipientInfo
	var pwri PasswordRecipientInfo
	if _, err := asn1.Unmarshal(recipientInfos[0].Bytes, &pwri); err != nil {
		return nil, fmt.Errorf("failed to parse PasswordRecipientInfo: %w", err)
	}

	// Verify KDF algorithm
	if !pwri.KeyDerivationAlgorithm.Algorithm.Equal(OIDPdfMacWrapKDF) {
		return nil, fmt.Errorf("%w: invalid KDF algorithm", ErrPdfMacValidation)
	}

	// Verify key encryption algorithm
	if !pwri.KeyEncryptionAlgorithm.Algorithm.Equal(OIDAes256Wrap) {
		return nil, fmt.Errorf("%w: invalid key encryption algorithm", ErrPdfMacValidation)
	}

	// Unwrap MAC key
	macKey, err := aesKeyUnwrap(h.macKEK, pwri.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap MAC key: %w", err)
	}

	return macKey, nil
}

// validateAuthAttrs validates the authenticated attributes.
func (h *PdfMacTokenHandler) validateAuthAttrs(authData AuthenticatedData) error {
	// Parse attributes
	var attrs []CMSAttribute
	if _, err := asn1.Unmarshal(authData.AuthAttrs.FullBytes, &attrs); err != nil {
		return fmt.Errorf("failed to parse auth attrs: %w", err)
	}

	// Find and validate content-type
	contentTypeFound := false
	messageDigestFound := false
	algoProtectionFound := false

	for _, attr := range attrs {
		if attr.Type.Equal(OIDContentType) {
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(attr.Value.FullBytes, &oid); err != nil {
				return fmt.Errorf("failed to parse content-type: %w", err)
			}
			if !oid.Equal(OIDPdfMacIntegrityInfo) {
				return fmt.Errorf("%w: invalid content-type", ErrPdfMacValidation)
			}
			contentTypeFound = true
		} else if attr.Type.Equal(OIDMessageDigest) {
			// Verify message digest
			var digest []byte
			if _, err := asn1.Unmarshal(attr.Value.FullBytes, &digest); err != nil {
				return fmt.Errorf("failed to parse message-digest: %w", err)
			}

			// Compute expected digest
			hashFunc, err := h.GetHashFunc()
			if err != nil {
				return err
			}
			hasher := hashFunc()
			hasher.Write(authData.EncapContentInfo.Content)
			expectedDigest := hasher.Sum(nil)

			if !bytes.Equal(digest, expectedDigest) {
				return fmt.Errorf("%w: message digest mismatch", ErrPdfMacValidation)
			}
			messageDigestFound = true
		} else if attr.Type.Equal(OIDCMSAlgorithmProtection) {
			algoProtectionFound = true
		}
	}

	if !contentTypeFound {
		return fmt.Errorf("%w: missing content-type attribute", ErrPdfMacValidation)
	}
	if !messageDigestFound {
		return fmt.Errorf("%w: missing message-digest attribute", ErrPdfMacValidation)
	}
	if !algoProtectionFound {
		return fmt.Errorf("%w: missing algorithm-protection attribute", ErrPdfMacValidation)
	}

	return nil
}

// validateEncapContent validates the encapsulated content.
func (h *PdfMacTokenHandler) validateEncapContent(eci EncapsulatedContentInfo, documentDigest, signatureDigest []byte) error {
	if !eci.ContentType.Equal(OIDPdfMacIntegrityInfo) {
		return fmt.Errorf("%w: invalid encapsulated content type", ErrPdfMacValidation)
	}

	var intInfo PdfMacIntegrityInfo
	if _, err := asn1.Unmarshal(eci.Content, &intInfo); err != nil {
		return fmt.Errorf("failed to parse PdfMacIntegrityInfo: %w", err)
	}

	// Verify data digest
	if !bytes.Equal(intInfo.DataDigest, documentDigest) {
		return ErrPdfMacInvalidDigest
	}

	// Verify signature digest if present
	if signatureDigest != nil {
		if intInfo.SignatureDigest == nil {
			return fmt.Errorf("%w: missing signature digest", ErrPdfMacValidation)
		}
		if !bytes.Equal(intInfo.SignatureDigest, signatureDigest) {
			return fmt.Errorf("%w: signature digest mismatch", ErrPdfMacValidation)
		}
	} else if intInfo.SignatureDigest != nil {
		return fmt.Errorf("%w: unexpected signature digest", ErrPdfMacValidation)
	}

	return nil
}

// ASN.1 helper structures

// ContentInfo represents CMS ContentInfo.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// AuthenticatedData represents CMS AuthenticatedData.
type AuthenticatedData struct {
	Version          int
	RecipientInfos   []asn1.RawValue `asn1:"set"`
	MacAlgorithm     AlgorithmIdentifier
	DigestAlgorithm  AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	EncapContentInfo EncapsulatedContentInfo
	AuthAttrs        asn1.RawValue `asn1:"optional,implicit,tag:2,set"`
	Mac              []byte
	UnauthAttrs      asn1.RawValue `asn1:"optional,implicit,tag:3,set"`
}

// EncapsulatedContentInfo represents encapsulated content.
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"optional,explicit,tag:0"`
}

// AlgorithmIdentifier represents an algorithm with optional parameters.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// PasswordRecipientInfo represents CMS PasswordRecipientInfo.
type PasswordRecipientInfo struct {
	Version                int
	KeyDerivationAlgorithm AlgorithmIdentifier `asn1:"optional,implicit,tag:0"`
	KeyEncryptionAlgorithm AlgorithmIdentifier
	EncryptedKey           []byte
}

// CMSAttribute represents a CMS attribute.
type CMSAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// CMSAlgorithmProtection represents CMS algorithm protection attribute.
type CMSAlgorithmProtection struct {
	DigestAlgorithm    AlgorithmIdentifier
	SignatureAlgorithm *AlgorithmIdentifier `asn1:"optional,implicit,tag:1"`
	MacAlgorithm       *AlgorithmIdentifier `asn1:"optional,implicit,tag:2"`
}

// Common CMS OIDs
var (
	OIDContentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDCMSAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
)

// Digest algorithm OIDs (SHA256, SHA384, SHA512 defined in pubkey.go)
var (
	OIDSHA3256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	OIDSHA3384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	OIDSHA3512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
)

// getDigestOID returns the OID for a digest algorithm name.
func getDigestOID(algorithm string) asn1.ObjectIdentifier {
	switch algorithm {
	case "sha256":
		return OIDSHA256
	case "sha384":
		return OIDSHA384
	case "sha512":
		return OIDSHA512
	case "sha3_256":
		return OIDSHA3256
	case "sha3_384":
		return OIDSHA3384
	case "sha3_512":
		return OIDSHA3512
	default:
		return OIDSHA256
	}
}

// mustMarshal marshals a value and panics on error.
func mustMarshal(v interface{}) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// StandalonePdfMac represents a standalone PDF MAC dictionary entry.
type StandalonePdfMac struct {
	ByteRange     []int
	MAC           []byte
	MACLocation   MACLocation
	BytesReserved int
}

// NewStandalonePdfMac creates a new standalone PDF MAC.
func NewStandalonePdfMac(bytesReserved int) *StandalonePdfMac {
	return &StandalonePdfMac{
		MACLocation:   MACLocationStandalone,
		BytesReserved: bytesReserved,
	}
}

// ValidatePdfMac validates a PDF MAC in a document.
// This is a high-level validation function.
func ValidatePdfMac(
	tokenData []byte,
	fileEncryptionKey []byte,
	kdfSalt []byte,
	documentDigest []byte,
	signatureDigest []byte,
	mdAlgorithm string,
) error {
	// Validate algorithm
	if !AllowedMDAlgorithms[mdAlgorithm] {
		return fmt.Errorf("%w: %s", ErrPdfMacUnsupportedAlg, mdAlgorithm)
	}

	// Create handler
	handler, err := NewPdfMacTokenHandlerFromKeyMaterial(fileEncryptionKey, kdfSalt, mdAlgorithm)
	if err != nil {
		return err
	}

	return handler.ValidatePdfMacToken(tokenData, documentDigest, signatureDigest)
}

// AddStandaloneMac creates a standalone MAC for a PDF.
// Returns the MAC token bytes.
func AddStandaloneMac(
	fileEncryptionKey []byte,
	kdfSalt []byte,
	documentDigest []byte,
	mdAlgorithm string,
) ([]byte, error) {
	handler, err := NewPdfMacTokenHandlerFromKeyMaterial(fileEncryptionKey, kdfSalt, mdAlgorithm)
	if err != nil {
		return nil, err
	}

	return handler.BuildPdfMacToken(documentDigest, nil, false)
}

// ComputeDocumentDigest computes the document digest for MAC validation.
// byteRanges is a list of [offset, length] pairs.
func ComputeDocumentDigest(reader io.ReaderAt, byteRanges [][2]int64, algorithm string) ([]byte, error) {
	hashFunc, err := GetHashFunc(algorithm)
	if err != nil {
		return nil, err
	}

	hasher := hashFunc()

	for _, br := range byteRanges {
		offset, length := br[0], br[1]
		buf := make([]byte, length)
		if _, err := reader.ReadAt(buf, offset); err != nil {
			return nil, fmt.Errorf("failed to read byte range: %w", err)
		}
		hasher.Write(buf)
	}

	return hasher.Sum(nil), nil
}
