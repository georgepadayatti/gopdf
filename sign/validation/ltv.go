// Package validation provides PDF signature validation.
// This file contains Long-Term Validation (LTV) functionality.
package validation

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/sign/cms"
)

// LTV validation errors.
var (
	ErrNoDSSFound              = errors.New("no DSS found in document")
	ErrNoTimestampChain        = errors.New("purported PAdES-LTA signature does not have a timestamp chain")
	ErrLTVRequiresTimestamp    = errors.New("LTV signatures require a trusted timestamp")
	ErrTimestampValidation     = errors.New("could not establish time of signing, timestamp token did not validate")
	ErrNoRevocationInfoArchive = errors.New("no revocation info archival attribute found")
	ErrPAdESLTARequiresTwoTS   = errors.New("PAdES-LTA signature requires separate timestamps protecting the signature and revocation info")
)

// RevocationInfoValidationType indicates a validation profile for revocation info.
type RevocationInfoValidationType int

const (
	// RevocationInfoAdobeStyle retrieves validation info from CMS object using Adobe's
	// revocation info archival attribute.
	RevocationInfoAdobeStyle RevocationInfoValidationType = iota

	// RevocationInfoPAdESLT retrieves validation info from DSS and requires
	// the signature's embedded timestamp to still be valid.
	RevocationInfoPAdESLT

	// RevocationInfoPAdESLTA retrieves validation info from DSS and validates
	// the chain of document timestamps to establish integrity of validation info.
	RevocationInfoPAdESLTA
)

// String returns the string representation of the validation type.
func (t RevocationInfoValidationType) String() string {
	switch t {
	case RevocationInfoAdobeStyle:
		return "adobe"
	case RevocationInfoPAdESLT:
		return "pades"
	case RevocationInfoPAdESLTA:
		return "pades-lta"
	default:
		return "unknown"
	}
}

// ParseRevocationInfoValidationType parses a string to RevocationInfoValidationType.
func ParseRevocationInfoValidationType(s string) (RevocationInfoValidationType, error) {
	switch s {
	case "adobe":
		return RevocationInfoAdobeStyle, nil
	case "pades":
		return RevocationInfoPAdESLT, nil
	case "pades-lta":
		return RevocationInfoPAdESLTA, nil
	default:
		return 0, fmt.Errorf("unknown validation type: %s", s)
	}
}

// DefaultLTVRevocationCheckingPolicy is the default revocation policy for LTV.
var DefaultLTVRevocationCheckingPolicy = certvalidator.NewRevocationCheckingPolicy(
	certvalidator.RevocationRuleCheckIfDeclared,
	certvalidator.RevocationRuleCheckIfDeclared,
)

// StrictLTVRevocationCheckingPolicy is a stricter revocation policy for LTV.
var StrictLTVRevocationCheckingPolicy = certvalidator.NewRevocationCheckingPolicy(
	certvalidator.RevocationRuleCRLOrOCSPRequired,
	certvalidator.RevocationRuleCRLOrOCSPRequired,
)

// NewDefaultLTVRevocationPolicy creates a default LTV revocation trust policy.
func NewDefaultLTVRevocationPolicy(retroactive bool) *certvalidator.CertRevTrustPolicy {
	policy := certvalidator.NewCertRevTrustPolicy(DefaultLTVRevocationCheckingPolicy)
	policy.RetroactiveRevInfo = retroactive
	return policy
}

// NewStrictLTVRevocationPolicy creates a strict LTV revocation trust policy.
func NewStrictLTVRevocationPolicy(retroactive bool) *certvalidator.CertRevTrustPolicy {
	policy := certvalidator.NewCertRevTrustPolicy(StrictLTVRevocationCheckingPolicy)
	policy.RetroactiveRevInfo = retroactive
	return policy
}

// LTVValidationContext holds context for LTV validation.
type LTVValidationContext struct {
	// TrustManager provides trust anchors.
	TrustManager certvalidator.TrustManager

	// CertRegistry for certificate storage.
	CertRegistry *certvalidator.CertificateRegistry

	// RevocationPolicy controls revocation checking.
	RevocationPolicy *certvalidator.CertRevTrustPolicy

	// ValidationTime for certificate validation.
	ValidationTime time.Time

	// AllowFetching controls whether online fetching is allowed.
	AllowFetching bool

	// RetroactiveRevInfo treats revocation info as retroactively valid.
	RetroactiveRevInfo bool

	// Certificates from DSS or embedded sources.
	Certificates []*x509.Certificate

	// CRLs from DSS or embedded sources.
	CRLs [][]byte

	// OCSPs from DSS or embedded sources.
	OCSPs [][]byte
}

// NewLTVValidationContext creates a new LTV validation context with defaults.
func NewLTVValidationContext(trustManager certvalidator.TrustManager) *LTVValidationContext {
	return &LTVValidationContext{
		TrustManager:       trustManager,
		RevocationPolicy:   NewDefaultLTVRevocationPolicy(false),
		ValidationTime:     time.Now(),
		AllowFetching:      true,
		RetroactiveRevInfo: false,
	}
}

// WithValidationTime sets the validation time.
func (ctx *LTVValidationContext) WithValidationTime(t time.Time) *LTVValidationContext {
	ctx.ValidationTime = t
	return ctx
}

// WithRevocationPolicy sets the revocation policy.
func (ctx *LTVValidationContext) WithRevocationPolicy(policy *certvalidator.CertRevTrustPolicy) *LTVValidationContext {
	ctx.RevocationPolicy = policy
	return ctx
}

// WithDSSData loads data from a DSS.
func (ctx *LTVValidationContext) WithDSSData(dss *DocumentSecurityStore) *LTVValidationContext {
	if dss != nil {
		ctx.Certificates = append(ctx.Certificates, dss.Certs...)
		ctx.CRLs = append(ctx.CRLs, dss.CRLs...)
		ctx.OCSPs = append(ctx.OCSPs, dss.OCSPs...)
	}
	return ctx
}

// TimestampTrustData holds data about timestamp trust establishment.
type TimestampTrustData struct {
	// LatestDocTimestamp is the most recent document timestamp.
	LatestDocTimestamp *reader.EmbeddedSignature

	// EarliestTimestampStatus is the status of the earliest valid timestamp.
	EarliestTimestampStatus *TimestampSignatureStatus

	// ChainLength is the number of timestamps in the chain.
	ChainLength int

	// ValidationTime is the established validation time from timestamps.
	ValidationTime time.Time
}

// TimestampSignatureStatus holds the validation status of a timestamp.
type TimestampSignatureStatus struct {
	// Valid indicates the timestamp signature is cryptographically valid.
	Valid bool

	// Trusted indicates the timestamp signer is trusted.
	Trusted bool

	// Timestamp is the time claimed by the timestamp.
	Timestamp time.Time

	// SignerCertificate is the timestamp authority certificate.
	SignerCertificate *x509.Certificate

	// CertificatePath is the validated certificate path.
	CertificatePath []*x509.Certificate

	// Errors encountered during validation.
	Errors []error

	// Warnings during validation.
	Warnings []string
}

// Summary returns a summary of the timestamp status.
func (s *TimestampSignatureStatus) Summary() string {
	if s.Valid && s.Trusted {
		return fmt.Sprintf("valid trusted timestamp at %s", s.Timestamp)
	}
	if s.Valid {
		return fmt.Sprintf("valid but untrusted timestamp at %s", s.Timestamp)
	}
	return "invalid timestamp"
}

// LTVSignatureStatus extends signature status with LTV information.
type LTVSignatureStatus struct {
	*SignatureValidationResult

	// ValidationType is the LTV validation profile used.
	ValidationType RevocationInfoValidationType

	// TimestampValidity is the status of the protecting timestamp.
	TimestampValidity *TimestampSignatureStatus

	// SignerReportedTime is the time from the timestamp.
	SignerReportedTime time.Time

	// TimestampChainLength is the number of timestamps in the chain.
	TimestampChainLength int

	// DSSPresent indicates a DSS was found.
	DSSPresent bool

	// ValidationMaterialComplete indicates all validation material is present.
	ValidationMaterialComplete bool
}

// GetTimestampChain returns document timestamps from the reader, newest to oldest.
func GetTimestampChain(pdfReader *reader.PdfFileReader) ([]*reader.EmbeddedSignature, error) {
	sigs, err := pdfReader.GetEmbeddedSignatures()
	if err != nil {
		return nil, err
	}

	var timestamps []*reader.EmbeddedSignature
	for i := len(sigs) - 1; i >= 0; i-- {
		sig := sigs[i]
		// Check if this is a document timestamp
		if isDocumentTimestamp(sig) {
			timestamps = append(timestamps, sig)
		}
	}

	return timestamps, nil
}

// isDocumentTimestamp checks if a signature is a document timestamp.
func isDocumentTimestamp(sig *reader.EmbeddedSignature) bool {
	if sig.Dictionary == nil {
		return false
	}

	// Check for /Type /DocTimeStamp in the signature dictionary
	typeObj := sig.Dictionary.Get("Type")
	if typeObj != nil {
		// Get string representation
		if typeStr := getNameValue(typeObj); typeStr == "/DocTimeStamp" || typeStr == "DocTimeStamp" {
			return true
		}
	}

	// Also check Field if available
	if sig.Field != nil {
		typeObj = sig.Field.Get("Type")
		if typeObj != nil {
			if typeStr := getNameValue(typeObj); typeStr == "/DocTimeStamp" || typeStr == "DocTimeStamp" {
				return true
			}
		}
	}

	return false
}

// getNameValue extracts a name value from a PDF object.
func getNameValue(obj interface{}) string {
	if obj == nil {
		return ""
	}
	// Use fmt.Sprintf to get string representation
	return fmt.Sprintf("%v", obj)
}

// EstablishTimestampTrust validates a timestamp for trust establishment.
func EstablishTimestampTrust(
	timestampData []byte,
	validationCtx *LTVValidationContext,
	expectedImprint []byte,
) (*TimestampSignatureStatus, error) {
	status := &TimestampSignatureStatus{}

	// Parse and validate the timestamp token
	tstInfo, err := parseTimestampToken(timestampData)
	if err != nil {
		status.Errors = append(status.Errors, fmt.Errorf("failed to parse timestamp: %w", err))
		return status, err
	}

	// Verify the message imprint matches
	if expectedImprint != nil {
		if err := verifyTimestampImprint(tstInfo, expectedImprint); err != nil {
			status.Errors = append(status.Errors, err)
			return status, fmt.Errorf("timestamp imprint mismatch: %w", err)
		}
	}

	// Get the timestamp time
	status.Timestamp = tstInfo.GenTime

	// Verify the CMS signature
	if err := cms.VerifyCMSSignature(timestampData, nil); err != nil {
		status.Errors = append(status.Errors, err)
		return status, fmt.Errorf("timestamp signature verification failed: %w", err)
	}

	status.Valid = true

	// Validate the signer certificate chain
	signerCerts, err := cms.GetSignerCertificates(timestampData)
	if err != nil {
		status.Warnings = append(status.Warnings, fmt.Sprintf("failed to get signer certs: %v", err))
	} else if len(signerCerts) > 0 {
		status.SignerCertificate = signerCerts[0]
		status.CertificatePath = signerCerts

		// Verify trust using IsRoot
		if validationCtx.TrustManager != nil {
			// Check if any cert in chain is a trusted root
			for _, cert := range signerCerts {
				if validationCtx.TrustManager.IsRoot(cert) {
					status.Trusted = true
					break
				}
			}
		}
	}

	if !status.Valid || !status.Trusted {
		return status, ErrTimestampValidation
	}

	return status, nil
}

// TSTInfo represents a timestamp token info structure.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       *Accuracy       `asn1:"optional"`
	Ordering       bool            `asn1:"optional,default:false"`
	Nonce          *big.Int        `asn1:"optional"`
	TSA            asn1.RawValue   `asn1:"optional,tag:0"`
	Extensions     []asn1.RawValue `asn1:"optional,tag:1"`
}

// MessageImprint represents the hash of the timestamped data.
type MessageImprint struct {
	HashAlgorithm cms.AlgorithmIdentifier
	HashedMessage []byte
}

// Accuracy represents the accuracy of a timestamp.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// parseTimestampToken parses a timestamp token from CMS data.
func parseTimestampToken(data []byte) (*TSTInfo, error) {
	signedData, err := cms.ParseCMSSignature(data)
	if err != nil {
		return nil, err
	}

	// Extract TSTInfo from encapsulated content
	var tstInfo TSTInfo
	if len(signedData.EncapContentInfo.EContent.Bytes) > 0 {
		if _, err := asn1.Unmarshal(signedData.EncapContentInfo.EContent.Bytes, &tstInfo); err != nil {
			return nil, fmt.Errorf("failed to parse TSTInfo: %w", err)
		}
	} else {
		return nil, errors.New("no encapsulated content in timestamp")
	}

	return &tstInfo, nil
}

// verifyTimestampImprint verifies the message imprint in a timestamp.
func verifyTimestampImprint(tstInfo *TSTInfo, expectedDigest []byte) error {
	if len(tstInfo.MessageImprint.HashedMessage) != len(expectedDigest) {
		return errors.New("message imprint length mismatch")
	}

	for i, b := range tstInfo.MessageImprint.HashedMessage {
		if b != expectedDigest[i] {
			return errors.New("message imprint mismatch")
		}
	}

	return nil
}

// ValidateLTVSignature validates a PDF signature using LTV validation.
func ValidateLTVSignature(
	embeddedSig *reader.EmbeddedSignature,
	validationType RevocationInfoValidationType,
	validationCtx *LTVValidationContext,
	diffPolicy *DiffPolicy,
) (*LTVSignatureStatus, error) {
	pdfReader := embeddedSig.Reader

	result := &LTVSignatureStatus{
		SignatureValidationResult: &SignatureValidationResult{
			Status: StatusUnknown,
		},
		ValidationType: validationType,
	}

	var dss *DocumentSecurityStore
	var err error

	// For non-Adobe profiles, read the DSS
	if validationType != RevocationInfoAdobeStyle {
		dss, err = ExtractDSS(pdfReader)
		if err != nil && !errors.Is(err, ErrNoDSSFound) {
			return result, err
		}
		if dss != nil {
			result.DSSPresent = true
			validationCtx.WithDSSData(dss)
		}
	}

	// Process timestamp chain for PAdES profiles
	var timestampTrust *TimestampTrustData
	if validationType != RevocationInfoAdobeStyle {
		timestampTrust, err = establishTimestampTrustLTA(pdfReader, validationCtx, embeddedSig)
		if err != nil {
			if validationType == RevocationInfoPAdESLTA {
				return result, err
			}
			// For PAdES-LT, we continue if no timestamp chain
		}

		if timestampTrust != nil {
			result.TimestampChainLength = timestampTrust.ChainLength
			result.TimestampValidity = timestampTrust.EarliestTimestampStatus

			if timestampTrust.EarliestTimestampStatus == nil && validationType == RevocationInfoPAdESLTA {
				return result, ErrNoTimestampChain
			}
		}
	}

	// Check for embedded timestamp token in signature
	embeddedTST := getEmbeddedTimestamp(embeddedSig)
	if embeddedTST != nil {
		tstStatus, err := EstablishTimestampTrust(embeddedTST, validationCtx, nil)
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else {
			result.TimestampValidity = tstStatus
			result.SignerReportedTime = tstStatus.Timestamp
			validationCtx.ValidationTime = tstStatus.Timestamp
		}
	} else if validationType == RevocationInfoPAdESLTA && result.TimestampChainLength == 1 {
		return result, ErrPAdESLTARequiresTwoTS
	}

	// Must have a trusted timestamp for LTV
	if result.TimestampValidity == nil {
		return result, ErrLTVRequiresTimestamp
	}

	// For Adobe style, retrieve revocation info from CMS
	if validationType == RevocationInfoAdobeStyle {
		ocsps, crls, err := RetrieveAdobeRevocationInfo(embeddedSig.Contents)
		if err != nil {
			return result, err
		}
		validationCtx.OCSPs = ocsps
		validationCtx.CRLs = crls
	}

	// Now validate the signature with the established context
	validationCtx.AllowFetching = false
	result.SignatureValidationResult = validateSignatureWithContext(embeddedSig, validationCtx)

	// Check coverage and modifications
	if diffPolicy != nil {
		result.CoverageStatus = checkCoverageWithPolicy(embeddedSig, diffPolicy)
	}

	// Determine overall status
	if result.IntegrityStatus == StatusValid && result.TrustStatus == StatusValid {
		result.Status = StatusValid
		result.ValidationMaterialComplete = true
	} else if result.IntegrityStatus == StatusInvalid {
		result.Status = StatusInvalid
	} else {
		result.Status = StatusWarning
	}

	return result, nil
}

// establishTimestampTrustLTA establishes trust through the timestamp chain.
func establishTimestampTrustLTA(
	pdfReader *reader.PdfFileReader,
	validationCtx *LTVValidationContext,
	untilSignature *reader.EmbeddedSignature,
) (*TimestampTrustData, error) {
	timestamps, err := GetTimestampChain(pdfReader)
	if err != nil {
		return nil, err
	}

	if len(timestamps) == 0 {
		return nil, nil
	}

	result := &TimestampTrustData{}
	var currentCtx = validationCtx

	for i, ts := range timestamps {
		// Check if we've reached the signature's revision
		if untilSignature != nil && ts.ByteRange[0] < untilSignature.ByteRange[0] {
			break
		}

		// Compute the digest for this timestamp
		digest := ts.GetSignedData()

		// Validate the timestamp
		tstStatus, err := EstablishTimestampTrust(ts.Contents, currentCtx, digest)
		if err != nil {
			return result, err
		}

		result.ChainLength = i + 1
		result.EarliestTimestampStatus = tstStatus
		result.ValidationTime = tstStatus.Timestamp

		if i == 0 {
			result.LatestDocTimestamp = ts
		}

		// Update context for next iteration
		currentCtx = &LTVValidationContext{
			TrustManager:       validationCtx.TrustManager,
			RevocationPolicy:   NewStrictLTVRevocationPolicy(validationCtx.RetroactiveRevInfo),
			ValidationTime:     tstStatus.Timestamp,
			AllowFetching:      false,
			RetroactiveRevInfo: validationCtx.RetroactiveRevInfo,
		}

		// Try to read DSS at this revision
		// Note: This is a simplified version; full implementation would use historical resolver
	}

	return result, nil
}

// getEmbeddedTimestamp extracts embedded timestamp from signature.
func getEmbeddedTimestamp(sig *reader.EmbeddedSignature) []byte {
	// Look for timestamp token attribute in the CMS signed data
	return getTimestampTokenFromCMS(sig.Contents)
}

// OID for timestamp token attribute
var OIDTimestampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// getTimestampTokenFromCMS extracts a timestamp token from CMS unsigned attributes.
func getTimestampTokenFromCMS(cmsData []byte) []byte {
	signedData, err := cms.ParseCMSSignature(cmsData)
	if err != nil {
		return nil
	}

	if len(signedData.SignerInfos) == 0 {
		return nil
	}

	// Look in unsigned attributes for timestamp token
	for _, attr := range signedData.SignerInfos[0].UnsignedAttrs {
		if attr.Type.Equal(OIDTimestampToken) && len(attr.Values) > 0 {
			return attr.Values[0].FullBytes
		}
	}

	return nil
}

// validateSignatureWithContext validates signature with given context.
func validateSignatureWithContext(sig *reader.EmbeddedSignature, ctx *LTVValidationContext) *SignatureValidationResult {
	result := &SignatureValidationResult{
		Status:          StatusUnknown,
		IntegrityStatus: StatusUnknown,
		TrustStatus:     StatusUnknown,
	}

	// Verify the CMS signature
	signedData := sig.GetSignedData()
	if err := cms.VerifyCMSSignature(sig.Contents, signedData); err != nil {
		result.Status = StatusInvalid
		result.IntegrityStatus = StatusInvalid
		result.Errors = append(result.Errors, err)
		return result
	}

	result.IntegrityStatus = StatusValid

	// Get signer certificate
	certs, err := cms.GetSignerCertificates(sig.Contents)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("failed to get certificates: %v", err))
	} else if len(certs) > 0 {
		result.SignerCertificate = certs[0]
		result.CertificateChain = certs[1:]
		result.Name = certs[0].Subject.CommonName

		// Verify trust using the validation context
		if ctx.TrustManager != nil {
			for _, cert := range certs {
				if ctx.TrustManager.IsRoot(cert) {
					result.TrustStatus = StatusValid
					break
				}
			}
		}

		if result.TrustStatus != StatusValid {
			result.TrustStatus = StatusWarning
		}
	}

	// Determine overall status
	if result.IntegrityStatus == StatusValid && result.TrustStatus == StatusValid {
		result.Status = StatusValid
	} else if result.IntegrityStatus == StatusInvalid {
		result.Status = StatusInvalid
	} else {
		result.Status = StatusWarning
	}

	return result
}

// checkCoverageWithPolicy checks signature coverage with a diff policy.
func checkCoverageWithPolicy(sig *reader.EmbeddedSignature, policy *DiffPolicy) CoverageStatus {
	byteRange := sig.ByteRange
	fileSize := int64(len(sig.Reader.Data()))

	rangeEnd := byteRange[2] + byteRange[3]
	if rangeEnd == fileSize {
		return CoverageEntireFile
	}

	if byteRange[0] == 0 {
		return CoverageContiguous
	}

	return CoveragePartial
}

// OID for Adobe revocation info archival attribute
var OIDAdobeRevocationInfoArchival = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}

// AdobeRevocationInfoArchival represents Adobe's revocation info archival structure.
type AdobeRevocationInfoArchival struct {
	CRLs         []asn1.RawValue `asn1:"optional,explicit,tag:0"`
	OCSPs        []asn1.RawValue `asn1:"optional,explicit,tag:1"`
	OtherRevInfo []asn1.RawValue `asn1:"optional,explicit,tag:2"`
}

// RetrieveAdobeRevocationInfo extracts Adobe-style revocation info from CMS.
func RetrieveAdobeRevocationInfo(cmsData []byte) (ocsps [][]byte, crls [][]byte, err error) {
	signedData, err := cms.ParseCMSSignature(cmsData)
	if err != nil {
		return nil, nil, err
	}

	if len(signedData.SignerInfos) == 0 {
		return nil, nil, ErrNoRevocationInfoArchive
	}

	// Look for Adobe revocation info in signed attributes
	var revInfoRaw []byte
	for _, attr := range signedData.SignerInfos[0].SignedAttrs {
		if attr.Type.Equal(OIDAdobeRevocationInfoArchival) && len(attr.Values) > 0 {
			revInfoRaw = attr.Values[0].FullBytes
			break
		}
	}

	if revInfoRaw == nil {
		return nil, nil, ErrNoRevocationInfoArchive
	}

	// Parse the revocation info archival structure
	var revInfo AdobeRevocationInfoArchival
	if _, err := asn1.Unmarshal(revInfoRaw, &revInfo); err != nil {
		return nil, nil, fmt.Errorf("failed to parse revocation info: %w", err)
	}

	// Extract OCSPs
	for _, ocsp := range revInfo.OCSPs {
		ocsps = append(ocsps, ocsp.FullBytes)
	}

	// Extract CRLs
	for _, crl := range revInfo.CRLs {
		crls = append(crls, crl.FullBytes)
	}

	return ocsps, crls, nil
}

// ApplyAdobeRevocationInfo creates a validation context with Adobe revocation info.
func ApplyAdobeRevocationInfo(
	cmsData []byte,
	trustManager certvalidator.TrustManager,
) (*LTVValidationContext, error) {
	ocsps, crls, err := RetrieveAdobeRevocationInfo(cmsData)
	if err != nil {
		return nil, err
	}

	ctx := NewLTVValidationContext(trustManager)
	ctx.OCSPs = ocsps
	ctx.CRLs = crls
	ctx.AllowFetching = false

	return ctx, nil
}

// LTVValidator provides LTV validation functionality.
type LTVValidator struct {
	TrustManager certvalidator.TrustManager
	DiffPolicy   *DiffPolicy
}

// NewLTVValidator creates a new LTV validator.
func NewLTVValidator(trustManager certvalidator.TrustManager) *LTVValidator {
	return &LTVValidator{
		TrustManager: trustManager,
		DiffPolicy:   NewDiffPolicy(),
	}
}

// ValidateSignature validates a signature using LTV validation.
func (v *LTVValidator) ValidateSignature(
	embeddedSig *reader.EmbeddedSignature,
	validationType RevocationInfoValidationType,
) (*LTVSignatureStatus, error) {
	ctx := NewLTVValidationContext(v.TrustManager)
	return ValidateLTVSignature(embeddedSig, validationType, ctx, v.DiffPolicy)
}

// ValidateAllSignatures validates all signatures in a PDF using LTV.
func (v *LTVValidator) ValidateAllSignatures(
	pdfReader *reader.PdfFileReader,
	validationType RevocationInfoValidationType,
) ([]*LTVSignatureStatus, error) {
	sigs, err := pdfReader.GetEmbeddedSignatures()
	if err != nil {
		return nil, err
	}

	var results []*LTVSignatureStatus
	for _, sig := range sigs {
		if isDocumentTimestamp(sig) {
			continue // Skip document timestamps in signature validation
		}

		status, err := v.ValidateSignature(sig, validationType)
		if err != nil {
			// Add error but continue with other signatures
			if status == nil {
				status = &LTVSignatureStatus{
					SignatureValidationResult: &SignatureValidationResult{
						Status: StatusInvalid,
					},
				}
			}
			status.Errors = append(status.Errors, err)
		}
		results = append(results, status)
	}

	return results, nil
}

// LTVProfile represents a predefined LTV validation profile.
type LTVProfile struct {
	Name           string
	ValidationType RevocationInfoValidationType
	RequireDSS     bool
	RequireChain   bool
	MinChainLength int
}

// Predefined LTV profiles.
var (
	LTVProfileAdobe = &LTVProfile{
		Name:           "adobe",
		ValidationType: RevocationInfoAdobeStyle,
		RequireDSS:     false,
		RequireChain:   false,
	}

	LTVProfilePAdESLT = &LTVProfile{
		Name:           "pades-lt",
		ValidationType: RevocationInfoPAdESLT,
		RequireDSS:     true,
		RequireChain:   false,
	}

	LTVProfilePAdESLTA = &LTVProfile{
		Name:           "pades-lta",
		ValidationType: RevocationInfoPAdESLTA,
		RequireDSS:     true,
		RequireChain:   true,
		MinChainLength: 2,
	}
)

// GetLTVProfile returns a profile by name.
func GetLTVProfile(name string) *LTVProfile {
	switch name {
	case "adobe":
		return LTVProfileAdobe
	case "pades-lt", "pades":
		return LTVProfilePAdESLT
	case "pades-lta":
		return LTVProfilePAdESLTA
	default:
		return nil
	}
}
