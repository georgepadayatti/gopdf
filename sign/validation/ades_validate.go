// Package validation provides PDF signature validation.
// This file contains AdES (Advanced Electronic Signatures) validation.
package validation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/sign/ades"
	"github.com/georgepadayatti/gopdf/sign/cms"
)

// AdES validation errors.
var (
	ErrFormatFailure              = errors.New("format failure")
	ErrHashFailure                = errors.New("hash failure")
	ErrSignatureConstraintFailure = errors.New("signature constraint failure")
	ErrCryptoConstraintsFailure   = errors.New("crypto constraints failure")
	ErrCertificateChainFailure    = errors.New("certificate chain failure")
	ErrNoValidTimestamp           = errors.New("no valid timestamp")
	ErrNoSignerCertFound          = errors.New("no signer certificate found")
	ErrPolicyProcessingError      = errors.New("policy processing error")
)

// ValidationObjectType represents the type of a validation object.
type ValidationObjectType int

const (
	ValidationObjectCertificate ValidationObjectType = iota
	ValidationObjectCRL
	ValidationObjectOCSP
	ValidationObjectTimestamp
	ValidationObjectSignedData
)

// String returns the string representation.
func (t ValidationObjectType) String() string {
	switch t {
	case ValidationObjectCertificate:
		return "certificate"
	case ValidationObjectCRL:
		return "crl"
	case ValidationObjectOCSP:
		return "ocsp"
	case ValidationObjectTimestamp:
		return "timestamp"
	case ValidationObjectSignedData:
		return "signed_data"
	default:
		return "unknown"
	}
}

// ValidationObject represents an object used in validation.
type ValidationObject struct {
	ObjectType ValidationObjectType
	Value      interface{}
	Identifier string
}

// ValidationObjectSet is a collection of validation objects.
type ValidationObjectSet struct {
	objects map[string]*ValidationObject
}

// NewValidationObjectSet creates a new validation object set.
func NewValidationObjectSet() *ValidationObjectSet {
	return &ValidationObjectSet{
		objects: make(map[string]*ValidationObject),
	}
}

// Add adds a validation object to the set.
func (s *ValidationObjectSet) Add(obj *ValidationObject) {
	if obj.Identifier != "" {
		s.objects[obj.Identifier] = obj
	}
}

// Get returns a validation object by identifier.
func (s *ValidationObjectSet) Get(identifier string) (*ValidationObject, bool) {
	obj, ok := s.objects[identifier]
	return obj, ok
}

// All returns all validation objects.
func (s *ValidationObjectSet) All() []*ValidationObject {
	result := make([]*ValidationObject, 0, len(s.objects))
	for _, obj := range s.objects {
		result = append(result, obj)
	}
	return result
}

// Count returns the number of objects.
func (s *ValidationObjectSet) Count() int {
	return len(s.objects)
}

// DeriveValidationObjectIdentifier creates an identifier for a validation object.
func DeriveValidationObjectIdentifier(obj *ValidationObject) string {
	var data []byte

	switch v := obj.Value.(type) {
	case *x509.Certificate:
		data = v.Raw
	case []byte:
		data = v
	default:
		return ""
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("vo-%s-%s", obj.ObjectType.String(), hex.EncodeToString(hash[:8]))
}

// AdESBasicValidationResult is the result of AdES basic validation.
type AdESBasicValidationResult struct {
	// Indication is the main validation indication (PASSED, FAILED, INDETERMINATE).
	Indication string

	// SubIndication provides more detail about the result.
	SubIndication string

	// APIStatus is the internal signature status.
	APIStatus *SignatureValidationResult

	// FailureMessage describes the failure reason.
	FailureMessage string

	// ValidationObjects are objects used during validation.
	ValidationObjects *ValidationObjectSet

	// SignaturePOETime is the proof-of-existence time for the signature.
	SignaturePOETime time.Time

	// ValidationPath is the certificate validation path.
	ValidationPath []*x509.Certificate

	// TimestampValidity is the status of embedded timestamps.
	TimestampValidity *TimestampSignatureStatus
}

// NewAdESBasicValidationResult creates a new basic validation result.
func NewAdESBasicValidationResult() *AdESBasicValidationResult {
	return &AdESBasicValidationResult{
		Indication:        ades.IndicationIndeterminate,
		ValidationObjects: NewValidationObjectSet(),
	}
}

// IsPassed returns true if validation passed.
func (r *AdESBasicValidationResult) IsPassed() bool {
	return r.Indication == ades.IndicationPassed
}

// IsFailed returns true if validation failed.
func (r *AdESBasicValidationResult) IsFailed() bool {
	return r.Indication == ades.IndicationFailed
}

// AdESWithTimeValidationResult extends basic validation with time info.
type AdESWithTimeValidationResult struct {
	*AdESBasicValidationResult

	// BestSignatureTime is the best available time for the signature.
	BestSignatureTime time.Time

	// ContentTimestampValidity is the status of content timestamps.
	ContentTimestampValidity *TimestampSignatureStatus
}

// NewAdESWithTimeValidationResult creates a new with-time validation result.
func NewAdESWithTimeValidationResult() *AdESWithTimeValidationResult {
	return &AdESWithTimeValidationResult{
		AdESBasicValidationResult: NewAdESBasicValidationResult(),
	}
}

// AdESLTAValidationResult is the result of LTA (Long-Term Archival) validation.
type AdESLTAValidationResult struct {
	*AdESWithTimeValidationResult

	// DocumentTimestamps are validated document timestamps.
	DocumentTimestamps []*TimestampSignatureStatus

	// DSSPresent indicates if a DSS was found.
	DSSPresent bool

	// RevocationDataComplete indicates if revocation data is complete.
	RevocationDataComplete bool

	// CertificateDataComplete indicates if certificate data is complete.
	CertificateDataComplete bool
}

// NewAdESLTAValidationResult creates a new LTA validation result.
func NewAdESLTAValidationResult() *AdESLTAValidationResult {
	return &AdESLTAValidationResult{
		AdESWithTimeValidationResult: NewAdESWithTimeValidationResult(),
	}
}

// AdESValidationSpec specifies parameters for AdES validation.
type AdESValidationSpec struct {
	// TrustManager provides trust anchors.
	TrustManager certvalidator.TrustManager

	// ValidationTime is the time to use for validation.
	ValidationTime time.Time

	// AlgorithmPolicy controls algorithm acceptance.
	AlgorithmPolicy certvalidator.AlgorithmUsagePolicy

	// RevocationPolicy controls revocation checking.
	RevocationPolicy *certvalidator.CertRevTrustPolicy

	// LocalKnowledge provides additional validation material.
	LocalKnowledge *LocalKnowledge

	// RequireTimestamp requires a valid timestamp.
	RequireTimestamp bool

	// TimestampSpec specifies timestamp validation settings.
	TimestampSpec *SignatureValidationSpec
}

// NewAdESValidationSpec creates a new AdES validation spec with defaults.
func NewAdESValidationSpec(trustManager certvalidator.TrustManager) *AdESValidationSpec {
	return &AdESValidationSpec{
		TrustManager:     trustManager,
		ValidationTime:   time.Now(),
		AlgorithmPolicy:  certvalidator.NewDisallowWeakAlgorithmsPolicy(),
		RevocationPolicy: certvalidator.NewCertRevTrustPolicy(certvalidator.RequireRevInfo),
		LocalKnowledge:   NewLocalKnowledge(),
	}
}

// AdESBasicValidation performs AdES basic validation per ETSI EN 319 102-1 § 5.3.
func AdESBasicValidation(
	embeddedSig *reader.EmbeddedSignature,
	spec *AdESValidationSpec,
) (*AdESBasicValidationResult, error) {
	result := NewAdESBasicValidationResult()

	// Step 1: Verify the signature cryptographically
	signedData := embeddedSig.GetSignedData()
	if err := cms.VerifyCMSSignature(embeddedSig.Contents, signedData); err != nil {
		result.Indication = ades.IndicationFailed
		result.SubIndication = ades.SubIndicationHashFailure
		result.FailureMessage = fmt.Sprintf("signature verification failed: %v", err)
		return result, nil
	}

	// Step 2: Get signer certificate
	certs, err := cms.GetSignerCertificates(embeddedSig.Contents)
	if err != nil || len(certs) == 0 {
		result.Indication = ades.IndicationIndeterminate
		result.SubIndication = ades.SubIndicationNoSignerCertFound
		result.FailureMessage = "signer certificate not found"
		return result, nil
	}

	signerCert := certs[0]
	result.ValidationPath = certs

	// Add certificates to validation objects
	for _, cert := range certs {
		vo := &ValidationObject{
			ObjectType: ValidationObjectCertificate,
			Value:      cert,
		}
		vo.Identifier = DeriveValidationObjectIdentifier(vo)
		result.ValidationObjects.Add(vo)
	}

	// Step 3: Validate certificate chain
	if spec.TrustManager != nil {
		trusted := false
		for _, cert := range certs {
			if spec.TrustManager.IsRoot(cert) {
				trusted = true
				break
			}
		}
		if !trusted {
			result.Indication = ades.IndicationIndeterminate
			result.SubIndication = ades.SubIndicationNoCertificateChainFound
			result.FailureMessage = "certificate chain not trusted"
		}
	}

	// Step 4: Check certificate validity at validation time
	validationTime := spec.ValidationTime
	if validationTime.Before(signerCert.NotBefore) || validationTime.After(signerCert.NotAfter) {
		result.Indication = ades.IndicationIndeterminate
		result.SubIndication = ades.SubIndicationOutOfBoundsNoPoE
		result.FailureMessage = fmt.Sprintf("certificate not valid at %s", validationTime)
		return result, nil
	}

	// Step 5: Check crypto constraints
	if spec.AlgorithmPolicy != nil {
		// Check signature algorithm
		constraint := spec.AlgorithmPolicy.SignatureAlgorithmAllowed(
			signerCert.SignatureAlgorithm,
			&validationTime,
			signerCert.PublicKey,
		)
		if !constraint.Allowed {
			result.Indication = ades.IndicationIndeterminate
			result.SubIndication = ades.SubIndicationCryptoConstraintsFailureNoPoE
			result.FailureMessage = constraint.FailureReason
			return result, nil
		}
	}

	// Build API status
	result.APIStatus = &SignatureValidationResult{
		Status:            StatusValid,
		IntegrityStatus:   StatusValid,
		TrustStatus:       StatusValid,
		SignerCertificate: signerCert,
		CertificateChain:  certs[1:],
		Name:              signerCert.Subject.CommonName,
	}

	// Set signing time
	signingTime, err := cms.GetSigningTime(embeddedSig.Contents)
	if err == nil {
		result.APIStatus.SigningTime = signingTime
		result.SignaturePOETime = signingTime
	}

	// If we got here, basic validation passed
	if result.Indication == ades.IndicationIndeterminate && result.SubIndication == "" {
		result.Indication = ades.IndicationPassed
	}

	return result, nil
}

// AdESTimestampValidation validates a timestamp token per ETSI EN 319 102-1 § 5.4.
func AdESTimestampValidation(
	timestampData []byte,
	expectedImprint []byte,
	spec *AdESValidationSpec,
) (*AdESBasicValidationResult, error) {
	result := NewAdESBasicValidationResult()

	// Parse the timestamp token
	tstInfo, err := parseTimestampToken(timestampData)
	if err != nil {
		result.Indication = ades.IndicationFailed
		result.SubIndication = ades.SubIndicationFormatFailure
		result.FailureMessage = fmt.Sprintf("failed to parse timestamp: %v", err)
		return result, nil
	}

	// Verify the message imprint
	if expectedImprint != nil {
		if err := verifyTimestampImprint(tstInfo, expectedImprint); err != nil {
			result.Indication = ades.IndicationFailed
			result.SubIndication = ades.SubIndicationHashFailure
			result.FailureMessage = "timestamp imprint mismatch"
			return result, nil
		}
	}

	// Verify the CMS signature
	if err := cms.VerifyCMSSignature(timestampData, nil); err != nil {
		result.Indication = ades.IndicationFailed
		result.SubIndication = ades.SubIndicationSigCryptoFailure
		result.FailureMessage = fmt.Sprintf("timestamp signature invalid: %v", err)
		return result, nil
	}

	// Get TSA certificate
	certs, err := cms.GetSignerCertificates(timestampData)
	if err != nil || len(certs) == 0 {
		result.Indication = ades.IndicationIndeterminate
		result.SubIndication = ades.SubIndicationNoSignerCertFound
		result.FailureMessage = "TSA certificate not found"
		return result, nil
	}

	// Verify TSA trust
	if spec.TrustManager != nil {
		trusted := false
		for _, cert := range certs {
			if spec.TrustManager.IsRoot(cert) {
				trusted = true
				break
			}
		}
		if !trusted {
			result.Indication = ades.IndicationIndeterminate
			result.SubIndication = ades.SubIndicationNoCertificateChainFound
			result.FailureMessage = "TSA certificate not trusted"
			return result, nil
		}
	}

	result.Indication = ades.IndicationPassed
	result.SignaturePOETime = tstInfo.GenTime
	result.ValidationPath = certs

	// Create timestamp status
	result.TimestampValidity = &TimestampSignatureStatus{
		Valid:             true,
		Trusted:           true,
		Timestamp:         tstInfo.GenTime,
		SignerCertificate: certs[0],
		CertificatePath:   certs,
	}

	return result, nil
}

// AdESWithTimeValidation performs with-time validation per ETSI EN 319 102-1 § 5.5.
func AdESWithTimeValidation(
	embeddedSig *reader.EmbeddedSignature,
	spec *AdESValidationSpec,
) (*AdESWithTimeValidationResult, error) {
	result := NewAdESWithTimeValidationResult()

	// First do basic validation
	basicResult, err := AdESBasicValidation(embeddedSig, spec)
	if err != nil {
		return nil, err
	}
	result.AdESBasicValidationResult = basicResult

	// If basic validation failed, return early
	if !basicResult.IsPassed() {
		return result, nil
	}

	// Check for embedded timestamp
	embeddedTS := getEmbeddedTimestamp(embeddedSig)
	if embeddedTS != nil {
		tsResult, err := AdESTimestampValidation(embeddedTS, nil, spec)
		if err != nil {
			return nil, err
		}

		if tsResult.IsPassed() {
			result.TimestampValidity = tsResult.TimestampValidity
			result.BestSignatureTime = tsResult.SignaturePOETime
		} else if spec.RequireTimestamp {
			result.Indication = ades.IndicationIndeterminate
			result.SubIndication = ades.SubIndicationNoValidTimestamp
			result.FailureMessage = "timestamp validation failed"
			return result, nil
		}
	} else if spec.RequireTimestamp {
		result.Indication = ades.IndicationIndeterminate
		result.SubIndication = ades.SubIndicationNoValidTimestamp
		result.FailureMessage = "no timestamp present"
		return result, nil
	}

	// Use signing time if no timestamp
	if result.BestSignatureTime.IsZero() && result.APIStatus != nil {
		result.BestSignatureTime = result.APIStatus.SigningTime
	}

	return result, nil
}

// AdESLTAValidation performs LTA (Long-Term Archival) validation per ETSI EN 319 102-1 § 5.6.
func AdESLTAValidation(
	embeddedSig *reader.EmbeddedSignature,
	spec *AdESValidationSpec,
) (*AdESLTAValidationResult, error) {
	result := NewAdESLTAValidationResult()
	pdfReader := embeddedSig.Reader

	// Get with-time validation first
	withTimeResult, err := AdESWithTimeValidation(embeddedSig, spec)
	if err != nil {
		return nil, err
	}
	result.AdESWithTimeValidationResult = withTimeResult

	// Check for DSS
	dss, err := ExtractDSS(pdfReader)
	if err == nil && dss != nil {
		result.DSSPresent = true

		// Check for revocation data
		if len(dss.CRLs) > 0 || len(dss.OCSPs) > 0 {
			result.RevocationDataComplete = true

			// Add to validation objects
			for _, crl := range dss.CRLs {
				vo := &ValidationObject{
					ObjectType: ValidationObjectCRL,
					Value:      crl,
				}
				vo.Identifier = DeriveValidationObjectIdentifier(vo)
				result.ValidationObjects.Add(vo)
			}
			for _, ocsp := range dss.OCSPs {
				vo := &ValidationObject{
					ObjectType: ValidationObjectOCSP,
					Value:      ocsp,
				}
				vo.Identifier = DeriveValidationObjectIdentifier(vo)
				result.ValidationObjects.Add(vo)
			}
		}

		// Check for certificates
		if len(dss.Certs) > 0 {
			result.CertificateDataComplete = true

			for _, cert := range dss.Certs {
				vo := &ValidationObject{
					ObjectType: ValidationObjectCertificate,
					Value:      cert,
				}
				vo.Identifier = DeriveValidationObjectIdentifier(vo)
				result.ValidationObjects.Add(vo)
			}
		}
	}

	// Validate document timestamps
	docTimestamps, err := GetTimestampChain(pdfReader)
	if err == nil && len(docTimestamps) > 0 {
		for _, ts := range docTimestamps {
			tsResult, err := AdESTimestampValidation(ts.Contents, nil, spec)
			if err != nil {
				continue
			}
			if tsResult.TimestampValidity != nil {
				result.DocumentTimestamps = append(result.DocumentTimestamps, tsResult.TimestampValidity)
			}
		}
	}

	// For LTA, we need DSS and valid timestamps
	if !result.DSSPresent {
		// Not technically a failure for LTA, but we note it
		result.FailureMessage = "no DSS found for LTA validation"
	}

	return result, nil
}

// AdESValidator provides AdES validation functionality.
type AdESValidator struct {
	Spec *AdESValidationSpec
}

// NewAdESValidator creates a new AdES validator.
func NewAdESValidator(trustManager certvalidator.TrustManager) *AdESValidator {
	return &AdESValidator{
		Spec: NewAdESValidationSpec(trustManager),
	}
}

// ValidateBasic performs basic AdES validation.
func (v *AdESValidator) ValidateBasic(sig *reader.EmbeddedSignature) (*AdESBasicValidationResult, error) {
	return AdESBasicValidation(sig, v.Spec)
}

// ValidateWithTime performs with-time AdES validation.
func (v *AdESValidator) ValidateWithTime(sig *reader.EmbeddedSignature) (*AdESWithTimeValidationResult, error) {
	return AdESWithTimeValidation(sig, v.Spec)
}

// ValidateLTA performs LTA AdES validation.
func (v *AdESValidator) ValidateLTA(sig *reader.EmbeddedSignature) (*AdESLTAValidationResult, error) {
	return AdESLTAValidation(sig, v.Spec)
}

// ValidateAllSignatures validates all signatures in a PDF.
func (v *AdESValidator) ValidateAllSignatures(pdfReader *reader.PdfFileReader) ([]*AdESLTAValidationResult, error) {
	sigs, err := pdfReader.GetEmbeddedSignatures()
	if err != nil {
		return nil, err
	}

	var results []*AdESLTAValidationResult
	for _, sig := range sigs {
		// Skip document timestamps
		if isDocumentTimestamp(sig) {
			continue
		}

		result, err := v.ValidateLTA(sig)
		if err != nil {
			// Add error result
			errResult := NewAdESLTAValidationResult()
			errResult.Indication = ades.IndicationFailed
			errResult.FailureMessage = err.Error()
			results = append(results, errResult)
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// GenerateValidationReport generates an AdES validation report.
func (v *AdESValidator) GenerateValidationReport(
	pdfReader *reader.PdfFileReader,
	reportID string,
) (*ades.ValidationReport, error) {
	builder := ades.NewReportBuilder(reportID)

	results, err := v.ValidateAllSignatures(pdfReader)
	if err != nil {
		return nil, err
	}

	for i, result := range results {
		sigID := fmt.Sprintf("sig-%d", i+1)
		builder.StartSignature(sigID)
		builder.SetSignatureFormat("PAdES")

		if result.APIStatus != nil {
			if result.APIStatus.SignerCertificate != nil {
				builder.SetSignerCertificate(result.APIStatus.SignerCertificate)
			}
			if !result.APIStatus.SigningTime.IsZero() {
				builder.SetSigningTime(result.APIStatus.SigningTime)
			}
			for j, cert := range result.APIStatus.CertificateChain {
				builder.AddChainCertificate(cert, fmt.Sprintf("chain-%d", j+1))
			}
		}

		// Set level based on LTA data
		level := "PAdES-B"
		if len(result.DocumentTimestamps) > 0 {
			if result.DSSPresent && result.RevocationDataComplete {
				level = "PAdES-LTA"
			} else if result.TimestampValidity != nil {
				level = "PAdES-LT"
			} else {
				level = "PAdES-T"
			}
		} else if result.TimestampValidity != nil {
			level = "PAdES-T"
		}
		builder.SetSignatureLevel(level)

		builder.SetSignatureConclusion(result.Indication, result.SubIndication)
		if result.FailureMessage != "" {
			builder.AddSignatureError("validation", result.FailureMessage)
		}

		builder.EndSignature()
	}

	return builder.Build(), nil
}

// SimulateFutureAdESLTAValidation simulates future LTA validation.
func SimulateFutureAdESLTAValidation(
	embeddedSig *reader.EmbeddedSignature,
	futureTime time.Time,
	spec *AdESValidationSpec,
) (*AdESLTAValidationResult, error) {
	// Create a copy of the spec with the future time
	futureSpec := &AdESValidationSpec{
		TrustManager:     spec.TrustManager,
		ValidationTime:   futureTime,
		AlgorithmPolicy:  spec.AlgorithmPolicy,
		RevocationPolicy: spec.RevocationPolicy,
		LocalKnowledge:   spec.LocalKnowledge,
		RequireTimestamp: true, // Future validation always requires timestamp
	}

	return AdESLTAValidation(embeddedSig, futureSpec)
}
