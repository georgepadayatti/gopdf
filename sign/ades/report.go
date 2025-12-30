// AdES validation report functionality.
// This implements ETSI TS 119 102-2 validation report format.

package ades

import (
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Validation Indication values per ETSI EN 319 102-1
const (
	IndicationPassed        = "PASSED"
	IndicationFailed        = "FAILED"
	IndicationIndeterminate = "INDETERMINATE"
)

// Sub-indication values per ETSI EN 319 102-1
const (
	// PASSED sub-indications (none defined, PASSED is always standalone)

	// FAILED sub-indications
	SubIndicationFormatFailure                   = "FORMAT_FAILURE"
	SubIndicationHashFailure                     = "HASH_FAILURE"
	SubIndicationSigConstraintsFailure           = "SIG_CONSTRAINTS_FAILURE"
	SubIndicationPolicyProcessingError           = "POLICY_PROCESSING_ERROR"
	SubIndicationSignatureConstraintFailure      = "SIGNATURE_CONSTRAINT_FAILURE"
	SubIndicationChainConstraintsFailure         = "CHAIN_CONSTRAINTS_FAILURE"
	SubIndicationCertificateChainGeneralFailure  = "CERTIFICATE_CHAIN_GENERAL_FAILURE"
	SubIndicationCryptoConstraintsFailure        = "CRYPTO_CONSTRAINTS_FAILURE"
	SubIndicationExpiredNoPoE                    = "EXPIRED_NO_POE"
	SubIndicationRevokedNoPoe                    = "REVOKED_NO_POE"
	SubIndicationRevokedCaNoPoe                  = "REVOKED_CA_NO_POE"

	// INDETERMINATE sub-indications
	SubIndicationSigCryptoFailure                = "SIG_CRYPTO_FAILURE"
	SubIndicationRevoked                         = "REVOKED"
	SubIndicationSignedDataNotFound              = "SIGNED_DATA_NOT_FOUND"
	SubIndicationNoPoa                           = "NO_POA"
	SubIndicationNoValidTimestamp                = "NO_VALID_TIMESTAMP"
	SubIndicationTimestampOrderFailure           = "TIMESTAMP_ORDER_FAILURE"
	SubIndicationNoCertificateChainFound         = "NO_CERTIFICATE_CHAIN_FOUND"
	SubIndicationRevokedNoPoE                    = "REVOKED_NO_POE"
	SubIndicationOutOfBoundsNoPoE                = "OUT_OF_BOUNDS_NO_POE"
	SubIndicationOutOfBoundsNotRevoked           = "OUT_OF_BOUNDS_NOT_REVOKED"
	SubIndicationCryptoConstraintsFailureNoPoE   = "CRYPTO_CONSTRAINTS_FAILURE_NO_POE"
	SubIndicationNoSignerCertFound               = "NO_SIGNER_CERT_FOUND"
	SubIndicationTryLater                        = "TRY_LATER"
	SubIndicationGenericNoPoE                    = "GENERIC_NO_POE"
)

// ValidationConclusion represents the overall validation conclusion.
type ValidationConclusion struct {
	Indication    string `json:"indication" xml:"Indication"`
	SubIndication string `json:"subIndication,omitempty" xml:"SubIndication,omitempty"`
	Errors        []ValidationError `json:"errors,omitempty" xml:"Errors>Error,omitempty"`
	Warnings      []ValidationWarning `json:"warnings,omitempty" xml:"Warnings>Warning,omitempty"`
	Infos         []ValidationInfo `json:"infos,omitempty" xml:"Infos>Info,omitempty"`
}

// ValidationError represents a validation error.
type ValidationError struct {
	Key     string `json:"key" xml:"Key"`
	Value   string `json:"value" xml:"Value"`
}

// ValidationWarning represents a validation warning.
type ValidationWarning struct {
	Key     string `json:"key" xml:"Key"`
	Value   string `json:"value" xml:"Value"`
}

// ValidationInfo represents validation information.
type ValidationInfo struct {
	Key     string `json:"key" xml:"Key"`
	Value   string `json:"value" xml:"Value"`
}

// NewValidationConclusion creates a new validation conclusion.
func NewValidationConclusion(indication string) *ValidationConclusion {
	return &ValidationConclusion{
		Indication: indication,
	}
}

// SetSubIndication sets the sub-indication.
func (c *ValidationConclusion) SetSubIndication(subInd string) {
	c.SubIndication = subInd
}

// AddError adds an error to the conclusion.
func (c *ValidationConclusion) AddError(key, value string) {
	c.Errors = append(c.Errors, ValidationError{Key: key, Value: value})
}

// AddWarning adds a warning to the conclusion.
func (c *ValidationConclusion) AddWarning(key, value string) {
	c.Warnings = append(c.Warnings, ValidationWarning{Key: key, Value: value})
}

// AddInfo adds information to the conclusion.
func (c *ValidationConclusion) AddInfo(key, value string) {
	c.Infos = append(c.Infos, ValidationInfo{Key: key, Value: value})
}

// IsPassed returns true if the indication is PASSED.
func (c *ValidationConclusion) IsPassed() bool {
	return c.Indication == IndicationPassed
}

// IsFailed returns true if the indication is FAILED.
func (c *ValidationConclusion) IsFailed() bool {
	return c.Indication == IndicationFailed
}

// IsIndeterminate returns true if the indication is INDETERMINATE.
func (c *ValidationConclusion) IsIndeterminate() bool {
	return c.Indication == IndicationIndeterminate
}

// SignatureScope represents the scope of a signature.
type SignatureScope struct {
	Name        string `json:"name" xml:"Name"`
	Description string `json:"description,omitempty" xml:"Description,omitempty"`
	Scope       string `json:"scope" xml:"Scope"`
}

// CertificateInfo contains information about a certificate in the report.
type CertificateInfo struct {
	ID                  string    `json:"id" xml:"Id,attr"`
	Subject             string    `json:"subject" xml:"Subject"`
	Issuer              string    `json:"issuer" xml:"Issuer"`
	SerialNumber        string    `json:"serialNumber" xml:"SerialNumber"`
	NotBefore           time.Time `json:"notBefore" xml:"NotBefore"`
	NotAfter            time.Time `json:"notAfter" xml:"NotAfter"`
	IsSelfSigned        bool      `json:"isSelfSigned" xml:"IsSelfSigned"`
	IsCA                bool      `json:"isCA" xml:"IsCA"`
	KeyUsage            []string  `json:"keyUsage,omitempty" xml:"KeyUsage>Usage,omitempty"`
	ExtendedKeyUsage    []string  `json:"extendedKeyUsage,omitempty" xml:"ExtendedKeyUsage>Usage,omitempty"`
	QCStatements        []string  `json:"qcStatements,omitempty" xml:"QCStatements>Statement,omitempty"`
}

// NewCertificateInfo creates certificate info from an x509 certificate.
func NewCertificateInfo(cert *x509.Certificate, id string) *CertificateInfo {
	info := &CertificateInfo{
		ID:           id,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsSelfSigned: cert.CheckSignatureFrom(cert) == nil,
		IsCA:         cert.IsCA,
	}

	// Key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		info.KeyUsage = append(info.KeyUsage, "digitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		info.KeyUsage = append(info.KeyUsage, "contentCommitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		info.KeyUsage = append(info.KeyUsage, "keyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		info.KeyUsage = append(info.KeyUsage, "dataEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		info.KeyUsage = append(info.KeyUsage, "keyAgreement")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		info.KeyUsage = append(info.KeyUsage, "keyCertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		info.KeyUsage = append(info.KeyUsage, "cRLSign")
	}

	// Extended key usage
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			info.ExtendedKeyUsage = append(info.ExtendedKeyUsage, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			info.ExtendedKeyUsage = append(info.ExtendedKeyUsage, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			info.ExtendedKeyUsage = append(info.ExtendedKeyUsage, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			info.ExtendedKeyUsage = append(info.ExtendedKeyUsage, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			info.ExtendedKeyUsage = append(info.ExtendedKeyUsage, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			info.ExtendedKeyUsage = append(info.ExtendedKeyUsage, "OCSPSigning")
		}
	}

	return info
}

// IsValidAt checks if the certificate was valid at the given time.
func (c *CertificateInfo) IsValidAt(at time.Time) bool {
	return !at.Before(c.NotBefore) && !at.After(c.NotAfter)
}

// TimestampInfo contains information about a timestamp.
type TimestampInfo struct {
	ID            string              `json:"id" xml:"Id,attr"`
	Type          string              `json:"type" xml:"Type"`
	ProductionTime time.Time          `json:"productionTime" xml:"ProductionTime"`
	DigestAlgorithm string            `json:"digestAlgorithm" xml:"DigestAlgorithm"`
	DigestValue   string              `json:"digestValue" xml:"DigestValue"`
	TSAName       string              `json:"tsaName,omitempty" xml:"TSAName,omitempty"`
	Conclusion    *ValidationConclusion `json:"conclusion" xml:"Conclusion"`
}

// RevocationInfo contains revocation information.
type RevocationInfo struct {
	ID            string    `json:"id" xml:"Id,attr"`
	Type          string    `json:"type" xml:"Type"` // "CRL" or "OCSP"
	ProductionTime time.Time `json:"productionTime" xml:"ProductionTime"`
	ThisUpdate    time.Time `json:"thisUpdate" xml:"ThisUpdate"`
	NextUpdate    *time.Time `json:"nextUpdate,omitempty" xml:"NextUpdate,omitempty"`
	RevocationDate *time.Time `json:"revocationDate,omitempty" xml:"RevocationDate,omitempty"`
	RevocationReason string  `json:"revocationReason,omitempty" xml:"RevocationReason,omitempty"`
}

// SignatureInfo contains detailed signature information.
type SignatureInfo struct {
	ID                   string               `json:"id" xml:"Id,attr"`
	SignatureFormat      string               `json:"signatureFormat" xml:"SignatureFormat"`
	SignatureLevel       string               `json:"signatureLevel,omitempty" xml:"SignatureLevel,omitempty"`
	SigningTime          *time.Time           `json:"signingTime,omitempty" xml:"SigningTime,omitempty"`
	ClaimedSigningTime   *time.Time           `json:"claimedSigningTime,omitempty" xml:"ClaimedSigningTime,omitempty"`
	BestSignatureTime    *time.Time           `json:"bestSignatureTime,omitempty" xml:"BestSignatureTime,omitempty"`
	SignatureProductionPlace *SignatureProductionPlace `json:"signatureProductionPlace,omitempty" xml:"SignatureProductionPlace,omitempty"`
	SignerRole           *SignerRole          `json:"signerRole,omitempty" xml:"SignerRole,omitempty"`
	CommitmentTypes      []string             `json:"commitmentTypes,omitempty" xml:"CommitmentTypes>Type,omitempty"`
	DigestAlgorithm      string               `json:"digestAlgorithm" xml:"DigestAlgorithm"`
	EncryptionAlgorithm  string               `json:"encryptionAlgorithm" xml:"EncryptionAlgorithm"`
	SignerCertificate    *CertificateInfo     `json:"signerCertificate,omitempty" xml:"SignerCertificate,omitempty"`
	CertificateChain     []*CertificateInfo   `json:"certificateChain,omitempty" xml:"CertificateChain>Certificate,omitempty"`
	Timestamps           []*TimestampInfo     `json:"timestamps,omitempty" xml:"Timestamps>Timestamp,omitempty"`
	RevocationData       []*RevocationInfo    `json:"revocationData,omitempty" xml:"RevocationData>Revocation,omitempty"`
	Scopes               []*SignatureScope    `json:"scopes,omitempty" xml:"SignatureScopes>SignatureScope,omitempty"`
	Conclusion           *ValidationConclusion `json:"conclusion" xml:"Conclusion"`
}

// SignatureProductionPlace represents where a signature was produced.
type SignatureProductionPlace struct {
	City            string `json:"city,omitempty" xml:"City,omitempty"`
	StateOrProvince string `json:"stateOrProvince,omitempty" xml:"StateOrProvince,omitempty"`
	PostalCode      string `json:"postalCode,omitempty" xml:"PostalCode,omitempty"`
	CountryName     string `json:"countryName,omitempty" xml:"CountryName,omitempty"`
	StreetAddress   string `json:"streetAddress,omitempty" xml:"StreetAddress,omitempty"`
}

// SignerRole represents the role of a signer.
type SignerRole struct {
	ClaimedRoles    []string `json:"claimedRoles,omitempty" xml:"ClaimedRoles>Role,omitempty"`
	CertifiedRoles  []string `json:"certifiedRoles,omitempty" xml:"CertifiedRoles>Role,omitempty"`
}

// ValidationReport represents an AdES validation report.
type ValidationReport struct {
	XMLName              xml.Name             `json:"-" xml:"ValidationReport"`
	ID                   string               `json:"id" xml:"Id,attr"`
	ValidationTime       time.Time            `json:"validationTime" xml:"ValidationTime"`
	ValidationPolicy     *ValidationPolicy    `json:"validationPolicy,omitempty" xml:"ValidationPolicy,omitempty"`
	SignatureValidation  []*SignatureInfo     `json:"signatureValidation,omitempty" xml:"SignatureValidation>Signature,omitempty"`
	DocumentInfo         *DocumentInfo        `json:"documentInfo,omitempty" xml:"DocumentInfo,omitempty"`
	Conclusion           *ValidationConclusion `json:"conclusion" xml:"Conclusion"`
}

// ValidationPolicy represents the policy used for validation.
type ValidationPolicy struct {
	ID          string `json:"id" xml:"Id"`
	Name        string `json:"name" xml:"Name"`
	Description string `json:"description,omitempty" xml:"Description,omitempty"`
	URL         string `json:"url,omitempty" xml:"URL,omitempty"`
}

// DocumentInfo contains information about the validated document.
type DocumentInfo struct {
	Filename    string `json:"filename,omitempty" xml:"Filename,omitempty"`
	MimeType    string `json:"mimeType,omitempty" xml:"MimeType,omitempty"`
	DigestAlgo  string `json:"digestAlgorithm,omitempty" xml:"DigestAlgorithm,omitempty"`
	DigestValue string `json:"digestValue,omitempty" xml:"DigestValue,omitempty"`
	Size        int64  `json:"size,omitempty" xml:"Size,omitempty"`
}

// NewValidationReport creates a new validation report.
func NewValidationReport(id string) *ValidationReport {
	return &ValidationReport{
		ID:             id,
		ValidationTime: time.Now(),
		Conclusion:     NewValidationConclusion(IndicationIndeterminate),
	}
}

// SetValidationPolicy sets the validation policy.
func (r *ValidationReport) SetValidationPolicy(policy *ValidationPolicy) {
	r.ValidationPolicy = policy
}

// SetDocumentInfo sets the document information.
func (r *ValidationReport) SetDocumentInfo(info *DocumentInfo) {
	r.DocumentInfo = info
}

// AddSignature adds a signature validation result.
func (r *ValidationReport) AddSignature(sig *SignatureInfo) {
	r.SignatureValidation = append(r.SignatureValidation, sig)
}

// ComputeOverallConclusion computes the overall conclusion from all signatures.
func (r *ValidationReport) ComputeOverallConclusion() {
	if len(r.SignatureValidation) == 0 {
		r.Conclusion = NewValidationConclusion(IndicationIndeterminate)
		r.Conclusion.SetSubIndication(SubIndicationSignedDataNotFound)
		return
	}

	// Overall is PASSED only if all signatures are PASSED
	allPassed := true
	hasFailed := false
	var firstSubInd string

	for _, sig := range r.SignatureValidation {
		if sig.Conclusion == nil {
			allPassed = false
			continue
		}
		if sig.Conclusion.IsFailed() {
			hasFailed = true
			if firstSubInd == "" {
				firstSubInd = sig.Conclusion.SubIndication
			}
		}
		if !sig.Conclusion.IsPassed() {
			allPassed = false
			if firstSubInd == "" && sig.Conclusion.SubIndication != "" {
				firstSubInd = sig.Conclusion.SubIndication
			}
		}
	}

	if allPassed {
		r.Conclusion = NewValidationConclusion(IndicationPassed)
	} else if hasFailed {
		r.Conclusion = NewValidationConclusion(IndicationFailed)
		if firstSubInd != "" {
			r.Conclusion.SetSubIndication(firstSubInd)
		}
	} else {
		r.Conclusion = NewValidationConclusion(IndicationIndeterminate)
		if firstSubInd != "" {
			r.Conclusion.SetSubIndication(firstSubInd)
		}
	}
}

// SignatureCount returns the number of signatures.
func (r *ValidationReport) SignatureCount() int {
	return len(r.SignatureValidation)
}

// PassedCount returns the number of passed signatures.
func (r *ValidationReport) PassedCount() int {
	count := 0
	for _, sig := range r.SignatureValidation {
		if sig.Conclusion != nil && sig.Conclusion.IsPassed() {
			count++
		}
	}
	return count
}

// FailedCount returns the number of failed signatures.
func (r *ValidationReport) FailedCount() int {
	count := 0
	for _, sig := range r.SignatureValidation {
		if sig.Conclusion != nil && sig.Conclusion.IsFailed() {
			count++
		}
	}
	return count
}

// ToJSON serializes the report to JSON.
func (r *ValidationReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToXML serializes the report to XML.
func (r *ValidationReport) ToXML() ([]byte, error) {
	return xml.MarshalIndent(r, "", "  ")
}

// ReportBuilder helps build validation reports.
type ReportBuilder struct {
	report *ValidationReport
	currentSig *SignatureInfo
}

// NewReportBuilder creates a new report builder.
func NewReportBuilder(id string) *ReportBuilder {
	return &ReportBuilder{
		report: NewValidationReport(id),
	}
}

// SetValidationTime sets the validation time.
func (b *ReportBuilder) SetValidationTime(t time.Time) *ReportBuilder {
	b.report.ValidationTime = t
	return b
}

// SetPolicy sets the validation policy.
func (b *ReportBuilder) SetPolicy(id, name, description string) *ReportBuilder {
	b.report.ValidationPolicy = &ValidationPolicy{
		ID:          id,
		Name:        name,
		Description: description,
	}
	return b
}

// SetDocument sets the document information.
func (b *ReportBuilder) SetDocument(filename, mimeType string, size int64) *ReportBuilder {
	b.report.DocumentInfo = &DocumentInfo{
		Filename: filename,
		MimeType: mimeType,
		Size:     size,
	}
	return b
}

// StartSignature starts a new signature entry.
func (b *ReportBuilder) StartSignature(id string) *ReportBuilder {
	b.currentSig = &SignatureInfo{
		ID:         id,
		Conclusion: NewValidationConclusion(IndicationIndeterminate),
	}
	return b
}

// SetSignatureFormat sets the signature format.
func (b *ReportBuilder) SetSignatureFormat(format string) *ReportBuilder {
	if b.currentSig != nil {
		b.currentSig.SignatureFormat = format
	}
	return b
}

// SetSignatureLevel sets the signature level.
func (b *ReportBuilder) SetSignatureLevel(level string) *ReportBuilder {
	if b.currentSig != nil {
		b.currentSig.SignatureLevel = level
	}
	return b
}

// SetSigningTime sets the signing time.
func (b *ReportBuilder) SetSigningTime(t time.Time) *ReportBuilder {
	if b.currentSig != nil {
		b.currentSig.SigningTime = &t
	}
	return b
}

// SetSignerCertificate sets the signer certificate.
func (b *ReportBuilder) SetSignerCertificate(cert *x509.Certificate) *ReportBuilder {
	if b.currentSig != nil && cert != nil {
		b.currentSig.SignerCertificate = NewCertificateInfo(cert, "signer-cert")
	}
	return b
}

// AddChainCertificate adds a certificate to the chain.
func (b *ReportBuilder) AddChainCertificate(cert *x509.Certificate, id string) *ReportBuilder {
	if b.currentSig != nil && cert != nil {
		b.currentSig.CertificateChain = append(b.currentSig.CertificateChain, NewCertificateInfo(cert, id))
	}
	return b
}

// SetSignatureConclusion sets the signature conclusion.
func (b *ReportBuilder) SetSignatureConclusion(indication, subIndication string) *ReportBuilder {
	if b.currentSig != nil {
		b.currentSig.Conclusion = NewValidationConclusion(indication)
		if subIndication != "" {
			b.currentSig.Conclusion.SetSubIndication(subIndication)
		}
	}
	return b
}

// AddSignatureError adds an error to the current signature.
func (b *ReportBuilder) AddSignatureError(key, value string) *ReportBuilder {
	if b.currentSig != nil && b.currentSig.Conclusion != nil {
		b.currentSig.Conclusion.AddError(key, value)
	}
	return b
}

// AddSignatureWarning adds a warning to the current signature.
func (b *ReportBuilder) AddSignatureWarning(key, value string) *ReportBuilder {
	if b.currentSig != nil && b.currentSig.Conclusion != nil {
		b.currentSig.Conclusion.AddWarning(key, value)
	}
	return b
}

// EndSignature ends the current signature and adds it to the report.
func (b *ReportBuilder) EndSignature() *ReportBuilder {
	if b.currentSig != nil {
		b.report.AddSignature(b.currentSig)
		b.currentSig = nil
	}
	return b
}

// Build completes and returns the report.
func (b *ReportBuilder) Build() *ValidationReport {
	// End any pending signature
	if b.currentSig != nil {
		b.EndSignature()
	}
	b.report.ComputeOverallConclusion()
	return b.report
}

// SimpleReportFormat represents a simplified text report format.
type SimpleReportFormat struct {
	IncludeDetails bool
	IncludeChain   bool
	IncludeTimestamps bool
}

// DefaultSimpleReportFormat returns the default simple report format.
func DefaultSimpleReportFormat() *SimpleReportFormat {
	return &SimpleReportFormat{
		IncludeDetails:    true,
		IncludeChain:      false,
		IncludeTimestamps: true,
	}
}

// ToSimpleText generates a simple text report.
func (r *ValidationReport) ToSimpleText(format *SimpleReportFormat) string {
	if format == nil {
		format = DefaultSimpleReportFormat()
	}

	var sb strings.Builder

	sb.WriteString("=== VALIDATION REPORT ===\n")
	sb.WriteString(fmt.Sprintf("Report ID: %s\n", r.ID))
	sb.WriteString(fmt.Sprintf("Validation Time: %s\n", r.ValidationTime.Format(time.RFC3339)))

	if r.DocumentInfo != nil {
		sb.WriteString(fmt.Sprintf("Document: %s (%s)\n", r.DocumentInfo.Filename, r.DocumentInfo.MimeType))
	}

	sb.WriteString(fmt.Sprintf("\nOverall Result: %s", r.Conclusion.Indication))
	if r.Conclusion.SubIndication != "" {
		sb.WriteString(fmt.Sprintf(" (%s)", r.Conclusion.SubIndication))
	}
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("\nSignatures: %d total, %d passed, %d failed\n",
		r.SignatureCount(), r.PassedCount(), r.FailedCount()))

	for i, sig := range r.SignatureValidation {
		sb.WriteString(fmt.Sprintf("\n--- Signature %d ---\n", i+1))
		sb.WriteString(fmt.Sprintf("ID: %s\n", sig.ID))
		sb.WriteString(fmt.Sprintf("Format: %s\n", sig.SignatureFormat))
		if sig.SignatureLevel != "" {
			sb.WriteString(fmt.Sprintf("Level: %s\n", sig.SignatureLevel))
		}
		if sig.SigningTime != nil {
			sb.WriteString(fmt.Sprintf("Signing Time: %s\n", sig.SigningTime.Format(time.RFC3339)))
		}

		if format.IncludeDetails && sig.SignerCertificate != nil {
			sb.WriteString(fmt.Sprintf("Signer: %s\n", sig.SignerCertificate.Subject))
			sb.WriteString(fmt.Sprintf("Issuer: %s\n", sig.SignerCertificate.Issuer))
		}

		if format.IncludeChain && len(sig.CertificateChain) > 0 {
			sb.WriteString("Certificate Chain:\n")
			for j, cert := range sig.CertificateChain {
				sb.WriteString(fmt.Sprintf("  %d. %s\n", j+1, cert.Subject))
			}
		}

		if format.IncludeTimestamps && len(sig.Timestamps) > 0 {
			sb.WriteString("Timestamps:\n")
			for _, ts := range sig.Timestamps {
				sb.WriteString(fmt.Sprintf("  - %s: %s\n", ts.Type, ts.ProductionTime.Format(time.RFC3339)))
			}
		}

		if sig.Conclusion != nil {
			sb.WriteString(fmt.Sprintf("Result: %s", sig.Conclusion.Indication))
			if sig.Conclusion.SubIndication != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", sig.Conclusion.SubIndication))
			}
			sb.WriteString("\n")

			for _, err := range sig.Conclusion.Errors {
				sb.WriteString(fmt.Sprintf("  ERROR: %s - %s\n", err.Key, err.Value))
			}
			for _, warn := range sig.Conclusion.Warnings {
				sb.WriteString(fmt.Sprintf("  WARNING: %s - %s\n", warn.Key, warn.Value))
			}
		}
	}

	return sb.String()
}

// SignatureLevelDetector detects the AdES signature level.
type SignatureLevelDetector struct{}

// DetectLevel detects the signature level based on available data.
func (d *SignatureLevelDetector) DetectLevel(sig *SignatureInfo) string {
	// Check for archive timestamps (level A)
	hasArchiveTS := false
	for _, ts := range sig.Timestamps {
		if ts.Type == "ARCHIVE_TIMESTAMP" {
			hasArchiveTS = true
			break
		}
	}
	if hasArchiveTS && len(sig.RevocationData) > 0 && len(sig.CertificateChain) > 0 {
		return "PAdES-A" // or CAdES-A
	}

	// Check for complete validation data (level LT/XL)
	if len(sig.RevocationData) > 0 && len(sig.CertificateChain) > 0 {
		hasTS := false
		for _, ts := range sig.Timestamps {
			if ts.Type == "SIGNATURE_TIMESTAMP" {
				hasTS = true
				break
			}
		}
		if hasTS {
			return "PAdES-LT" // or CAdES-XL
		}
	}

	// Check for timestamp (level T)
	for _, ts := range sig.Timestamps {
		if ts.Type == "SIGNATURE_TIMESTAMP" || ts.Type == "CONTENT_TIMESTAMP" {
			return "PAdES-T" // or CAdES-T
		}
	}

	// Basic level
	return "PAdES-B" // or CAdES-BES
}

// ValidationReportMerger merges multiple validation reports.
type ValidationReportMerger struct{}

// Merge merges multiple reports into one.
func (m *ValidationReportMerger) Merge(reports []*ValidationReport, id string) *ValidationReport {
	merged := NewValidationReport(id)

	for _, r := range reports {
		for _, sig := range r.SignatureValidation {
			merged.AddSignature(sig)
		}
	}

	merged.ComputeOverallConclusion()
	return merged
}

// ValidationReportFilter filters signatures in a report.
type ValidationReportFilter struct{}

// FilterByIndication returns a report with only signatures matching the indication.
func (f *ValidationReportFilter) FilterByIndication(report *ValidationReport, indication string) *ValidationReport {
	filtered := NewValidationReport(report.ID + "-filtered")
	filtered.ValidationTime = report.ValidationTime
	filtered.ValidationPolicy = report.ValidationPolicy
	filtered.DocumentInfo = report.DocumentInfo

	for _, sig := range report.SignatureValidation {
		if sig.Conclusion != nil && sig.Conclusion.Indication == indication {
			filtered.AddSignature(sig)
		}
	}

	filtered.ComputeOverallConclusion()
	return filtered
}

// FilterPassed returns only passed signatures.
func (f *ValidationReportFilter) FilterPassed(report *ValidationReport) *ValidationReport {
	return f.FilterByIndication(report, IndicationPassed)
}

// FilterFailed returns only failed signatures.
func (f *ValidationReportFilter) FilterFailed(report *ValidationReport) *ValidationReport {
	return f.FilterByIndication(report, IndicationFailed)
}
