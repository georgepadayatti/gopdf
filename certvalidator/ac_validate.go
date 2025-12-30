// Package certvalidator provides X.509 certificate path validation.
// This file implements attribute certificate (AC) validation per RFC 5755.
package certvalidator

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// AC validation errors
var (
	// ErrACHolderMismatch indicates the holder doesn't match the AC.
	ErrACHolderMismatch = errors.New("AC holder mismatch")

	// ErrACIssuerNotFound indicates no valid AA could be found.
	ErrACIssuerNotFound = errors.New("AC issuer not found")

	// ErrACTargetMismatch indicates the AC targeting doesn't match.
	ErrACTargetMismatch = errors.New("AC target mismatch")

	// ErrACExpired indicates the AC has expired.
	ErrACExpired = errors.New("AC expired")

	// ErrACNotYetValid indicates the AC is not yet valid.
	ErrACNotYetValid = errors.New("AC not yet valid")

	// ErrACCriticalExtension indicates an unsupported critical extension.
	ErrACCriticalExtension = errors.New("unsupported critical extension in AC")

	// ErrACObjectDigestNotSupported indicates ObjectDigestInfo is not supported.
	ErrACObjectDigestNotSupported = errors.New("ObjectDigestInfo not supported")

	// ErrACRevoked indicates the AC has been revoked.
	ErrACRevoked = errors.New("AC revoked")
)

// ACTargetDescription describes acceptable targets for AC validation.
type ACTargetDescription struct {
	// ValidatorNames are acceptable target names (as DNS names or URIs).
	ValidatorNames []string

	// GroupMemberships are acceptable group memberships.
	GroupMemberships []string
}

// NewACTargetDescription creates a new target description.
func NewACTargetDescription(names, groups []string) *ACTargetDescription {
	return &ACTargetDescription{
		ValidatorNames:   names,
		GroupMemberships: groups,
	}
}

// IsEmpty returns true if no targets are specified.
func (d *ACTargetDescription) IsEmpty() bool {
	return len(d.ValidatorNames) == 0 && len(d.GroupMemberships) == 0
}

// Holder represents the holder of an attribute certificate (RFC 5755).
type Holder struct {
	// BaseCertificateID identifies holder by issuer/serial.
	BaseCertificateID *IssuerSerial `asn1:"optional,explicit,tag:0"`

	// EntityName identifies holder by name.
	EntityName GeneralNames `asn1:"optional,explicit,tag:1"`

	// ObjectDigestInfo identifies holder by object digest.
	ObjectDigestInfo *ObjectDigestInfo `asn1:"optional,explicit,tag:2"`
}

// GeneralNames is a sequence of GeneralName values.
type GeneralNames []ASN1GeneralName

// V2Form represents the V2 form of AC issuer.
type V2Form struct {
	IssuerName        GeneralNames      `asn1:"optional"`
	BaseCertificateID *IssuerSerial     `asn1:"optional,explicit,tag:0"`
	ObjectDigestInfo  *ObjectDigestInfo `asn1:"optional,explicit,tag:1"`
}

// AttCertIssuer represents the issuer of an attribute certificate.
type AttCertIssuer struct {
	V1Form GeneralNames `asn1:"optional"`
	V2Form *V2Form      `asn1:"optional,explicit,tag:0"`
}

// AttCertValidityPeriod represents the validity period of an AC.
type AttCertValidityPeriod struct {
	NotBeforeTime time.Time
	NotAfterTime  time.Time
}

// AttCertAttribute represents an attribute in an attribute certificate.
type AttCertAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// AttributeCertificateInfo contains the information in an attribute certificate.
type AttributeCertificateInfo struct {
	Version             int                   `asn1:"default:1"`
	Holder              Holder
	Issuer              AttCertIssuer
	Signature           AlgorithmIdentifier
	SerialNumber        *big.Int
	AttrCertValidityPeriod AttCertValidityPeriod
	Attributes          []AttCertAttribute
	IssuerUniqueID      asn1.BitString     `asn1:"optional"`
	Extensions          []pkix.Extension   `asn1:"optional"`
}

// AttributeCertificateV2 represents an X.509 attribute certificate.
type AttributeCertificateV2 struct {
	ACInfo             AttributeCertificateInfo
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// ParseAttributeCertificate parses a DER-encoded attribute certificate.
func ParseAttributeCertificate(data []byte) (*AttributeCertificateV2, error) {
	var ac AttributeCertificateV2
	_, err := asn1.Unmarshal(data, &ac)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attribute certificate: %w", err)
	}
	return &ac, nil
}

// ACValidationConfig holds configuration for AC validation.
type ACValidationConfig struct {
	// TrustManager manages trust anchors
	TrustManager TrustManager

	// CertRegistry for certificate lookups
	CertRegistry *CertificateRegistry

	// ValidationTime for certificate validation
	ValidationTime time.Time

	// TimeTolerance for validity period checks
	TimeTolerance time.Duration

	// TargetDescription specifies acceptable targets
	TargetDescription *ACTargetDescription

	// SkipRevocation skips revocation checking
	SkipRevocation bool

	// PKIXParams for path validation
	PKIXParams *PKIXValidationParams
}

// NewACValidationConfig creates a new AC validation config with defaults.
func NewACValidationConfig(trustManager TrustManager) *ACValidationConfig {
	return &ACValidationConfig{
		TrustManager:   trustManager,
		ValidationTime: time.Now(),
		TimeTolerance:  time.Minute,
	}
}

// ACValidationResult holds the result of AC validation.
type ACValidationResult struct {
	// Valid indicates whether validation succeeded
	Valid bool

	// AttrCert is the validated attribute certificate
	AttrCert *AttributeCertificateV2

	// AACert is the Attribute Authority certificate
	AACert *x509.Certificate

	// AAPath is the validated AA certificate path
	AAPath *CertificationPath

	// ApprovedAttributes contains the approved attribute types and values
	ApprovedAttributes map[string][]asn1.RawValue

	// Errors encountered during validation
	Errors []error

	// Warnings (non-fatal issues)
	Warnings []string
}

// HolderMismatch represents a holder matching result.
type HolderMismatch int

const (
	// HolderMatchOK indicates holder matches.
	HolderMatchOK HolderMismatch = iota
	// HolderMismatchIssuer indicates issuer mismatch.
	HolderMismatchIssuer
	// HolderMismatchSerial indicates serial number mismatch.
	HolderMismatchSerial
	// HolderMismatchName indicates name mismatch.
	HolderMismatchName
)

// CheckACHolderMatch checks if a certificate matches the AC holder.
func CheckACHolderMatch(holderCert *x509.Certificate, holder *Holder) ([]HolderMismatch, error) {
	var mismatches []HolderMismatch

	// Check ObjectDigestInfo first - not supported
	if holder.ObjectDigestInfo != nil {
		return nil, ErrACObjectDigestNotSupported
	}

	// Check baseCertificateID
	if holder.BaseCertificateID != nil {
		// Compare issuer
		issuerMatch := compareIssuerSerial(holderCert, holder.BaseCertificateID)
		if !issuerMatch {
			mismatches = append(mismatches, HolderMismatchIssuer, HolderMismatchSerial)
		}
	}

	// Check entityName
	if len(holder.EntityName) > 0 {
		nameMatch := false
		for _, gn := range holder.EntityName {
			if matchesGeneralName(holderCert, &gn) {
				nameMatch = true
				break
			}
		}
		if !nameMatch {
			mismatches = append(mismatches, HolderMismatchName)
		}
	}

	return mismatches, nil
}

// compareIssuerSerial compares a certificate's issuer/serial with an IssuerSerial.
func compareIssuerSerial(cert *x509.Certificate, is *IssuerSerial) bool {
	// Compare issuer DN
	var issuerRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(is.Issuer.FullBytes, &issuerRDN); err != nil {
		return false
	}

	var certIssuer pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawIssuer, &certIssuer); err != nil {
		return false
	}

	if !compareRDNSequences(issuerRDN, certIssuer) {
		return false
	}

	// Compare serial number
	var serial *big.Int
	if _, err := asn1.Unmarshal(is.SerialNumber.FullBytes, &serial); err != nil {
		return false
	}

	return cert.SerialNumber.Cmp(serial) == 0
}

// compareRDNSequences compares two RDN sequences.
func compareRDNSequences(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if !a[i][j].Type.Equal(b[i][j].Type) {
				return false
			}
			if a[i][j].Value != b[i][j].Value {
				return false
			}
		}
	}
	return true
}

// matchesGeneralName checks if a certificate matches a GeneralName.
func matchesGeneralName(cert *x509.Certificate, gn *ASN1GeneralName) bool {
	switch gn.GetType() {
	case GeneralNameDNSName:
		// Compare with DNS names in SAN
		dnsName := string(gn.Raw.Bytes)
		for _, dns := range cert.DNSNames {
			if dns == dnsName {
				return true
			}
		}
	case GeneralNameRFC822Name:
		// Compare with email addresses
		email := string(gn.Raw.Bytes)
		for _, e := range cert.EmailAddresses {
			if e == email {
				return true
			}
		}
	case GeneralNameDirectoryName:
		// Compare with subject DN
		var rdn pkix.RDNSequence
		if _, err := asn1.Unmarshal(gn.Raw.Bytes, &rdn); err == nil {
			var subjectRDN pkix.RDNSequence
			if _, err := asn1.Unmarshal(cert.RawSubject, &subjectRDN); err == nil {
				if compareRDNSequences(rdn, subjectRDN) {
					return true
				}
			}
		}
	}
	return false
}

// ACValidator validates attribute certificates.
type ACValidator struct {
	Config *ACValidationConfig
}

// NewACValidator creates a new AC validator.
func NewACValidator(config *ACValidationConfig) *ACValidator {
	return &ACValidator{Config: config}
}

// ValidateAC validates an attribute certificate.
func (v *ACValidator) ValidateAC(ac *AttributeCertificateV2, holderCert *x509.Certificate) (*ACValidationResult, error) {
	result := &ACValidationResult{
		Valid:              true,
		AttrCert:           ac,
		ApprovedAttributes: make(map[string][]asn1.RawValue),
	}

	// Step 1: Check critical extensions
	if err := v.checkCriticalExtensions(ac); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		return result, nil
	}

	// Step 2: Check targeting if target description is provided
	if v.Config.TargetDescription != nil && !v.Config.TargetDescription.IsEmpty() {
		if err := v.validateACTargeting(ac); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}
	}

	// Step 3: Check holder if provided
	if holderCert != nil {
		mismatches, err := CheckACHolderMatch(holderCert, &ac.ACInfo.Holder)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}
		if len(mismatches) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, ErrACHolderMismatch)
			return result, nil
		}
	}

	// Step 4: Check validity period
	if err := v.checkValidityPeriod(ac); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		return result, nil
	}

	// Step 5: Find and validate AA certificate
	aaCert, aaPath, err := v.findAndValidateAA(ac)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		return result, nil
	}
	result.AACert = aaCert
	result.AAPath = aaPath

	// Step 6: Verify AC signature
	if err := v.verifyACSignature(ac, aaCert); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		return result, nil
	}

	// Step 7: Check revocation (unless no_rev_avail is present)
	if !v.Config.SkipRevocation && !hasACNoRevAvail(ac) {
		if err := v.checkACRevocation(ac, aaCert); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}
	}

	// Step 8: Filter and approve attributes based on AA controls
	for _, attr := range ac.ACInfo.Attributes {
		oidStr := attr.Type.String()
		if v.isAttributeApproved(attr.Type, aaPath) {
			result.ApprovedAttributes[oidStr] = attr.Values
		}
	}

	return result, nil
}

// Supported AC critical extensions
var supportedACExtensions = map[string]bool{
	"2.5.29.35": true, // authorityKeyIdentifier
	"2.5.29.31": true, // cRLDistributionPoints
	"2.5.29.46": true, // freshestCRL
	"2.5.29.14": true, // subjectKeyIdentifier
	"2.5.29.55": true, // targetInformation
	"2.5.29.56": true, // noRevAvail
	"1.3.6.1.5.5.7.1.1": true, // authorityInfoAccess
	"1.3.6.1.5.5.7.1.4": true, // auditIdentity
}

// checkCriticalExtensions checks for unsupported critical extensions.
func (v *ACValidator) checkCriticalExtensions(ac *AttributeCertificateV2) error {
	for _, ext := range ac.ACInfo.Extensions {
		if ext.Critical && !supportedACExtensions[ext.Id.String()] {
			return fmt.Errorf("%w: %s", ErrACCriticalExtension, ext.Id.String())
		}
	}
	return nil
}

// validateACTargeting validates AC targeting.
func (v *ACValidator) validateACTargeting(ac *AttributeCertificateV2) error {
	// Find target_information extension
	var targetInfo *SequenceOfTargets
	for _, ext := range ac.ACInfo.Extensions {
		if ext.Id.Equal(OIDTargetInformation) {
			var err error
			targetInfo, err = ParseTargetInformation(ext.Value)
			if err != nil {
				return err
			}
			break
		}
	}

	if targetInfo == nil {
		// No targeting - accept
		return nil
	}

	// Check if any target matches
	for _, targets := range *targetInfo {
		for _, target := range targets {
			switch target.GetType() {
			case TargetTypeName:
				// Check validator names
				name := string(target.TargetName.Raw.Bytes)
				for _, validName := range v.Config.TargetDescription.ValidatorNames {
					if name == validName {
						return nil
					}
				}
			case TargetTypeGroup:
				// Check group memberships
				group := string(target.TargetGroup.Raw.Bytes)
				for _, validGroup := range v.Config.TargetDescription.GroupMemberships {
					if group == validGroup {
						return nil
					}
				}
			}
		}
	}

	return ErrACTargetMismatch
}

// checkValidityPeriod checks the AC validity period.
func (v *ACValidator) checkValidityPeriod(ac *AttributeCertificateV2) error {
	validationTime := v.Config.ValidationTime
	tolerance := v.Config.TimeTolerance

	notBefore := ac.ACInfo.AttrCertValidityPeriod.NotBeforeTime.Add(-tolerance)
	if validationTime.Before(notBefore) {
		return ErrACNotYetValid
	}

	notAfter := ac.ACInfo.AttrCertValidityPeriod.NotAfterTime.Add(tolerance)
	if validationTime.After(notAfter) {
		return ErrACExpired
	}

	return nil
}

// findAndValidateAA finds and validates the Attribute Authority certificate.
func (v *ACValidator) findAndValidateAA(ac *AttributeCertificateV2) (*x509.Certificate, *CertificationPath, error) {
	if v.Config.CertRegistry == nil {
		return nil, nil, errors.New("certificate registry required")
	}

	// Find candidate AA certificates
	candidates := v.findAACandidates(ac)
	if len(candidates) == 0 {
		return nil, nil, ErrACIssuerNotFound
	}

	// Try to validate each candidate
	pathBuilder := NewPathBuilder(v.Config.TrustManager, v.Config.CertRegistry)

	for _, candidate := range candidates {
		path, err := pathBuilder.BuildFirstPath(nil, candidate)
		if err != nil {
			continue
		}

		// Validate the path
		pkixConfig := NewPKIXValidationConfig(v.Config.TrustManager)
		pkixConfig.CertRegistry = v.Config.CertRegistry
		pkixConfig.ValidationTime = v.Config.ValidationTime
		pkixConfig.SkipRevocation = v.Config.SkipRevocation
		if v.Config.PKIXParams != nil {
			pkixConfig.PKIXParams = v.Config.PKIXParams
		}

		validator := NewPKIXPathValidator(pkixConfig)
		result, err := validator.ValidatePath(path)
		if err == nil && result.Valid {
			return candidate, path, nil
		}
	}

	return nil, nil, ErrACIssuerNotFound
}

// findAACandidates finds candidate AA certificates for an AC.
func (v *ACValidator) findAACandidates(ac *AttributeCertificateV2) []*x509.Certificate {
	var candidates []*x509.Certificate

	issuer := ac.ACInfo.Issuer

	// Check V2Form first (preferred)
	if issuer.V2Form != nil {
		if issuer.V2Form.IssuerName != nil {
			for _, gn := range issuer.V2Form.IssuerName {
				if gn.GetType() == GeneralNameDirectoryName {
					certs := v.findByName(gn.Raw.Bytes)
					candidates = append(candidates, certs...)
				}
			}
		}
	}

	// Check V1Form
	if len(issuer.V1Form) > 0 {
		for _, gn := range issuer.V1Form {
			if gn.GetType() == GeneralNameDirectoryName {
				certs := v.findByName(gn.Raw.Bytes)
				candidates = append(candidates, certs...)
			}
		}
	}

	// Filter by AKI if present
	aki := getACAuthorityKeyID(ac)
	if aki != nil {
		var filtered []*x509.Certificate
		for _, cert := range candidates {
			if bytes.Equal(cert.SubjectKeyId, aki) {
				filtered = append(filtered, cert)
			}
		}
		if len(filtered) > 0 {
			candidates = filtered
		}
	}

	return candidates
}

// findByName finds certificates by subject name.
func (v *ACValidator) findByName(nameBytes []byte) []*x509.Certificate {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(nameBytes, &rdn); err != nil {
		return nil
	}

	name := pkix.Name{}
	name.FillFromRDNSequence(&rdn)

	return v.Config.CertRegistry.RetrieveByName(name)
}

// getACAuthorityKeyID extracts the authority key identifier from an AC.
func getACAuthorityKeyID(ac *AttributeCertificateV2) []byte {
	for _, ext := range ac.ACInfo.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) { // authorityKeyIdentifier
			var aki struct {
				KeyIdentifier []byte `asn1:"optional,tag:0"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &aki); err == nil {
				return aki.KeyIdentifier
			}
		}
	}
	return nil
}

// verifyACSignature verifies the AC signature using the AA certificate.
func (v *ACValidator) verifyACSignature(ac *AttributeCertificateV2, aaCert *x509.Certificate) error {
	// Encode the ACInfo for signature verification
	acInfoBytes, err := asn1.Marshal(ac.ACInfo)
	if err != nil {
		return fmt.Errorf("failed to encode ACInfo: %w", err)
	}

	// Create signature algorithm
	sigAlgorithm := x509SignatureToSignedDigest(aaCert.SignatureAlgorithm)
	hashAlgo := getHashFromSignatureAlgorithm(aaCert.SignatureAlgorithm)

	context := &SignatureValidationContext{
		ContextualMDAlgorithm: hashAlgo,
	}

	validator := NewDefaultSignatureValidator()
	return validator.ValidateSignature(
		ac.SignatureValue.Bytes,
		acInfoBytes,
		aaCert.PublicKey,
		sigAlgorithm,
		context,
	)
}

// hasACNoRevAvail checks if the AC has the no_rev_avail extension.
func hasACNoRevAvail(ac *AttributeCertificateV2) bool {
	for _, ext := range ac.ACInfo.Extensions {
		if ext.Id.Equal(OIDNoRevAvail) {
			return true
		}
	}
	return false
}

// checkACRevocation checks AC revocation status.
func (v *ACValidator) checkACRevocation(ac *AttributeCertificateV2, aaCert *x509.Certificate) error {
	// TODO: Implement full CRL/OCSP revocation checking for ACs
	// For now, this is a placeholder
	return nil
}

// isAttributeApproved checks if an attribute is approved based on AA controls.
func (v *ACValidator) isAttributeApproved(attrType asn1.ObjectIdentifier, aaPath *CertificationPath) bool {
	// Check AA controls in the path
	for _, cert := range aaPath.Certificates {
		controls, err := ReadAAControlsExtension(cert)
		if err != nil || controls == nil {
			continue
		}
		if !controls.Accept(attrType) {
			return false
		}
	}
	return true
}

// GetACExtensionValue retrieves an extension value from an AC.
func GetACExtensionValue(ac *AttributeCertificateV2, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, ext := range ac.ACInfo.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, true
		}
	}
	return nil, false
}

// GetACIssuerDN returns the issuer DN from an AC.
func GetACIssuerDN(ac *AttributeCertificateV2) (pkix.Name, error) {
	issuer := ac.ACInfo.Issuer

	// Check V2Form first
	if issuer.V2Form != nil && len(issuer.V2Form.IssuerName) > 0 {
		for _, gn := range issuer.V2Form.IssuerName {
			if gn.GetType() == GeneralNameDirectoryName {
				var rdn pkix.RDNSequence
				if _, err := asn1.Unmarshal(gn.Raw.Bytes, &rdn); err != nil {
					return pkix.Name{}, err
				}
				var name pkix.Name
				name.FillFromRDNSequence(&rdn)
				return name, nil
			}
		}
	}

	// Check V1Form
	for _, gn := range issuer.V1Form {
		if gn.GetType() == GeneralNameDirectoryName {
			var rdn pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Raw.Bytes, &rdn); err != nil {
				return pkix.Name{}, err
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			return name, nil
		}
	}

	return pkix.Name{}, errors.New("no issuer DN found")
}

// GetACSerialNumber returns the serial number from an AC.
func GetACSerialNumber(ac *AttributeCertificateV2) *big.Int {
	return ac.ACInfo.SerialNumber
}
