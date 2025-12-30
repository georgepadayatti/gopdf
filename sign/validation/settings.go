// Package validation provides PDF signature validation settings.
package validation

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// OID for Document Signing EKU per RFC 9336
// id-kp-documentSigning OBJECT IDENTIFIER ::= { id-kp 36 }
// where id-kp is 1.3.6.1.5.5.7.3
var OIDExtKeyUsageDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

// KeyUsage represents a key usage bit.
type KeyUsage string

// Key usage constants matching x509.KeyUsage bits.
const (
	KeyUsageDigitalSignature  KeyUsage = "digital_signature"
	KeyUsageContentCommitment KeyUsage = "content_commitment" // aka non_repudiation
	KeyUsageKeyEncipherment   KeyUsage = "key_encipherment"
	KeyUsageDataEncipherment  KeyUsage = "data_encipherment"
	KeyUsageKeyAgreement      KeyUsage = "key_agreement"
	KeyUsageKeyCertSign       KeyUsage = "key_cert_sign"
	KeyUsageCRLSign           KeyUsage = "crl_sign"
	KeyUsageEncipherOnly      KeyUsage = "encipher_only"
	KeyUsageDecipherOnly      KeyUsage = "decipher_only"
)

// ExtKeyUsage represents an extended key usage OID.
type ExtKeyUsage string

// Extended key usage constants.
const (
	ExtKeyUsageAny                            ExtKeyUsage = "any_extended_key_usage"
	ExtKeyUsageServerAuth                     ExtKeyUsage = "server_auth"
	ExtKeyUsageClientAuth                     ExtKeyUsage = "client_auth"
	ExtKeyUsageCodeSigning                    ExtKeyUsage = "code_signing"
	ExtKeyUsageEmailProtection                ExtKeyUsage = "email_protection"
	ExtKeyUsageIPSECEndSystem                 ExtKeyUsage = "ipsec_end_system"
	ExtKeyUsageIPSECTunnel                    ExtKeyUsage = "ipsec_tunnel"
	ExtKeyUsageIPSECUser                      ExtKeyUsage = "ipsec_user"
	ExtKeyUsageTimeStamping                   ExtKeyUsage = "time_stamping"
	ExtKeyUsageOCSPSigning                    ExtKeyUsage = "ocsp_signing"
	ExtKeyUsageMicrosoftServerGatedCrypto     ExtKeyUsage = "microsoft_server_gated_crypto"
	ExtKeyUsageNetscapeServerGatedCrypto      ExtKeyUsage = "netscape_server_gated_crypto"
	ExtKeyUsageMicrosoftCommercialCodeSigning ExtKeyUsage = "microsoft_commercial_code_signing"
	ExtKeyUsageMicrosoftKernelCodeSigning     ExtKeyUsage = "microsoft_kernel_code_signing"
	// ExtKeyUsageDocumentSigning is the Document Signing EKU per RFC 9336.
	// OID: 1.3.6.1.5.5.7.3.36
	ExtKeyUsageDocumentSigning ExtKeyUsage = "document_signing"
)

// KeyUsageValidationError is returned when key usage validation fails.
type KeyUsageValidationError struct {
	Message string
}

func (e *KeyUsageValidationError) Error() string {
	return e.Message
}

// KeyUsageConstraints validates key usage requirements.
// This is flexible enough to handle both PKIX and ISO 32000 certificate
// seed value constraint semantics.
type KeyUsageConstraints struct {
	// KeyUsage specifies required key usage extensions.
	// All or some (depending on MatchAllKeyUsages) of these must be present.
	// If nil or empty, all key usages are considered acceptable.
	KeyUsage []KeyUsage

	// KeyUsageForbidden specifies forbidden key usages.
	// These key usages must not be present in the signer's certificate.
	// Note: This behaviour is undefined in RFC 5280 (PKIX), but included
	// for compatibility with certificate seed value settings in ISO 32000.
	KeyUsageForbidden []KeyUsage

	// ExtdKeyUsage specifies acceptable extended key usages.
	// If nil, all extended key usages are considered acceptable.
	// If the anyExtendedKeyUsage purpose is present, behavior depends
	// on ExplicitExtdKeyUsageRequired.
	// Setting this to an empty slice effectively bans all extended key usages.
	ExtdKeyUsage []ExtKeyUsage

	// ExplicitExtdKeyUsageRequired requires an extended key usage extension
	// with the right key usages to be present if ExtdKeyUsage is non-empty.
	// If true, at least one key purpose in ExtdKeyUsage must appear in the
	// certificate's extended key usage, and anyExtendedKeyUsage will be ignored.
	ExplicitExtdKeyUsageRequired bool

	// MatchAllKeyUsages requires all key usages in KeyUsage to be present.
	// If false, one match suffices.
	MatchAllKeyUsages bool
}

// NewKeyUsageConstraints creates a new KeyUsageConstraints with defaults.
func NewKeyUsageConstraints() *KeyUsageConstraints {
	return &KeyUsageConstraints{
		ExplicitExtdKeyUsageRequired: true,
		MatchAllKeyUsages:            false,
	}
}

// SigningConstraints returns key usage constraints suitable for document signing.
func SigningConstraints() *KeyUsageConstraints {
	return &KeyUsageConstraints{
		KeyUsage:                     []KeyUsage{KeyUsageDigitalSignature, KeyUsageContentCommitment},
		MatchAllKeyUsages:            false,
		ExplicitExtdKeyUsageRequired: false,
	}
}

// DocumentSigningConstraints returns key usage constraints per RFC 9336 for document signing.
// This requires Digital Signature key usage and prefers Document Signing EKU (1.3.6.1.5.5.7.3.36),
// but also accepts Email Protection and Client Auth as fallback alternatives.
func DocumentSigningConstraints() *KeyUsageConstraints {
	return &KeyUsageConstraints{
		KeyUsage:          []KeyUsage{KeyUsageDigitalSignature},
		MatchAllKeyUsages: true,
		ExtdKeyUsage: []ExtKeyUsage{
			ExtKeyUsageDocumentSigning, // Primary: RFC 9336 Document Signing
			ExtKeyUsageEmailProtection, // Fallback: commonly used for S/MIME
			ExtKeyUsageClientAuth,      // Fallback: sometimes used in practice
		},
		ExplicitExtdKeyUsageRequired: false, // Allow certs without EKU extension
	}
}

// StrictDocumentSigningConstraints returns strict RFC 9336 constraints requiring Document Signing EKU.
// Use this for maximum security when you need to ensure the certificate is specifically
// issued for document signing purposes.
func StrictDocumentSigningConstraints() *KeyUsageConstraints {
	return &KeyUsageConstraints{
		KeyUsage:          []KeyUsage{KeyUsageDigitalSignature},
		MatchAllKeyUsages: true,
		ExtdKeyUsage: []ExtKeyUsage{
			ExtKeyUsageDocumentSigning, // Only accept Document Signing EKU
		},
		ExplicitExtdKeyUsageRequired: true, // Require EKU extension
	}
}

// NonRepudiationDocumentSigningConstraints returns constraints requiring both
// Digital Signature and Non-Repudiation (Content Commitment) key usages.
// This provides the highest level of assurance for legally binding signatures.
func NonRepudiationDocumentSigningConstraints() *KeyUsageConstraints {
	return &KeyUsageConstraints{
		KeyUsage: []KeyUsage{
			KeyUsageDigitalSignature,
			KeyUsageContentCommitment, // Non-Repudiation
		},
		MatchAllKeyUsages: true, // Require both
		ExtdKeyUsage: []ExtKeyUsage{
			ExtKeyUsageDocumentSigning,
			ExtKeyUsageEmailProtection,
			ExtKeyUsageClientAuth,
		},
		ExplicitExtdKeyUsageRequired: false,
	}
}

// Validate validates a certificate against the key usage constraints.
func (c *KeyUsageConstraints) Validate(cert *x509.Certificate) error {
	return c.ValidateWithExtra(cert, nil, nil)
}

// ValidateWithExtra validates a certificate with extra asserted usages.
func (c *KeyUsageConstraints) ValidateWithExtra(
	cert *x509.Certificate,
	extraKeyUsages []KeyUsage,
	extraExtdKeyUsages []ExtKeyUsage,
) error {
	// Validate key usage extension
	if err := c.validateKeyUsageExtension(cert, extraKeyUsages); err != nil {
		return err
	}

	// Validate extended key usage extension
	if err := c.validateExtdKeyUsageExtension(cert, extraExtdKeyUsages); err != nil {
		return err
	}

	return nil
}

// validateKeyUsageExtension validates the regular key usage extension.
func (c *KeyUsageConstraints) validateKeyUsageExtension(
	cert *x509.Certificate,
	extra []KeyUsage,
) error {
	// Extract key usages from certificate
	certKU := extractKeyUsages(cert.KeyUsage)

	// Add extra asserted key usages
	allKU := make(map[KeyUsage]bool)
	for _, ku := range certKU {
		allKU[ku] = true
	}
	for _, ku := range extra {
		allKU[ku] = true
	}

	return c.ValidateAssertedKeyUsage(allKU)
}

// ValidateAssertedKeyUsage validates asserted key usages against constraints.
func (c *KeyUsageConstraints) ValidateAssertedKeyUsage(asserted map[KeyUsage]bool) error {
	if len(c.KeyUsage) == 0 {
		return nil
	}

	// Check blacklisted key usages (ISO 32k)
	forbidden := make(map[KeyUsage]bool)
	for _, ku := range c.KeyUsageForbidden {
		forbidden[ku] = true
	}

	var forbiddenPresent []string
	for ku := range asserted {
		if forbidden[ku] {
			forbiddenPresent = append(forbiddenPresent, formatKeyUsage(ku))
		}
	}

	if len(forbiddenPresent) > 0 {
		return &KeyUsageValidationError{
			Message: fmt.Sprintf(
				"The active key usage policy explicitly bans certificates used for %s.",
				strings.Join(forbiddenPresent, ", "),
			),
		}
	}

	// Check required key usage extension values
	required := make(map[KeyUsage]bool)
	for _, ku := range c.KeyUsage {
		required[ku] = true
	}

	if !matchUsages(required, asserted, c.MatchAllKeyUsages) {
		var requiredList []string
		for ku := range required {
			requiredList = append(requiredList, formatKeyUsage(ku))
		}

		qualifier := "at least one of "
		if c.MatchAllKeyUsages {
			qualifier = ""
		}

		return &KeyUsageValidationError{
			Message: fmt.Sprintf(
				"The active key usage policy requires %sthe key usage extensions %s to be present.",
				qualifier,
				strings.Join(requiredList, ", "),
			),
		}
	}

	return nil
}

// validateExtdKeyUsageExtension validates the extended key usage extension.
func (c *KeyUsageConstraints) validateExtdKeyUsageExtension(
	cert *x509.Certificate,
	extra []ExtKeyUsage,
) error {
	// Extract extended key usages from certificate
	certEKU := extractExtKeyUsages(cert.ExtKeyUsage, cert.UnknownExtKeyUsage)

	// Add extra asserted extended key usages
	allEKU := make(map[ExtKeyUsage]bool)
	for _, eku := range certEKU {
		allEKU[eku] = true
	}
	for _, eku := range extra {
		allEKU[eku] = true
	}

	return c.ValidateAssertedExtendedKeyUsage(allEKU)
}

// ValidateAssertedExtendedKeyUsage validates asserted extended key usages.
func (c *KeyUsageConstraints) ValidateAssertedExtendedKeyUsage(asserted map[ExtKeyUsage]bool) error {
	if c.ExtdKeyUsage == nil {
		return nil
	}

	// No EKU extension present
	if len(asserted) == 0 {
		if c.ExplicitExtdKeyUsageRequired && len(c.ExtdKeyUsage) > 0 {
			return &KeyUsageValidationError{
				Message: "The active key usage policy requires an extended key usage extension.",
			}
		}
		return nil // cert is presumably valid for all EKUs
	}

	// Check for anyExtendedKeyUsage
	if asserted[ExtKeyUsageAny] && !c.ExplicitExtdKeyUsageRequired {
		return nil // cert is valid for all EKUs
	}

	// Check required extended key usages
	required := make(map[ExtKeyUsage]bool)
	for _, eku := range c.ExtdKeyUsage {
		required[eku] = true
	}

	if !matchExtUsages(required, asserted) {
		var okList string
		if len(c.ExtdKeyUsage) > 0 {
			var ekuList []string
			for eku := range required {
				ekuList = append(ekuList, formatExtKeyUsage(eku))
			}
			okList = fmt.Sprintf("Relevant key purposes are %s.", strings.Join(ekuList, ", "))
		} else {
			okList = "There are no acceptable extended key usages."
		}

		return &KeyUsageValidationError{
			Message: fmt.Sprintf(
				"The extended key usages for which this certificate is valid do not match the active key usage policy. %s",
				okList,
			),
		}
	}

	return nil
}

// matchUsages checks if required usages match present usages.
func matchUsages(required, present map[KeyUsage]bool, needAll bool) bool {
	if needAll {
		// All required must be present
		for ku := range required {
			if !present[ku] {
				return false
			}
		}
		return true
	}

	// At least one intersection
	for ku := range required {
		if present[ku] {
			return true
		}
	}
	return false
}

// matchExtUsages checks if at least one required EKU matches present EKUs.
func matchExtUsages(required, present map[ExtKeyUsage]bool) bool {
	for eku := range required {
		if present[eku] {
			return true
		}
	}
	return len(required) == 0
}

// extractKeyUsages extracts key usages from x509.KeyUsage bitmask.
func extractKeyUsages(ku x509.KeyUsage) []KeyUsage {
	var usages []KeyUsage

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, KeyUsageDigitalSignature)
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, KeyUsageContentCommitment)
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, KeyUsageKeyEncipherment)
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, KeyUsageDataEncipherment)
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, KeyUsageKeyAgreement)
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, KeyUsageKeyCertSign)
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, KeyUsageCRLSign)
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, KeyUsageEncipherOnly)
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, KeyUsageDecipherOnly)
	}

	return usages
}

// extractExtKeyUsages extracts extended key usages from certificate.
func extractExtKeyUsages(ekus []x509.ExtKeyUsage, unknownEKUs []asn1.ObjectIdentifier) []ExtKeyUsage {
	var usages []ExtKeyUsage

	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, ExtKeyUsageAny)
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, ExtKeyUsageServerAuth)
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, ExtKeyUsageClientAuth)
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, ExtKeyUsageCodeSigning)
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, ExtKeyUsageEmailProtection)
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, ExtKeyUsageIPSECEndSystem)
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, ExtKeyUsageIPSECTunnel)
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, ExtKeyUsageIPSECUser)
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, ExtKeyUsageTimeStamping)
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, ExtKeyUsageOCSPSigning)
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, ExtKeyUsageMicrosoftServerGatedCrypto)
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, ExtKeyUsageNetscapeServerGatedCrypto)
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			usages = append(usages, ExtKeyUsageMicrosoftCommercialCodeSigning)
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			usages = append(usages, ExtKeyUsageMicrosoftKernelCodeSigning)
		}
	}

	// Check for Document Signing EKU (RFC 9336) in UnknownExtKeyUsage
	// Go's x509 package doesn't have a built-in constant for this OID
	for _, oid := range unknownEKUs {
		if oid.Equal(OIDExtKeyUsageDocumentSigning) {
			usages = append(usages, ExtKeyUsageDocumentSigning)
		}
	}

	return usages
}

// formatKeyUsage formats a key usage for display.
func formatKeyUsage(ku KeyUsage) string {
	return strings.ReplaceAll(string(ku), "_", " ")
}

// formatExtKeyUsage formats an extended key usage for display.
func formatExtKeyUsage(eku ExtKeyUsage) string {
	return strings.ReplaceAll(string(eku), "_", " ")
}

// KeyUsageToX509 converts our KeyUsage to x509.KeyUsage bitmask.
func KeyUsageToX509(usages []KeyUsage) x509.KeyUsage {
	var ku x509.KeyUsage

	for _, usage := range usages {
		switch usage {
		case KeyUsageDigitalSignature:
			ku |= x509.KeyUsageDigitalSignature
		case KeyUsageContentCommitment:
			ku |= x509.KeyUsageContentCommitment
		case KeyUsageKeyEncipherment:
			ku |= x509.KeyUsageKeyEncipherment
		case KeyUsageDataEncipherment:
			ku |= x509.KeyUsageDataEncipherment
		case KeyUsageKeyAgreement:
			ku |= x509.KeyUsageKeyAgreement
		case KeyUsageKeyCertSign:
			ku |= x509.KeyUsageCertSign
		case KeyUsageCRLSign:
			ku |= x509.KeyUsageCRLSign
		case KeyUsageEncipherOnly:
			ku |= x509.KeyUsageEncipherOnly
		case KeyUsageDecipherOnly:
			ku |= x509.KeyUsageDecipherOnly
		}
	}

	return ku
}

// ExtKeyUsageToX509 converts our ExtKeyUsage to x509.ExtKeyUsage slice.
func ExtKeyUsageToX509(usages []ExtKeyUsage) []x509.ExtKeyUsage {
	var ekus []x509.ExtKeyUsage

	for _, usage := range usages {
		switch usage {
		case ExtKeyUsageAny:
			ekus = append(ekus, x509.ExtKeyUsageAny)
		case ExtKeyUsageServerAuth:
			ekus = append(ekus, x509.ExtKeyUsageServerAuth)
		case ExtKeyUsageClientAuth:
			ekus = append(ekus, x509.ExtKeyUsageClientAuth)
		case ExtKeyUsageCodeSigning:
			ekus = append(ekus, x509.ExtKeyUsageCodeSigning)
		case ExtKeyUsageEmailProtection:
			ekus = append(ekus, x509.ExtKeyUsageEmailProtection)
		case ExtKeyUsageIPSECEndSystem:
			ekus = append(ekus, x509.ExtKeyUsageIPSECEndSystem)
		case ExtKeyUsageIPSECTunnel:
			ekus = append(ekus, x509.ExtKeyUsageIPSECTunnel)
		case ExtKeyUsageIPSECUser:
			ekus = append(ekus, x509.ExtKeyUsageIPSECUser)
		case ExtKeyUsageTimeStamping:
			ekus = append(ekus, x509.ExtKeyUsageTimeStamping)
		case ExtKeyUsageOCSPSigning:
			ekus = append(ekus, x509.ExtKeyUsageOCSPSigning)
		case ExtKeyUsageMicrosoftServerGatedCrypto:
			ekus = append(ekus, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case ExtKeyUsageNetscapeServerGatedCrypto:
			ekus = append(ekus, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		case ExtKeyUsageMicrosoftCommercialCodeSigning:
			ekus = append(ekus, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
		case ExtKeyUsageMicrosoftKernelCodeSigning:
			ekus = append(ekus, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
		}
	}

	return ekus
}

// ParseKeyUsage parses a string to KeyUsage.
func ParseKeyUsage(s string) (KeyUsage, error) {
	normalized := strings.ToLower(strings.ReplaceAll(s, "-", "_"))
	normalized = strings.ReplaceAll(normalized, " ", "_")

	switch normalized {
	case "digital_signature", "digitalsignature":
		return KeyUsageDigitalSignature, nil
	case "content_commitment", "contentcommitment", "non_repudiation", "nonrepudiation":
		return KeyUsageContentCommitment, nil
	case "key_encipherment", "keyencipherment":
		return KeyUsageKeyEncipherment, nil
	case "data_encipherment", "dataencipherment":
		return KeyUsageDataEncipherment, nil
	case "key_agreement", "keyagreement":
		return KeyUsageKeyAgreement, nil
	case "key_cert_sign", "keycertsign":
		return KeyUsageKeyCertSign, nil
	case "crl_sign", "crlsign":
		return KeyUsageCRLSign, nil
	case "encipher_only", "encipheronly":
		return KeyUsageEncipherOnly, nil
	case "decipher_only", "decipheronly":
		return KeyUsageDecipherOnly, nil
	default:
		return "", fmt.Errorf("unknown key usage: %s", s)
	}
}

// ParseExtKeyUsage parses a string to ExtKeyUsage.
func ParseExtKeyUsage(s string) (ExtKeyUsage, error) {
	normalized := strings.ToLower(strings.ReplaceAll(s, "-", "_"))
	normalized = strings.ReplaceAll(normalized, " ", "_")

	switch normalized {
	case "any_extended_key_usage", "anyextendedkeyusage", "any":
		return ExtKeyUsageAny, nil
	case "server_auth", "serverauth":
		return ExtKeyUsageServerAuth, nil
	case "client_auth", "clientauth":
		return ExtKeyUsageClientAuth, nil
	case "code_signing", "codesigning":
		return ExtKeyUsageCodeSigning, nil
	case "email_protection", "emailprotection":
		return ExtKeyUsageEmailProtection, nil
	case "ipsec_end_system", "ipsecendsystem":
		return ExtKeyUsageIPSECEndSystem, nil
	case "ipsec_tunnel", "ipsectunnel":
		return ExtKeyUsageIPSECTunnel, nil
	case "ipsec_user", "ipsecuser":
		return ExtKeyUsageIPSECUser, nil
	case "time_stamping", "timestamping":
		return ExtKeyUsageTimeStamping, nil
	case "ocsp_signing", "ocspsigning":
		return ExtKeyUsageOCSPSigning, nil
	case "document_signing", "documentsigning":
		return ExtKeyUsageDocumentSigning, nil
	default:
		return "", fmt.Errorf("unknown extended key usage: %s", s)
	}
}

// ValidateCertificateKeyUsage is a convenience function to validate a certificate's key usages.
func ValidateCertificateKeyUsage(cert *x509.Certificate, requiredKeyUsages []KeyUsage) error {
	constraints := &KeyUsageConstraints{
		KeyUsage:          requiredKeyUsages,
		MatchAllKeyUsages: false,
	}
	return constraints.Validate(cert)
}

// ValidateCertificateExtKeyUsage validates a certificate's extended key usages.
func ValidateCertificateExtKeyUsage(cert *x509.Certificate, requiredExtKeyUsages []ExtKeyUsage) error {
	constraints := &KeyUsageConstraints{
		ExtdKeyUsage:                 requiredExtKeyUsages,
		ExplicitExtdKeyUsageRequired: true,
	}
	return constraints.Validate(cert)
}

// IsKeyUsageValidationError checks if an error is a KeyUsageValidationError.
func IsKeyUsageValidationError(err error) bool {
	var kuErr *KeyUsageValidationError
	return errors.As(err, &kuErr)
}

// KeyUsageValidationResult contains detailed validation results for key usage checks.
type KeyUsageValidationResult struct {
	// KeyUsageValid indicates if key usage requirements are satisfied
	KeyUsageValid bool
	// KeyUsageError contains the error message if key usage validation failed
	KeyUsageError string
	// ExtKeyUsageValid indicates if extended key usage requirements are satisfied
	ExtKeyUsageValid bool
	// ExtKeyUsageError contains the error message if EKU validation failed
	ExtKeyUsageError string
	// HasDocumentSigningEKU indicates if the certificate has the RFC 9336 Document Signing EKU
	HasDocumentSigningEKU bool
	// HasDigitalSignature indicates if the certificate has Digital Signature key usage
	HasDigitalSignature bool
	// HasNonRepudiation indicates if the certificate has Non-Repudiation (Content Commitment) key usage
	HasNonRepudiation bool
	// ExtKeyUsages lists all extended key usages found in the certificate
	ExtKeyUsages []ExtKeyUsage
}

// ValidateKeyUsageDetailed performs detailed key usage validation and returns comprehensive results.
// This is useful for generating detailed validation reports.
func ValidateKeyUsageDetailed(cert *x509.Certificate, constraints *KeyUsageConstraints) *KeyUsageValidationResult {
	result := &KeyUsageValidationResult{
		KeyUsageValid:    true,
		ExtKeyUsageValid: true,
	}

	// Check for Digital Signature key usage
	result.HasDigitalSignature = (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0

	// Check for Non-Repudiation (Content Commitment) key usage
	result.HasNonRepudiation = (cert.KeyUsage & x509.KeyUsageContentCommitment) != 0

	// Extract all extended key usages
	result.ExtKeyUsages = extractExtKeyUsages(cert.ExtKeyUsage, cert.UnknownExtKeyUsage)

	// Check for Document Signing EKU
	for _, eku := range result.ExtKeyUsages {
		if eku == ExtKeyUsageDocumentSigning {
			result.HasDocumentSigningEKU = true
			break
		}
	}

	// Validate against constraints if provided
	if constraints != nil {
		if err := constraints.Validate(cert); err != nil {
			var kuErr *KeyUsageValidationError
			if errors.As(err, &kuErr) {
				msg := kuErr.Message
				// Determine if it's a key usage or extended key usage error
				if strings.Contains(msg, "extended key usage") || strings.Contains(msg, "key purpose") {
					result.ExtKeyUsageValid = false
					result.ExtKeyUsageError = msg
				} else {
					result.KeyUsageValid = false
					result.KeyUsageError = msg
				}
			}
		}
	}

	return result
}

// HasDocumentSigningEKU checks if a certificate has the RFC 9336 Document Signing EKU.
func HasDocumentSigningEKU(cert *x509.Certificate) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDExtKeyUsageDocumentSigning) {
			return true
		}
	}
	return false
}

// HasDigitalSignatureKeyUsage checks if a certificate has the Digital Signature key usage bit set.
func HasDigitalSignatureKeyUsage(cert *x509.Certificate) bool {
	return (cert.KeyUsage & x509.KeyUsageDigitalSignature) != 0
}

// HasNonRepudiationKeyUsage checks if a certificate has the Non-Repudiation (Content Commitment) key usage bit set.
func HasNonRepudiationKeyUsage(cert *x509.Certificate) bool {
	return (cert.KeyUsage & x509.KeyUsageContentCommitment) != 0
}

// ValidateDocumentSigningCertificate validates a certificate for document signing per RFC 9336.
// Returns nil if the certificate is valid for document signing, or an error describing why not.
func ValidateDocumentSigningCertificate(cert *x509.Certificate) error {
	return DocumentSigningConstraints().Validate(cert)
}

// ValidateDocumentSigningCertificateStrict validates a certificate strictly per RFC 9336,
// requiring the Document Signing EKU to be present.
func ValidateDocumentSigningCertificateStrict(cert *x509.Certificate) error {
	return StrictDocumentSigningConstraints().Validate(cert)
}

// KeyUsageConstraintsBuilder provides a fluent interface for building constraints.
type KeyUsageConstraintsBuilder struct {
	constraints *KeyUsageConstraints
}

// NewKeyUsageConstraintsBuilder creates a new builder.
func NewKeyUsageConstraintsBuilder() *KeyUsageConstraintsBuilder {
	return &KeyUsageConstraintsBuilder{
		constraints: NewKeyUsageConstraints(),
	}
}

// RequireKeyUsage adds a required key usage.
func (b *KeyUsageConstraintsBuilder) RequireKeyUsage(ku KeyUsage) *KeyUsageConstraintsBuilder {
	b.constraints.KeyUsage = append(b.constraints.KeyUsage, ku)
	return b
}

// ForbidKeyUsage adds a forbidden key usage.
func (b *KeyUsageConstraintsBuilder) ForbidKeyUsage(ku KeyUsage) *KeyUsageConstraintsBuilder {
	b.constraints.KeyUsageForbidden = append(b.constraints.KeyUsageForbidden, ku)
	return b
}

// RequireExtKeyUsage adds a required extended key usage.
func (b *KeyUsageConstraintsBuilder) RequireExtKeyUsage(eku ExtKeyUsage) *KeyUsageConstraintsBuilder {
	if b.constraints.ExtdKeyUsage == nil {
		b.constraints.ExtdKeyUsage = []ExtKeyUsage{}
	}
	b.constraints.ExtdKeyUsage = append(b.constraints.ExtdKeyUsage, eku)
	return b
}

// MatchAll sets whether all key usages must match.
func (b *KeyUsageConstraintsBuilder) MatchAll(matchAll bool) *KeyUsageConstraintsBuilder {
	b.constraints.MatchAllKeyUsages = matchAll
	return b
}

// ExplicitExtKeyUsageRequired sets whether explicit EKU is required.
func (b *KeyUsageConstraintsBuilder) ExplicitExtKeyUsageRequired(required bool) *KeyUsageConstraintsBuilder {
	b.constraints.ExplicitExtdKeyUsageRequired = required
	return b
}

// Build returns the constructed KeyUsageConstraints.
func (b *KeyUsageConstraintsBuilder) Build() *KeyUsageConstraints {
	return b.constraints
}
