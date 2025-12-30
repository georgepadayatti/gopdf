// Package certvalidator provides X.509 certificate path validation.
// This file contains custom ASN.1 type definitions for attribute certificates.
package certvalidator

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// OIDs for attribute certificate extensions
var (
	// OIDTargetInformation is the OID for target information extension (RFC 5755)
	OIDTargetInformation = asn1.ObjectIdentifier{2, 5, 29, 55}

	// OIDNoRevAvail is the OID for no revocation available extension
	OIDNoRevAvail = asn1.ObjectIdentifier{2, 5, 29, 56}

	// OIDAAControls is the OID for AA controls extension
	OIDAAControls = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 6}

	// OIDAuditIdentity is the OID for audit identity extension
	OIDAuditIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 4}
)

// IssuerSerial identifies a certificate by issuer and serial number.
type IssuerSerial struct {
	Issuer       asn1.RawValue
	SerialNumber asn1.RawValue
}

// ObjectDigestInfo contains digest information for an object.
type ObjectDigestInfo struct {
	DigestedObjectType asn1.Enumerated
	OtherObjectTypeID  asn1.ObjectIdentifier `asn1:"optional"`
	DigestAlgorithm    AlgorithmIdentifier
	ObjectDigest       asn1.BitString
}

// AlgorithmIdentifier identifies a cryptographic algorithm.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// ASN1GeneralName represents an X.509 general name in ASN.1 form.
// Note: GeneralNameType constants are defined in name_trees.go.
type ASN1GeneralName struct {
	Raw asn1.RawValue
}

// GetType returns the type of the general name.
// Uses the GeneralNameType constants defined in name_trees.go.
func (g *ASN1GeneralName) GetType() GeneralNameType {
	return GeneralNameType(g.Raw.Tag)
}

// TargetCert identifies a certificate as a target (RFC 5755).
type TargetCert struct {
	TargetCertificate IssuerSerial
	TargetName        ASN1GeneralName  `asn1:"optional,explicit,tag:0"`
	CertDigestInfo    ObjectDigestInfo `asn1:"optional,explicit,tag:1"`
}

// Target represents a target for attribute certificate verification (RFC 5755).
// It can be a target name, target group, or target cert.
type Target struct {
	TargetName  ASN1GeneralName `asn1:"optional,explicit,tag:0"`
	TargetGroup ASN1GeneralName `asn1:"optional,explicit,tag:1"`
	TargetCert  TargetCert      `asn1:"optional,explicit,tag:2"`
}

// TargetType represents the type of target.
type TargetType int

const (
	// TargetTypeName indicates a target name
	TargetTypeName TargetType = iota
	// TargetTypeGroup indicates a target group
	TargetTypeGroup
	// TargetTypeCert indicates a target certificate
	TargetTypeCert
	// TargetTypeUnknown indicates an unknown target type
	TargetTypeUnknown
)

// GetType returns the type of the target.
func (t *Target) GetType() TargetType {
	// Check which field is present based on ASN.1 tags
	if t.TargetName.Raw.FullBytes != nil {
		return TargetTypeName
	}
	if t.TargetGroup.Raw.FullBytes != nil {
		return TargetTypeGroup
	}
	if t.TargetCert.TargetCertificate.Issuer.FullBytes != nil {
		return TargetTypeCert
	}
	return TargetTypeUnknown
}

// Targets is a sequence of Target entries.
type Targets []Target

// SequenceOfTargets is a sequence of Targets (used in target_information extension).
type SequenceOfTargets []Targets

// AttrSpec specifies attribute types for AA controls.
type AttrSpec []asn1.ObjectIdentifier

// Contains checks if an attribute type is in the spec.
func (a AttrSpec) Contains(oid asn1.ObjectIdentifier) bool {
	for _, o := range a {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}

// AAControls represents the AA controls extension (RFC 5755).
// This extension constrains which attributes an attribute authority
// is permitted to issue.
type AAControls struct {
	PathLenConstraint int      `asn1:"optional"`
	PermittedAttrs    AttrSpec `asn1:"optional,implicit,tag:0"`
	ExcludedAttrs     AttrSpec `asn1:"optional,implicit,tag:1"`
	PermitUnspecified bool     `asn1:"default:true"`
}

// Accept checks if an attribute type is accepted by the AA controls.
func (a *AAControls) Accept(attrID asn1.ObjectIdentifier) bool {
	// Check if excluded
	if a.ExcludedAttrs != nil && a.ExcludedAttrs.Contains(attrID) {
		return false
	}

	// Check if explicitly permitted
	if a.PermittedAttrs != nil {
		if a.PermittedAttrs.Contains(attrID) {
			return true
		}
		// Not in permitted list - check permit_unspecified
		return a.PermitUnspecified
	}

	// No permitted list - use permit_unspecified
	return a.PermitUnspecified
}

// ParseAAControls parses AA controls from raw extension value.
func ParseAAControls(data []byte) (*AAControls, error) {
	var controls AAControls
	// Set default for PermitUnspecified
	controls.PermitUnspecified = true

	_, err := asn1.Unmarshal(data, &controls)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AA controls: %w", err)
	}

	return &controls, nil
}

// ReadAAControlsExtension reads the AA controls extension from a certificate.
func ReadAAControlsExtension(cert *x509.Certificate) (*AAControls, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAAControls) {
			return ParseAAControls(ext.Value)
		}
	}
	return nil, nil // Not present
}

// ParseTargetInformation parses target information from raw extension value.
func ParseTargetInformation(data []byte) (*SequenceOfTargets, error) {
	var targets SequenceOfTargets
	_, err := asn1.Unmarshal(data, &targets)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target information: %w", err)
	}
	return &targets, nil
}

// ReadTargetInformationExtension reads the target information extension from a certificate.
func ReadTargetInformationExtension(cert *x509.Certificate) (*SequenceOfTargets, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTargetInformation) {
			return ParseTargetInformation(ext.Value)
		}
	}
	return nil, nil // Not present
}

// HasNoRevAvail checks if a certificate has the no revocation available extension.
func HasNoRevAvail(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDNoRevAvail) {
			return true
		}
	}
	return false
}

// ParseAuditIdentity parses the audit identity extension value.
func ParseAuditIdentity(data []byte) ([]byte, error) {
	var identity asn1.RawValue
	_, err := asn1.Unmarshal(data, &identity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit identity: %w", err)
	}
	return identity.Bytes, nil
}

// ReadAuditIdentityExtension reads the audit identity extension from a certificate.
func ReadAuditIdentityExtension(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDAuditIdentity) {
			return ParseAuditIdentity(ext.Value)
		}
	}
	return nil, nil // Not present
}

// ExtensionRegistry provides lookup for extension OIDs.
type ExtensionRegistry struct {
	OIDMap map[string]string
}

// NewExtensionRegistry creates a new extension registry with default mappings.
func NewExtensionRegistry() *ExtensionRegistry {
	return &ExtensionRegistry{
		OIDMap: map[string]string{
			OIDTargetInformation.String(): "target_information",
			OIDNoRevAvail.String():        "no_rev_avail",
			OIDAAControls.String():        "aa_controls",
			OIDAuditIdentity.String():     "audit_identity",
		},
	}
}

// GetExtensionName returns the name for an extension OID.
func (r *ExtensionRegistry) GetExtensionName(oid asn1.ObjectIdentifier) string {
	if name, ok := r.OIDMap[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// RegisterExtension adds a custom extension to the registry.
func (r *ExtensionRegistry) RegisterExtension(oid asn1.ObjectIdentifier, name string) {
	r.OIDMap[oid.String()] = name
}

// DefaultExtensionRegistry is the default extension registry.
var DefaultExtensionRegistry = NewExtensionRegistry()
