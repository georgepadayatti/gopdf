// Package attributes provides CMS attribute handling for PDF signatures.
package attributes

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// Common errors
var (
	ErrInvalidAttribute     = errors.New("invalid attribute")
	ErrMissingAttributeType = errors.New("missing attribute type")
	ErrAttributeNotFound    = errors.New("attribute not found")
)

// OID definitions for CMS attributes
var (
	// Standard CMS attributes
	OIDContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDCountersignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}

	// Signature timestamp (RFC 3161)
	OIDSignatureTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	// Signing certificate v2 (RFC 5035)
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	// CMS Algorithm Protection (RFC 6211)
	OIDCMSAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}

	// Adobe revocation information
	OIDAdobeRevocationInfoArchival = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}

	// Content types
	OIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// Hash algorithms
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// CMSAttribute represents a CMS attribute.
type CMSAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// CMSAttributes is a set of CMS attributes.
type CMSAttributes []CMSAttribute

// Get retrieves an attribute by OID.
func (attrs CMSAttributes) Get(oid asn1.ObjectIdentifier) *CMSAttribute {
	for i := range attrs {
		if attrs[i].Type.Equal(oid) {
			return &attrs[i]
		}
	}
	return nil
}

// Has checks if an attribute with the given OID exists.
func (attrs CMSAttributes) Has(oid asn1.ObjectIdentifier) bool {
	return attrs.Get(oid) != nil
}

// AlgorithmIdentifier represents a cryptographic algorithm.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// ESSCertIDv2 represents a certificate identifier (RFC 5035).
type ESSCertIDv2 struct {
	HashAlgorithm AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  IssuerSerial `asn1:"optional"`
}

// IssuerSerial represents issuer and serial number.
type IssuerSerial struct {
	Issuer       asn1.RawValue
	SerialNumber asn1.RawValue
}

// SigningCertificateV2 represents the signing-certificate-v2 attribute.
type SigningCertificateV2 struct {
	Certs    []ESSCertIDv2
	Policies []PolicyInformation `asn1:"optional"`
}

// PolicyInformation represents a certificate policy.
type PolicyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	PolicyQualifiers []PolicyQualifierInfo `asn1:"optional"`
}

// PolicyQualifierInfo represents a policy qualifier.
type PolicyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         asn1.RawValue `asn1:"optional"`
}

// CMSAlgorithmProtection represents the CMS algorithm protection attribute.
type CMSAlgorithmProtection struct {
	DigestAlgorithm    AlgorithmIdentifier
	SignatureAlgorithm AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	MacAlgorithm       AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// RevocationInfoArchival represents Adobe revocation information.
type RevocationInfoArchival struct {
	CRL          []asn1.RawValue `asn1:"optional,explicit,tag:0"`
	OCSP         []asn1.RawValue `asn1:"optional,explicit,tag:1"`
	OtherRevInfo []OtherRevInfo  `asn1:"optional,explicit,tag:2"`
}

// OtherRevInfo represents other revocation information.
type OtherRevInfo struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// ContentInfo represents CMS ContentInfo.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// AttributeProvider is an interface for providing CMS attributes.
type AttributeProvider interface {
	// AttributeType returns the OID of the attribute type.
	AttributeType() asn1.ObjectIdentifier

	// BuildAttributeValue builds the attribute value.
	BuildAttributeValue(dryRun bool) (interface{}, error)
}

// SigningCertificateV2Provider provides signing-certificate-v2 attributes.
type SigningCertificateV2Provider struct {
	SigningCert *x509.Certificate
}

// AttributeType returns the attribute type OID.
func (p *SigningCertificateV2Provider) AttributeType() asn1.ObjectIdentifier {
	return OIDSigningCertificateV2
}

// BuildAttributeValue builds the signing-certificate-v2 attribute value.
func (p *SigningCertificateV2Provider) BuildAttributeValue(dryRun bool) (interface{}, error) {
	return AsSigningCertificateV2(p.SigningCert), nil
}

// AsSigningCertificateV2 creates a SigningCertificateV2 from a certificate.
func AsSigningCertificateV2(cert *x509.Certificate) *SigningCertificateV2 {
	// Compute SHA-256 hash of the certificate
	hash := sha256.Sum256(cert.Raw)

	return &SigningCertificateV2{
		Certs: []ESSCertIDv2{
			{
				HashAlgorithm: AlgorithmIdentifier{
					Algorithm: OIDSHA256,
				},
				CertHash: hash[:],
			},
		},
	}
}

// SigningTimeProvider provides signing-time attributes.
type SigningTimeProvider struct {
	Timestamp time.Time
}

// AttributeType returns the attribute type OID.
func (p *SigningTimeProvider) AttributeType() asn1.ObjectIdentifier {
	return OIDSigningTime
}

// BuildAttributeValue builds the signing-time attribute value.
func (p *SigningTimeProvider) BuildAttributeValue(dryRun bool) (interface{}, error) {
	return p.Timestamp.UTC(), nil
}

// CMSAlgorithmProtectionProvider provides CMS algorithm protection attributes.
type CMSAlgorithmProtectionProvider struct {
	DigestAlgo    string
	SignatureAlgo AlgorithmIdentifier
}

// AttributeType returns the attribute type OID.
func (p *CMSAlgorithmProtectionProvider) AttributeType() asn1.ObjectIdentifier {
	return OIDCMSAlgorithmProtection
}

// BuildAttributeValue builds the CMS algorithm protection attribute value.
func (p *CMSAlgorithmProtectionProvider) BuildAttributeValue(dryRun bool) (interface{}, error) {
	digestAlgo := AlgorithmIdentifier{
		Algorithm: DigestAlgorithmOID(p.DigestAlgo),
	}

	return &CMSAlgorithmProtection{
		DigestAlgorithm:    digestAlgo,
		SignatureAlgorithm: p.SignatureAlgo,
	}, nil
}

// AdobeRevinfoProvider provides Adobe revocation information attributes.
type AdobeRevinfoProvider struct {
	Value *RevocationInfoArchival
}

// AttributeType returns the attribute type OID.
func (p *AdobeRevinfoProvider) AttributeType() asn1.ObjectIdentifier {
	return OIDAdobeRevocationInfoArchival
}

// BuildAttributeValue builds the Adobe revocation info attribute value.
func (p *AdobeRevinfoProvider) BuildAttributeValue(dryRun bool) (interface{}, error) {
	return p.Value, nil
}

// DigestAlgorithmOID returns the OID for a digest algorithm name.
func DigestAlgorithmOID(algo string) asn1.ObjectIdentifier {
	switch algo {
	case "sha256", "SHA256":
		return OIDSHA256
	case "sha384", "SHA384":
		return OIDSHA384
	case "sha512", "SHA512":
		return OIDSHA512
	default:
		return OIDSHA256 // Default to SHA-256
	}
}

// SimpleCMSAttribute creates a simple CMS attribute with a single value.
func SimpleCMSAttribute(attrType asn1.ObjectIdentifier, value interface{}) (*CMSAttribute, error) {
	// Handle pointer types by dereferencing
	var valueBytes []byte
	var err error

	switch v := value.(type) {
	case *SigningCertificateV2:
		valueBytes, err = asn1.Marshal(*v)
	case *CMSAlgorithmProtection:
		valueBytes, err = asn1.Marshal(*v)
	case *RevocationInfoArchival:
		valueBytes, err = asn1.Marshal(*v)
	default:
		valueBytes, err = asn1.Marshal(value)
	}

	if err != nil {
		return nil, err
	}

	// Wrap in SET
	setBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      valueBytes,
	})
	if err != nil {
		return nil, err
	}

	return &CMSAttribute{
		Type: attrType,
		Values: asn1.RawValue{
			FullBytes: setBytes,
		},
	}, nil
}

// SignedAttributeProviderSpec specifies signed attribute providers.
type SignedAttributeProviderSpec struct {
	Providers []AttributeProvider
}

// UnsignedAttributeProviderSpec specifies unsigned attribute providers.
type UnsignedAttributeProviderSpec struct {
	Providers []AttributeProvider
}

// BuildSignedAttributes builds signed attributes from providers.
func (s *SignedAttributeProviderSpec) BuildSignedAttributes(dataDigest []byte, digestAlgorithm string, dryRun bool) (CMSAttributes, error) {
	var attrs CMSAttributes

	for _, provider := range s.Providers {
		value, err := provider.BuildAttributeValue(dryRun)
		if err != nil {
			return nil, err
		}

		if value != nil {
			attr, err := SimpleCMSAttribute(provider.AttributeType(), value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, *attr)
		}
	}

	return attrs, nil
}

// NewRevocationInfoArchival creates a new RevocationInfoArchival from CRLs and OCSP responses.
func NewRevocationInfoArchival(crls [][]byte, ocsps [][]byte) *RevocationInfoArchival {
	ria := &RevocationInfoArchival{}

	for _, crl := range crls {
		ria.CRL = append(ria.CRL, asn1.RawValue{FullBytes: crl})
	}

	for _, ocsp := range ocsps {
		ria.OCSP = append(ria.OCSP, asn1.RawValue{FullBytes: ocsp})
	}

	return ria
}

// Marshal encodes the CMSAttribute to ASN.1 DER.
func (a *CMSAttribute) Marshal() ([]byte, error) {
	return asn1.Marshal(*a)
}

// Marshal encodes the SigningCertificateV2 to ASN.1 DER.
func (s *SigningCertificateV2) Marshal() ([]byte, error) {
	return asn1.Marshal(*s)
}

// Marshal encodes the CMSAlgorithmProtection to ASN.1 DER.
func (c *CMSAlgorithmProtection) Marshal() ([]byte, error) {
	return asn1.Marshal(*c)
}

// Marshal encodes the RevocationInfoArchival to ASN.1 DER.
func (r *RevocationInfoArchival) Marshal() ([]byte, error) {
	return asn1.Marshal(*r)
}
