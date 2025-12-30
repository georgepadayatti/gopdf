// Package certvalidator provides X.509 certificate path validation.
// This file contains authority and trust anchor representations.
package certvalidator

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"time"
)

// TrustedServiceType indicates the type of service provided by a trust anchor.
type TrustedServiceType int

const (
	// TrustedServiceUnspecified means the trust anchor is trusted for any purpose.
	TrustedServiceUnspecified TrustedServiceType = iota

	// TrustedServiceUnsupported means the trust anchor is not trusted for any
	// purpose other than identifying itself.
	TrustedServiceUnsupported

	// TrustedServiceCA indicates a certificate authority.
	// Only trust anchors with this designation can appear in a PKIX validation
	// path as the issuer of another certificate.
	TrustedServiceCA

	// TrustedServiceTSA indicates a time stamping authority.
	TrustedServiceTSA
)

// String returns the string representation of TrustedServiceType.
func (t TrustedServiceType) String() string {
	switch t {
	case TrustedServiceUnspecified:
		return "unspecified"
	case TrustedServiceUnsupported:
		return "unsupported"
	case TrustedServiceCA:
		return "certificate_authority"
	case TrustedServiceTSA:
		return "time_stamping_authority"
	default:
		return "unknown"
	}
}

// TrustQualifiers contains parameters that allow a trust root to be qualified.
type TrustQualifiers struct {
	// StandardParameters contains PKIX validation parameters that apply when
	// initializing the validation process.
	StandardParameters *PKIXValidationParams

	// MaxPathLength is the maximal allowed path length for this trust root,
	// excluding self-issued intermediate CA certificates.
	// A value of -1 means any path length is accepted.
	MaxPathLength int

	// MaxAAPathLength is the maximal allowed path length for AAControls.
	// A value of -1 means any path length is accepted.
	MaxAAPathLength int

	// ValidFrom is the lower bound of the trust anchor's validity period.
	ValidFrom *time.Time

	// ValidUntil is the upper bound of the trust anchor's validity period.
	ValidUntil *time.Time

	// TrustedServiceType indicates the service provided by the trust root.
	TrustedServiceType TrustedServiceType
}

// NewTrustQualifiers creates a new TrustQualifiers with default values.
func NewTrustQualifiers() *TrustQualifiers {
	return &TrustQualifiers{
		MaxPathLength:      -1,
		MaxAAPathLength:    -1,
		TrustedServiceType: TrustedServiceUnspecified,
	}
}

// IsValidAt checks if the trust qualifier is valid at the given time.
func (q *TrustQualifiers) IsValidAt(t time.Time) bool {
	if q.ValidFrom != nil && t.Before(*q.ValidFrom) {
		return false
	}
	if q.ValidUntil != nil && t.After(*q.ValidUntil) {
		return false
	}
	return true
}

// Authority represents an abstract authority (a named key).
type Authority interface {
	// Name returns the authority's name.
	Name() pkix.Name

	// PublicKey returns the authority's public key.
	PublicKey() crypto.PublicKey

	// KeyID returns the key identifier as potentially referenced in an
	// authorityKeyIdentifier extension.
	KeyID() []byte

	// Hashable returns a hashable unique identifier of the authority.
	Hashable() string

	// IsPotentialIssuerOf determines whether this authority could potentially
	// be an issuer of the given certificate.
	IsPotentialIssuerOf(cert *x509.Certificate) bool
}

// BaseAuthority provides common implementation for Authority interface.
type BaseAuthority struct {
	name      pkix.Name
	publicKey crypto.PublicKey
	keyID     []byte
}

// Name returns the authority's name.
func (a *BaseAuthority) Name() pkix.Name {
	return a.name
}

// PublicKey returns the authority's public key.
func (a *BaseAuthority) PublicKey() crypto.PublicKey {
	return a.publicKey
}

// KeyID returns the key identifier.
func (a *BaseAuthority) KeyID() []byte {
	return a.keyID
}

// Hashable returns a unique identifier for the authority.
func (a *BaseAuthority) Hashable() string {
	h := sha256.New()
	h.Write([]byte(a.name.String()))
	return string(h.Sum(nil))
}

// IsPotentialIssuerOf checks if this authority could be an issuer of the certificate.
func (a *BaseAuthority) IsPotentialIssuerOf(cert *x509.Certificate) bool {
	// Check authority key identifier if present
	if len(cert.AuthorityKeyId) > 0 && len(a.keyID) > 0 {
		if bytes.Equal(cert.AuthorityKeyId, a.keyID) {
			return true
		}
		return false
	}

	// Fallback to issuer name match
	return namesEqual(cert.Issuer, a.name)
}

// namesEqual compares two pkix.Name structures.
func namesEqual(a, b pkix.Name) bool {
	return strings.EqualFold(canonicalNameString(a), canonicalNameString(b))
}

// TrustAnchorImpl is a trust anchor implementation.
type TrustAnchorImpl struct {
	authority  Authority
	qualifiers *TrustQualifiers
}

// NewTrustAnchor creates a new trust anchor.
func NewTrustAnchor(authority Authority, quals *TrustQualifiers) *TrustAnchorImpl {
	return &TrustAnchorImpl{
		authority:  authority,
		qualifiers: quals,
	}
}

// Authority returns the underlying authority.
func (t *TrustAnchorImpl) Authority() Authority {
	return t.authority
}

// TrustQualifiers returns the trust qualifiers.
func (t *TrustAnchorImpl) TrustQualifiers() *TrustQualifiers {
	if t.qualifiers != nil {
		return t.qualifiers
	}
	return NewTrustQualifiers()
}

// Equals checks if two trust anchors are equal.
func (t *TrustAnchorImpl) Equals(other *TrustAnchorImpl) bool {
	if other == nil {
		return false
	}
	return t.authority.Hashable() == other.authority.Hashable()
}

// AuthorityWithCert is an authority provisioned from a certificate.
type AuthorityWithCert struct {
	cert *x509.Certificate
}

// NewAuthorityWithCert creates an authority from a certificate.
func NewAuthorityWithCert(cert *x509.Certificate) *AuthorityWithCert {
	return &AuthorityWithCert{cert: cert}
}

// Name returns the certificate's subject.
func (a *AuthorityWithCert) Name() pkix.Name {
	return a.cert.Subject
}

// PublicKey returns the certificate's public key.
func (a *AuthorityWithCert) PublicKey() crypto.PublicKey {
	return a.cert.PublicKey
}

// KeyID returns the subject key identifier.
func (a *AuthorityWithCert) KeyID() []byte {
	return a.cert.SubjectKeyId
}

// Hashable returns a unique identifier for the authority.
func (a *AuthorityWithCert) Hashable() string {
	h := sha256.New()
	h.Write([]byte(a.cert.Subject.String()))
	h.Write(a.cert.RawSubjectPublicKeyInfo)
	return string(h.Sum(nil))
}

// IsPotentialIssuerOf checks if this authority could be an issuer of the certificate.
func (a *AuthorityWithCert) IsPotentialIssuerOf(cert *x509.Certificate) bool {
	// Check issuer name
	if !namesEqual(cert.Issuer, a.cert.Subject) {
		return false
	}

	// Check authority key identifier
	if len(cert.AuthorityKeyId) > 0 && len(a.cert.SubjectKeyId) > 0 {
		if !bytes.Equal(cert.AuthorityKeyId, a.cert.SubjectKeyId) {
			return false
		}
	}

	return true
}

// Certificate returns the underlying certificate.
func (a *AuthorityWithCert) Certificate() *x509.Certificate {
	return a.cert
}

// CertTrustAnchor is a trust anchor provisioned as a certificate.
type CertTrustAnchor struct {
	*TrustAnchorImpl
	cert                       *x509.Certificate
	deriveDefaultQualsFromCert bool
	derivedQuals               *TrustQualifiers
}

// NewCertTrustAnchor creates a trust anchor from a certificate.
func NewCertTrustAnchor(cert *x509.Certificate, quals *TrustQualifiers, deriveDefaultQuals bool) *CertTrustAnchor {
	authority := NewAuthorityWithCert(cert)
	return &CertTrustAnchor{
		TrustAnchorImpl:            NewTrustAnchor(authority, quals),
		cert:                       cert,
		deriveDefaultQualsFromCert: deriveDefaultQuals,
	}
}

// Certificate returns the underlying certificate.
func (c *CertTrustAnchor) Certificate() *x509.Certificate {
	return c.cert
}

// TrustQualifiers returns the trust qualifiers, deriving from cert if needed.
func (c *CertTrustAnchor) TrustQualifiers() *TrustQualifiers {
	if c.qualifiers != nil {
		return c.qualifiers
	}
	if c.deriveDefaultQualsFromCert {
		if c.derivedQuals == nil {
			c.derivedQuals = DeriveQualsFromCert(c.cert)
		}
		return c.derivedQuals
	}
	return NewTrustQualifiers()
}

// NamedKeyAuthority is an authority provisioned as a named key.
type NamedKeyAuthority struct {
	name      pkix.Name
	publicKey crypto.PublicKey
}

// NewNamedKeyAuthority creates a new named key authority.
func NewNamedKeyAuthority(name pkix.Name, publicKey crypto.PublicKey) *NamedKeyAuthority {
	return &NamedKeyAuthority{
		name:      name,
		publicKey: publicKey,
	}
}

// Name returns the authority's name.
func (a *NamedKeyAuthority) Name() pkix.Name {
	return a.name
}

// PublicKey returns the authority's public key.
func (a *NamedKeyAuthority) PublicKey() crypto.PublicKey {
	return a.publicKey
}

// KeyID returns nil for named key authorities.
func (a *NamedKeyAuthority) KeyID() []byte {
	return nil
}

// Hashable returns a unique identifier for the authority.
func (a *NamedKeyAuthority) Hashable() string {
	h := sha256.New()
	h.Write([]byte(a.name.String()))
	// Note: Can't easily serialize public key without knowing type
	return string(h.Sum(nil))
}

// IsPotentialIssuerOf checks if this authority could be an issuer of the certificate.
func (a *NamedKeyAuthority) IsPotentialIssuerOf(cert *x509.Certificate) bool {
	return namesEqual(cert.Issuer, a.name)
}

// DeriveQualsFromCert extracts trust qualifiers from certificate data and extensions.
func DeriveQualsFromCert(cert *x509.Certificate) *TrustQualifiers {
	quals := NewTrustQualifiers()

	// Set validity period
	validFrom := cert.NotBefore
	validUntil := cert.NotAfter
	quals.ValidFrom = &validFrom
	quals.ValidUntil = &validUntil

	// Set max path length
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		quals.MaxPathLength = cert.MaxPathLen
	}

	// Set service type based on CA flag
	if cert.IsCA {
		quals.TrustedServiceType = TrustedServiceCA
	} else {
		quals.TrustedServiceType = TrustedServiceUnsupported
	}

	// Extract standard parameters from extensions
	extFound := false
	var params *PKIXValidationParams

	// Check name constraints
	if len(cert.PermittedDNSDomains) > 0 || len(cert.ExcludedDNSDomains) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 || len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.PermittedURIDomains) > 0 || len(cert.ExcludedURIDomains) > 0 {
		extFound = true
		// Name constraints would be processed here
	}

	// Check certificate policies
	if len(cert.PolicyIdentifiers) > 0 {
		extFound = true
		policies := make(map[string]bool)
		for _, oid := range cert.PolicyIdentifiers {
			if oid.String() != "2.5.29.32.0" { // any-policy OID
				policies[oid.String()] = true
			}
		}
		if len(policies) > 0 {
			params = &PKIXValidationParams{
				UserInitialPolicySet:  policies,
				InitialExplicitPolicy: true,
			}
		}
	}

	if extFound && params != nil {
		quals.StandardParameters = params
	}

	return quals
}

// TrustAnchorStore stores multiple trust anchors.
type TrustAnchorStore struct {
	anchors []*CertTrustAnchor
}

// NewTrustAnchorStore creates a new trust anchor store.
func NewTrustAnchorStore() *TrustAnchorStore {
	return &TrustAnchorStore{
		anchors: make([]*CertTrustAnchor, 0),
	}
}

// Add adds a trust anchor to the store.
func (s *TrustAnchorStore) Add(anchor *CertTrustAnchor) {
	s.anchors = append(s.anchors, anchor)
}

// AddCertificate adds a certificate as a trust anchor.
func (s *TrustAnchorStore) AddCertificate(cert *x509.Certificate, deriveQuals bool) {
	anchor := NewCertTrustAnchor(cert, nil, deriveQuals)
	s.Add(anchor)
}

// FindPotentialIssuers finds trust anchors that could be issuers of the certificate.
func (s *TrustAnchorStore) FindPotentialIssuers(cert *x509.Certificate) []*CertTrustAnchor {
	var issuers []*CertTrustAnchor
	for _, anchor := range s.anchors {
		if anchor.Authority().IsPotentialIssuerOf(cert) {
			issuers = append(issuers, anchor)
		}
	}
	return issuers
}

// All returns all trust anchors.
func (s *TrustAnchorStore) All() []*CertTrustAnchor {
	return s.anchors
}

// Count returns the number of trust anchors.
func (s *TrustAnchorStore) Count() int {
	return len(s.anchors)
}

// ToCertPool converts the trust anchors to a x509.CertPool.
func (s *TrustAnchorStore) ToCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, anchor := range s.anchors {
		pool.AddCert(anchor.Certificate())
	}
	return pool
}
