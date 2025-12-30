// Package certvalidator provides X.509 certificate path validation.
// This file contains validation process state management.
package certvalidator

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// ConsList is an immutable cons list data structure for functional programming.
type ConsList[T any] struct {
	Head T
	Tail *ConsList[T]
}

// NewConsList creates a new cons list with the given head.
func NewConsList[T any](head T) *ConsList[T] {
	return &ConsList[T]{Head: head}
}

// Prepend adds a new head to the cons list.
func (c *ConsList[T]) Prepend(head T) *ConsList[T] {
	return &ConsList[T]{Head: head, Tail: c}
}

// IsEmpty returns true if the cons list is nil.
func (c *ConsList[T]) IsEmpty() bool {
	return c == nil
}

// Len returns the length of the cons list.
func (c *ConsList[T]) Len() int {
	if c == nil {
		return 0
	}
	count := 0
	for curr := c; curr != nil; curr = curr.Tail {
		count++
	}
	return count
}

// ToSlice converts the cons list to a slice.
func (c *ConsList[T]) ToSlice() []T {
	if c == nil {
		return nil
	}
	result := make([]T, 0)
	for curr := c; curr != nil; curr = curr.Tail {
		result = append(result, curr.Head)
	}
	return result
}

// ValidationPath represents a certification path being validated.
type ValidationPath struct {
	TrustAnchor   *x509.Certificate
	Intermediates []*x509.Certificate
	EECert        *x509.Certificate
}

// NewValidationPath creates a new validation path.
func NewValidationPath(trustAnchor *x509.Certificate) *ValidationPath {
	return &ValidationPath{
		TrustAnchor:   trustAnchor,
		Intermediates: make([]*x509.Certificate, 0),
	}
}

// AddIntermediate adds an intermediate certificate to the path.
func (p *ValidationPath) AddIntermediate(cert *x509.Certificate) {
	p.Intermediates = append(p.Intermediates, cert)
}

// SetEECert sets the end-entity certificate.
func (p *ValidationPath) SetEECert(cert *x509.Certificate) {
	p.EECert = cert
}

// PKIXLen returns the PKIX path length (excludes trust anchor).
func (p *ValidationPath) PKIXLen() int {
	count := len(p.Intermediates)
	if p.EECert != nil {
		count++
	}
	return count
}

// GetEECertSafe returns the end-entity certificate if available.
func (p *ValidationPath) GetEECertSafe() *x509.Certificate {
	return p.EECert
}

// AllCerts returns all certificates in the path including trust anchor.
func (p *ValidationPath) AllCerts() []*x509.Certificate {
	result := make([]*x509.Certificate, 0)
	if p.TrustAnchor != nil {
		result = append(result, p.TrustAnchor)
	}
	result = append(result, p.Intermediates...)
	if p.EECert != nil {
		result = append(result, p.EECert)
	}
	return result
}

// CertSHA256 returns the SHA256 hash of a certificate.
func CertSHA256(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// QualifiedPolicy represents a policy with both issuer and user domain OIDs.
type QualifiedPolicy struct {
	// IssuerDomainPolicyID is the policy OID in the issuer domain.
	IssuerDomainPolicyID string

	// UserDomainPolicyID is the policy OID in the user domain.
	UserDomainPolicyID string

	// Qualifiers are policy qualifier information objects.
	Qualifiers []interface{}
}

// NewQualifiedPolicy creates a new QualifiedPolicy.
func NewQualifiedPolicy(issuerPolicy, userPolicy string, qualifiers []interface{}) *QualifiedPolicy {
	return &QualifiedPolicy{
		IssuerDomainPolicyID: issuerPolicy,
		UserDomainPolicyID:   userPolicy,
		Qualifiers:           qualifiers,
	}
}

// First returns the first certificate in the path.
// This is the trust anchor if available.
func (p *ValidationPath) First() *x509.Certificate {
	if p.TrustAnchor != nil {
		return p.TrustAnchor
	}
	if len(p.Intermediates) > 0 {
		return p.Intermediates[0]
	}
	return p.EECert
}

// Leaf returns the leaf certificate in the path.
// If there is an EE cert, it returns that. Otherwise, returns the trust anchor
// if there are no intermediates.
func (p *ValidationPath) Leaf() *x509.Certificate {
	if p.EECert != nil {
		return p.EECert
	}
	if len(p.Intermediates) == 0 && p.TrustAnchor != nil {
		return p.TrustAnchor
	}
	return nil
}

// DescribeLeaf returns a human-readable description of the leaf certificate.
func (p *ValidationPath) DescribeLeaf() string {
	leaf := p.Leaf()
	if leaf == nil {
		return ""
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	return leaf.Subject.String()
}

// Last returns the last certificate in the path if it's an X.509 certificate.
// Returns an error if no EE cert is available.
func (p *ValidationPath) Last() (*x509.Certificate, error) {
	cert := p.GetEECertSafe()
	if cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf("no end-entity certificate in path")
}

// IterAuthorities returns all authorities in the path including the trust anchor.
func (p *ValidationPath) IterAuthorities() []*x509.Certificate {
	result := make([]*x509.Certificate, 0)
	if p.TrustAnchor != nil {
		result = append(result, p.TrustAnchor)
	}
	result = append(result, p.Intermediates...)
	return result
}

// FindIssuingAuthority finds the issuer of the specified certificate in this path.
func (p *ValidationPath) FindIssuingAuthority(cert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	issuerName := cert.Issuer.String()
	aki := cert.AuthorityKeyId

	for _, authority := range p.IterAuthorities() {
		if authority.Subject.String() == issuerName {
			// Check key identifier if available
			if len(aki) > 0 && len(authority.SubjectKeyId) > 0 {
				match := true
				for i := range aki {
					if i >= len(authority.SubjectKeyId) || aki[i] != authority.SubjectKeyId[i] {
						match = false
						break
					}
				}
				if !match {
					continue
				}
			}
			return authority, nil
		}
	}

	return nil, fmt.Errorf("unable to find the issuer of the certificate specified")
}

// TruncateToAndAppend removes all certificates after the specified cert and appends a new leaf.
func (p *ValidationPath) TruncateToAndAppend(cert, newLeaf *x509.Certificate) (*ValidationPath, error) {
	// Check if cert is the trust anchor
	if p.TrustAnchor != nil && CertSHA256(p.TrustAnchor) == CertSHA256(cert) {
		return &ValidationPath{
			TrustAnchor:   p.TrustAnchor,
			Intermediates: make([]*x509.Certificate, 0),
			EECert:        newLeaf,
		}, nil
	}

	// Find the certificate in intermediates
	for i, entry := range p.Intermediates {
		if CertSHA256(entry) == CertSHA256(cert) {
			newIntermediates := make([]*x509.Certificate, i+1)
			copy(newIntermediates, p.Intermediates[:i+1])
			return &ValidationPath{
				TrustAnchor:   p.TrustAnchor,
				Intermediates: newIntermediates,
				EECert:        newLeaf,
			}, nil
		}
	}

	return nil, fmt.Errorf("unable to find the specified certificate in the path")
}

// TruncateToIssuerAndAppend removes all certificates after the issuer of cert and appends cert as the new leaf.
func (p *ValidationPath) TruncateToIssuerAndAppend(cert *x509.Certificate) (*ValidationPath, error) {
	// Check if trust anchor is the issuer
	if p.TrustAnchor != nil && IsPotentialIssuerOf(p.TrustAnchor, cert) {
		// Check if cert is self-signed
		if IsSelfSigned(cert) {
			return &ValidationPath{
				TrustAnchor:   p.TrustAnchor,
				Intermediates: make([]*x509.Certificate, 0),
				EECert:        nil,
			}, nil
		}
		return &ValidationPath{
			TrustAnchor:   p.TrustAnchor,
			Intermediates: make([]*x509.Certificate, 0),
			EECert:        cert,
		}, nil
	}

	// Find issuer in intermediates
	for i, entry := range p.Intermediates {
		if IsPotentialIssuerOf(entry, cert) {
			newIntermediates := make([]*x509.Certificate, i+1)
			copy(newIntermediates, p.Intermediates[:i+1])
			return &ValidationPath{
				TrustAnchor:   p.TrustAnchor,
				Intermediates: newIntermediates,
				EECert:        cert,
			}, nil
		}
	}

	return nil, fmt.Errorf("unable to find the issuer of the certificate specified")
}

// IsPotentialIssuerOf checks if issuer could have issued subject based on names and key IDs.
func IsPotentialIssuerOf(issuer, subject *x509.Certificate) bool {
	if issuer == nil || subject == nil {
		return false
	}

	// Check that issuer's subject matches subject's issuer
	if issuer.Subject.String() != subject.Issuer.String() {
		return false
	}

	// Check authority key identifier if present
	if len(subject.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 {
		for i := range subject.AuthorityKeyId {
			if i >= len(issuer.SubjectKeyId) || subject.AuthorityKeyId[i] != issuer.SubjectKeyId[i] {
				return false
			}
		}
	}

	return true
}

// Note: IsSelfSigned is defined in util.go

// CopyAndAppend creates a copy of the path with a new leaf certificate appended.
func (p *ValidationPath) CopyAndAppend(cert *x509.Certificate) *ValidationPath {
	newIntermediates := make([]*x509.Certificate, len(p.Intermediates))
	copy(newIntermediates, p.Intermediates)

	// If there was an existing EE cert, move it to intermediates
	if p.EECert != nil {
		newIntermediates = append(newIntermediates, p.EECert)
	}

	return &ValidationPath{
		TrustAnchor:   p.TrustAnchor,
		Intermediates: newIntermediates,
		EECert:        cert,
	}
}

// CopyAndDropLeaf creates a copy of the path with the leaf dropped.
// The last intermediate becomes the new EE cert.
func (p *ValidationPath) CopyAndDropLeaf() (*ValidationPath, error) {
	if len(p.Intermediates) == 0 {
		return nil, fmt.Errorf("cannot drop leaf from path with no intermediates")
	}

	newIntermediates := make([]*x509.Certificate, len(p.Intermediates)-1)
	copy(newIntermediates, p.Intermediates[:len(p.Intermediates)-1])
	newEE := p.Intermediates[len(p.Intermediates)-1]

	return &ValidationPath{
		TrustAnchor:   p.TrustAnchor,
		Intermediates: newIntermediates,
		EECert:        newEE,
	}, nil
}

// IterCerts iterates over certificates in the path.
func (p *ValidationPath) IterCerts(includeRoot bool) []*x509.Certificate {
	result := make([]*x509.Certificate, 0)
	if includeRoot && p.TrustAnchor != nil {
		result = append(result, p.TrustAnchor)
	}
	result = append(result, p.Intermediates...)
	if p.EECert != nil {
		result = append(result, p.EECert)
	}
	return result
}

// Len returns the total length of the path including the trust anchor.
func (p *ValidationPath) Len() int {
	count := 0
	if p.TrustAnchor != nil {
		count++
	}
	count += len(p.Intermediates)
	if p.EECert != nil {
		count++
	}
	return count
}

// Equals checks if two validation paths are equal.
func (p *ValidationPath) Equals(other *ValidationPath) bool {
	if other == nil {
		return p == nil
	}

	// Compare trust anchors
	if p.TrustAnchor == nil && other.TrustAnchor != nil {
		return false
	}
	if p.TrustAnchor != nil && other.TrustAnchor == nil {
		return false
	}
	if p.TrustAnchor != nil && other.TrustAnchor != nil {
		if CertSHA256(p.TrustAnchor) != CertSHA256(other.TrustAnchor) {
			return false
		}
	}

	// Compare intermediates
	if len(p.Intermediates) != len(other.Intermediates) {
		return false
	}
	for i := range p.Intermediates {
		if CertSHA256(p.Intermediates[i]) != CertSHA256(other.Intermediates[i]) {
			return false
		}
	}

	// Compare EE certs
	if p.EECert == nil && other.EECert != nil {
		return false
	}
	if p.EECert != nil && other.EECert == nil {
		return false
	}
	if p.EECert != nil && other.EECert != nil {
		if CertSHA256(p.EECert) != CertSHA256(other.EECert) {
			return false
		}
	}

	return true
}

// Clone creates a deep copy of the validation path.
func (p *ValidationPath) Clone() *ValidationPath {
	if p == nil {
		return nil
	}

	newIntermediates := make([]*x509.Certificate, len(p.Intermediates))
	copy(newIntermediates, p.Intermediates)

	return &ValidationPath{
		TrustAnchor:   p.TrustAnchor,
		Intermediates: newIntermediates,
		EECert:        p.EECert,
	}
}

// ValProcState manages state during PKIX validation.
// It tracks the current position in the certificate chain and provides
// utility methods for detecting recursion and generating error messages.
type ValProcState struct {
	// Index is the current position in the path (0 = trust anchor)
	Index int

	// EENameOverride provides an alternative name for the end-entity
	// certificate in error messages.
	EENameOverride string

	// IsSideValidation indicates if this is a side validation
	// (e.g., validating a CRL issuer certificate).
	IsSideValidation bool

	// CertPathStack is the stack of validation paths being processed.
	CertPathStack *ConsList[*ValidationPath]
}

// NewValProcState creates a new validation process state.
func NewValProcState(certPathStack *ConsList[*ValidationPath], opts ...ValProcStateOption) (*ValProcState, error) {
	if certPathStack == nil || certPathStack.IsEmpty() {
		return nil, fmt.Errorf("empty path stack")
	}

	state := &ValProcState{
		Index:            0,
		CertPathStack:    certPathStack,
		IsSideValidation: certPathStack.Tail != nil,
	}

	for _, opt := range opts {
		opt(state)
	}

	return state, nil
}

// ValProcStateOption is a functional option for ValProcState.
type ValProcStateOption func(*ValProcState)

// WithEENameOverride sets the end-entity name override.
func WithEENameOverride(name string) ValProcStateOption {
	return func(s *ValProcState) {
		s.EENameOverride = name
	}
}

// WithInitIndex sets the initial index.
func WithInitIndex(index int) ValProcStateOption {
	return func(s *ValProcState) {
		s.Index = index
	}
}

// WithSideValidation sets the side validation flag.
func WithSideValidation(isSide bool) ValProcStateOption {
	return func(s *ValProcState) {
		s.IsSideValidation = isSide || s.CertPathStack.Tail != nil
	}
}

// PathLen returns the length of the path being validated.
// This is the path length in the sense of RFC 5280, i.e.
// the root doesn't count.
func (s *ValProcState) PathLen() int {
	if s.CertPathStack == nil {
		return 0
	}
	return s.CertPathStack.Head.PKIXLen()
}

// IsEECert returns true if the current position is the end-entity certificate.
func (s *ValProcState) IsEECert() bool {
	return s.Index == s.PathLen()
}

// CheckPathVerifRecursion checks if we're already validating the same certificate.
// This helps avoid infinite recursion in indirect CRL validation where a CRL issuer
// might be authorized to assert its own revocation status.
func (s *ValProcState) CheckPathVerifRecursion(eeCert *x509.Certificate) *ValidationPath {
	if eeCert == nil {
		return nil
	}

	eeCertHash := CertSHA256(eeCert)

	for curr := s.CertPathStack; curr != nil; curr = curr.Tail {
		path := curr.Head
		pathEECert := path.GetEECertSafe()
		if pathEECert != nil {
			pathCertHash := CertSHA256(pathEECert)
			if eeCertHash == pathCertHash {
				return path
			}
		}
	}

	return nil
}

// DescribeCert returns a human-readable description of the current certificate position.
func (s *ValProcState) DescribeCert(defInterm, neverDef bool) string {
	var result string
	prefix := !neverDef

	if s.Index == 0 && s.EENameOverride == "" {
		// Can happen for trust anchors with qualifiers
		result = "trust anchor"
	} else if !s.IsEECert() {
		prefix = prefix && defInterm
		result = fmt.Sprintf("intermediate certificate %d", s.Index)
	} else if s.EENameOverride != "" {
		result = s.EENameOverride
	} else {
		result = "end-entity certificate"
	}

	if prefix {
		return "the " + result
	}
	return result
}

// Advance moves to the next certificate in the path.
func (s *ValProcState) Advance() {
	s.Index++
}

// Reset resets the index to the beginning.
func (s *ValProcState) Reset() {
	s.Index = 0
}

// GetCurrentPath returns the current validation path.
func (s *ValProcState) GetCurrentPath() *ValidationPath {
	if s.CertPathStack == nil {
		return nil
	}
	return s.CertPathStack.Head
}

// PushPath pushes a new path onto the stack (for side validations).
func (s *ValProcState) PushPath(path *ValidationPath) {
	s.CertPathStack = s.CertPathStack.Prepend(path)
	s.IsSideValidation = true
}

// PopPath pops the current path from the stack.
func (s *ValProcState) PopPath() *ValidationPath {
	if s.CertPathStack == nil {
		return nil
	}
	path := s.CertPathStack.Head
	s.CertPathStack = s.CertPathStack.Tail
	s.IsSideValidation = s.CertPathStack != nil && s.CertPathStack.Tail != nil
	return path
}

// Clone creates a copy of the validation state.
func (s *ValProcState) Clone() *ValProcState {
	return &ValProcState{
		Index:            s.Index,
		EENameOverride:   s.EENameOverride,
		IsSideValidation: s.IsSideValidation,
		CertPathStack:    s.CertPathStack, // Immutable, safe to share
	}
}
