// Package certvalidator provides X.509 certificate path validation.
package certvalidator

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// Common errors
var (
	ErrCertificateExpired     = errors.New("certificate expired")
	ErrCertificateNotYetValid = errors.New("certificate not yet valid")
	ErrCertificateRevoked     = errors.New("certificate revoked")
	ErrInvalidChain           = errors.New("invalid certificate chain")
	ErrNoTrustAnchor          = errors.New("no trust anchor found")
	ErrRevocationCheckFailed  = errors.New("revocation check failed")
)

// ValidationContext provides context for certificate validation.
type ValidationContext struct {
	TrustRoots        *x509.CertPool
	IntermediateCerts []*x509.Certificate
	ValidationTime    time.Time
	CRLCache          map[string]*CRL
	OCSPCache         map[string]*OCSPResponse
	AllowFetching     bool
	SkipRevocation    bool
	MaxChainLength    int
	HTTPClient        *http.Client
}

// NewValidationContext creates a new validation context.
func NewValidationContext(roots *x509.CertPool) *ValidationContext {
	return &ValidationContext{
		TrustRoots:     roots,
		ValidationTime: time.Now(),
		CRLCache:       make(map[string]*CRL),
		OCSPCache:      make(map[string]*OCSPResponse),
		AllowFetching:  true,
		MaxChainLength: 10,
		HTTPClient:     &http.Client{Timeout: 30 * time.Second},
	}
}

// SetValidationTime sets the time for validation.
func (ctx *ValidationContext) SetValidationTime(t time.Time) {
	ctx.ValidationTime = t
}

// AddIntermediateCert adds an intermediate certificate.
func (ctx *ValidationContext) AddIntermediateCert(cert *x509.Certificate) {
	ctx.IntermediateCerts = append(ctx.IntermediateCerts, cert)
}

// ValidationResult contains the result of certificate validation.
type ValidationResult struct {
	Valid            bool
	Chain            []*x509.Certificate
	TrustAnchor      *x509.Certificate
	Errors           []error
	Warnings         []string
	RevocationStatus RevocationStatus
}

// RevocationStatus represents certificate revocation status.
type RevocationStatus int

const (
	RevocationUnknown RevocationStatus = iota
	RevocationGood
	RevocationRevoked
	RevocationCheckFailed
)

// CertificateValidator validates X.509 certificates.
type CertificateValidator struct {
	Context *ValidationContext
}

// NewCertificateValidator creates a new certificate validator.
func NewCertificateValidator(ctx *ValidationContext) *CertificateValidator {
	return &CertificateValidator{Context: ctx}
}

// Validate validates a certificate.
func (v *CertificateValidator) Validate(cert *x509.Certificate) (*ValidationResult, error) {
	result := &ValidationResult{}

	// Check validity period
	if v.Context.ValidationTime.After(cert.NotAfter) {
		result.Errors = append(result.Errors, ErrCertificateExpired)
	}
	if v.Context.ValidationTime.Before(cert.NotBefore) {
		result.Errors = append(result.Errors, ErrCertificateNotYetValid)
	}

	// Build and validate certificate chain
	chain, err := v.buildChain(cert)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return result, nil
	}
	result.Chain = chain

	if len(chain) > 0 {
		result.TrustAnchor = chain[len(chain)-1]
	}

	// Check revocation
	if !v.Context.SkipRevocation {
		revStatus := v.checkRevocation(cert)
		result.RevocationStatus = revStatus
		if revStatus == RevocationRevoked {
			result.Errors = append(result.Errors, ErrCertificateRevoked)
		} else if revStatus == RevocationCheckFailed {
			result.Warnings = append(result.Warnings, "revocation check failed")
		}
	}

	result.Valid = len(result.Errors) == 0
	return result, nil
}

// buildChain builds the certificate chain to a trust anchor.
func (v *CertificateValidator) buildChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	if v.Context.TrustRoots == nil {
		return nil, ErrNoTrustAnchor
	}

	// Create intermediate pool
	intermediates := x509.NewCertPool()
	for _, inter := range v.Context.IntermediateCerts {
		intermediates.AddCert(inter)
	}

	// Verify
	opts := x509.VerifyOptions{
		Roots:                     v.Context.TrustRoots,
		Intermediates:             intermediates,
		CurrentTime:               v.Context.ValidationTime,
		MaxConstraintComparisions: v.Context.MaxChainLength,
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChain, err)
	}

	if len(chains) > 0 {
		return chains[0], nil
	}

	return nil, ErrNoTrustAnchor
}

// checkRevocation checks the revocation status of a certificate.
func (v *CertificateValidator) checkRevocation(cert *x509.Certificate) RevocationStatus {
	// Try OCSP first
	if len(cert.OCSPServer) > 0 {
		status := v.checkOCSP(cert)
		if status != RevocationCheckFailed {
			return status
		}
	}

	// Fall back to CRL
	if len(cert.CRLDistributionPoints) > 0 {
		return v.checkCRL(cert)
	}

	return RevocationUnknown
}

// checkOCSP checks revocation via OCSP.
func (v *CertificateValidator) checkOCSP(cert *x509.Certificate) RevocationStatus {
	for _, ocspURL := range cert.OCSPServer {
		// Check cache
		if cached, ok := v.Context.OCSPCache[ocspURL]; ok {
			if cached.Status == OCSPGood {
				return RevocationGood
			} else if cached.Status == OCSPRevoked {
				return RevocationRevoked
			}
		}

		// Fetch OCSP response
		if v.Context.AllowFetching {
			resp, err := v.fetchOCSP(cert, ocspURL)
			if err == nil {
				v.Context.OCSPCache[ocspURL] = resp
				if resp.Status == OCSPGood {
					return RevocationGood
				} else if resp.Status == OCSPRevoked {
					return RevocationRevoked
				}
			}
		}
	}

	return RevocationCheckFailed
}

// checkCRL checks revocation via CRL.
func (v *CertificateValidator) checkCRL(cert *x509.Certificate) RevocationStatus {
	for _, crlURL := range cert.CRLDistributionPoints {
		// Check cache
		if cached, ok := v.Context.CRLCache[crlURL]; ok {
			if cached.Contains(cert.SerialNumber) {
				return RevocationRevoked
			}
			return RevocationGood
		}

		// Fetch CRL
		if v.Context.AllowFetching {
			crl, err := v.fetchCRL(crlURL)
			if err == nil {
				v.Context.CRLCache[crlURL] = crl
				if crl.Contains(cert.SerialNumber) {
					return RevocationRevoked
				}
				return RevocationGood
			}
		}
	}

	return RevocationCheckFailed
}

// fetchOCSP fetches an OCSP response.
func (v *CertificateValidator) fetchOCSP(cert *x509.Certificate, url string) (*OCSPResponse, error) {
	// Simplified OCSP fetch - real implementation would build proper OCSP request
	// and parse the response
	return nil, fmt.Errorf("OCSP not implemented")
}

// fetchCRL fetches a CRL.
func (v *CertificateValidator) fetchCRL(url string) (*CRL, error) {
	resp, err := v.Context.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return ParseCRL(data)
}

// CRL represents a Certificate Revocation List.
type CRL struct {
	Issuer       pkix.Name
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedCerts map[string]RevokedCertificate
	RawIssuer    []byte
}

// RevokedCertificate represents a revoked certificate entry.
type RevokedCertificate struct {
	SerialNumber   []byte
	RevocationDate time.Time
	Reason         int
}

// Contains checks if the CRL contains a revoked certificate.
func (c *CRL) Contains(serialNumber *big.Int) bool {
	_, exists := c.RevokedCerts[serialNumber.String()]
	return exists
}

// ParseCRL parses a CRL from DER data.
func ParseCRL(data []byte) (*CRL, error) {
	// Parse the CRL using Go's x509 package
	certList, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}

	crl := &CRL{
		Issuer:       certList.Issuer,
		ThisUpdate:   certList.ThisUpdate,
		NextUpdate:   certList.NextUpdate,
		RevokedCerts: make(map[string]RevokedCertificate),
		RawIssuer:    certList.RawIssuer,
	}

	for _, revoked := range certList.RevokedCertificateEntries {
		crl.RevokedCerts[revoked.SerialNumber.String()] = RevokedCertificate{
			SerialNumber:   revoked.SerialNumber.Bytes(),
			RevocationDate: revoked.RevocationTime,
		}
	}

	return crl, nil
}

// OCSPResponse represents an OCSP response.
type OCSPResponse struct {
	Status         OCSPStatus
	ProducedAt     time.Time
	ThisUpdate     time.Time
	NextUpdate     time.Time
	SerialNumber   []byte
	RevocationTime time.Time
}

// OCSPStatus represents OCSP response status.
type OCSPStatus int

const (
	OCSPUnknown OCSPStatus = iota
	OCSPGood
	OCSPRevoked
)

// OIDs for certificate extensions and attributes
var (
	OIDBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDSubjectKeyID          = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDAuthorityKeyID        = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	// Extended key usage
	OIDCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	OIDEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	OIDTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	OIDOCSPSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// CheckKeyUsage checks if the certificate has the required key usage.
func CheckKeyUsage(cert *x509.Certificate, usage x509.KeyUsage) bool {
	return cert.KeyUsage&usage != 0
}

// CheckExtKeyUsage checks if the certificate has the required extended key usage.
func CheckExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == usage {
			return true
		}
	}
	return false
}

// IsCA checks if the certificate is a CA.
func IsCA(cert *x509.Certificate) bool {
	return cert.IsCA
}

// GetPathLength returns the path length constraint.
func GetPathLength(cert *x509.Certificate) int {
	if cert.MaxPathLen == 0 && !cert.MaxPathLenZero {
		return -1 // No constraint
	}
	return cert.MaxPathLen
}

// TrustAnchor represents a trust anchor (root CA).
type TrustAnchor struct {
	Certificate *x509.Certificate
	Name        string
	Constraints *TrustConstraints
}

// TrustConstraints represents constraints on a trust anchor.
type TrustConstraints struct {
	PermittedNamespaces []string
	ExcludedNamespaces  []string
	ValidUsages         []x509.ExtKeyUsage
}

// TrustStore manages trust anchors.
type TrustStore struct {
	Anchors  []*TrustAnchor
	CertPool *x509.CertPool
}

// NewTrustStore creates a new trust store.
func NewTrustStore() *TrustStore {
	return &TrustStore{
		CertPool: x509.NewCertPool(),
	}
}

// AddTrustAnchor adds a trust anchor.
func (ts *TrustStore) AddTrustAnchor(anchor *TrustAnchor) {
	ts.Anchors = append(ts.Anchors, anchor)
	ts.CertPool.AddCert(anchor.Certificate)
}

// AddCertificate adds a certificate as a trust anchor.
func (ts *TrustStore) AddCertificate(cert *x509.Certificate) {
	ts.AddTrustAnchor(&TrustAnchor{
		Certificate: cert,
		Name:        cert.Subject.CommonName,
	})
}

// LoadSystemRoots loads the system root certificates.
func (ts *TrustStore) LoadSystemRoots() error {
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		return err
	}
	ts.CertPool = systemRoots
	return nil
}

// CreateValidationContext creates a validation context from the trust store.
func (ts *TrustStore) CreateValidationContext() *ValidationContext {
	return NewValidationContext(ts.CertPool)
}
