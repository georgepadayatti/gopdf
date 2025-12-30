// Package revinfo provides revocation information handling for certificate validation.
package revinfo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Common errors
var (
	ErrRevoked               = errors.New("certificate is revoked")
	ErrCRLExpired            = errors.New("CRL has expired")
	ErrCRLNotYetValid        = errors.New("CRL is not yet valid")
	ErrOCSPExpired           = errors.New("OCSP response has expired")
	ErrOCSPNotYetValid       = errors.New("OCSP response is not yet valid")
	ErrInvalidSignature      = errors.New("invalid signature")
	ErrIssuerMismatch        = errors.New("issuer mismatch")
	ErrNoRevocationInfo      = errors.New("no revocation information available")
	ErrRevocationCheckFailed = errors.New("revocation check failed")
)

// RevocationReason represents the reason for certificate revocation.
type RevocationReason int

const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	ReasonRemoveFromCRL        RevocationReason = 8
	ReasonPrivilegeWithdrawn   RevocationReason = 9
	ReasonAACompromise         RevocationReason = 10
)

// String returns the string representation of a revocation reason.
func (r RevocationReason) String() string {
	switch r {
	case ReasonUnspecified:
		return "unspecified"
	case ReasonKeyCompromise:
		return "keyCompromise"
	case ReasonCACompromise:
		return "cACompromise"
	case ReasonAffiliationChanged:
		return "affiliationChanged"
	case ReasonSuperseded:
		return "superseded"
	case ReasonCessationOfOperation:
		return "cessationOfOperation"
	case ReasonCertificateHold:
		return "certificateHold"
	case ReasonRemoveFromCRL:
		return "removeFromCRL"
	case ReasonPrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ReasonAACompromise:
		return "aACompromise"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// RevocationStatus represents the revocation status of a certificate.
type RevocationStatus int

const (
	StatusUnknown RevocationStatus = iota
	StatusGood
	StatusRevoked
)

// String returns the string representation of a revocation status.
func (s RevocationStatus) String() string {
	switch s {
	case StatusGood:
		return "good"
	case StatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// RevocationInfo contains information about a certificate's revocation status.
type RevocationInfo struct {
	// Status is the revocation status
	Status RevocationStatus
	// RevocationTime is when the certificate was revoked (if revoked)
	RevocationTime *time.Time
	// Reason is the revocation reason (if revoked)
	Reason RevocationReason
	// Source indicates where the info came from ("CRL" or "OCSP")
	Source string
	// ProducedAt is when the revocation info was produced
	ProducedAt time.Time
	// ThisUpdate is the thisUpdate time from OCSP/CRL
	ThisUpdate time.Time
	// NextUpdate is when new revocation info should be available
	NextUpdate *time.Time
	// RawData is the raw revocation data (CRL or OCSP response)
	RawData []byte
}

// IsValid checks if the revocation info is currently valid.
func (ri *RevocationInfo) IsValid(at time.Time) bool {
	if at.Before(ri.ThisUpdate) {
		return false
	}
	if ri.NextUpdate != nil && at.After(*ri.NextUpdate) {
		return false
	}
	return true
}

// CRLInfo contains parsed CRL information.
type CRLInfo struct {
	// Raw CRL data
	Raw []byte
	// Parsed CRL
	CRL *x509.RevocationList
	// Issuer certificate
	Issuer *x509.Certificate
	// Distribution point URL
	URL string
	// Whether this is a delta CRL
	IsDelta bool
	// Base CRL number (for delta CRLs)
	BaseCRLNumber *big.Int
}

// NewCRLInfo creates a new CRLInfo from raw data.
func NewCRLInfo(raw []byte, issuer *x509.Certificate, url string) (*CRLInfo, error) {
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	info := &CRLInfo{
		Raw:    raw,
		CRL:    crl,
		Issuer: issuer,
		URL:    url,
	}

	// Check for delta CRL indicator
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) { // deltaCRLIndicator
			info.IsDelta = true
			var baseCRLNumber big.Int
			if _, err := asn1.Unmarshal(ext.Value, &baseCRLNumber); err == nil {
				info.BaseCRLNumber = &baseCRLNumber
			}
			break
		}
	}

	return info, nil
}

// Validate validates the CRL.
func (ci *CRLInfo) Validate(at time.Time) error {
	if at.Before(ci.CRL.ThisUpdate) {
		return ErrCRLNotYetValid
	}
	if at.After(ci.CRL.NextUpdate) {
		return ErrCRLExpired
	}

	// Verify signature if issuer is available
	if ci.Issuer != nil {
		if err := ci.CRL.CheckSignatureFrom(ci.Issuer); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
	}

	return nil
}

// CheckCertificate checks if a certificate is in the CRL.
func (ci *CRLInfo) CheckCertificate(cert *x509.Certificate) *RevocationInfo {
	for _, entry := range ci.CRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			revTime := entry.RevocationTime
			return &RevocationInfo{
				Status:         StatusRevoked,
				RevocationTime: &revTime,
				Reason:         RevocationReason(entry.ReasonCode),
				Source:         "CRL",
				ThisUpdate:     ci.CRL.ThisUpdate,
				NextUpdate:     &ci.CRL.NextUpdate,
				RawData:        ci.Raw,
			}
		}
	}

	return &RevocationInfo{
		Status:     StatusGood,
		Source:     "CRL",
		ThisUpdate: ci.CRL.ThisUpdate,
		NextUpdate: &ci.CRL.NextUpdate,
		RawData:    ci.Raw,
	}
}

// OCSPInfo contains parsed OCSP response information.
type OCSPInfo struct {
	// Raw OCSP response data
	Raw []byte
	// Parsed OCSP response
	Response *ocsp.Response
	// Issuer certificate
	Issuer *x509.Certificate
	// OCSP responder URL
	URL string
}

// NewOCSPInfo creates a new OCSPInfo from raw data.
func NewOCSPInfo(raw []byte, issuer *x509.Certificate, url string) (*OCSPInfo, error) {
	resp, err := ocsp.ParseResponse(raw, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	return &OCSPInfo{
		Raw:      raw,
		Response: resp,
		Issuer:   issuer,
		URL:      url,
	}, nil
}

// Validate validates the OCSP response.
func (oi *OCSPInfo) Validate(at time.Time) error {
	if at.Before(oi.Response.ThisUpdate) {
		return ErrOCSPNotYetValid
	}
	if !oi.Response.NextUpdate.IsZero() && at.After(oi.Response.NextUpdate) {
		return ErrOCSPExpired
	}

	return nil
}

// ToRevocationInfo converts the OCSP response to RevocationInfo.
func (oi *OCSPInfo) ToRevocationInfo() *RevocationInfo {
	info := &RevocationInfo{
		Source:     "OCSP",
		ProducedAt: oi.Response.ProducedAt,
		ThisUpdate: oi.Response.ThisUpdate,
		RawData:    oi.Raw,
	}

	if !oi.Response.NextUpdate.IsZero() {
		info.NextUpdate = &oi.Response.NextUpdate
	}

	switch oi.Response.Status {
	case ocsp.Good:
		info.Status = StatusGood
	case ocsp.Revoked:
		info.Status = StatusRevoked
		info.RevocationTime = &oi.Response.RevokedAt
		info.Reason = RevocationReason(oi.Response.RevocationReason)
	default:
		info.Status = StatusUnknown
	}

	return info
}

// RevocationInfoArchive stores revocation information for archival purposes.
type RevocationInfoArchive struct {
	mu    sync.RWMutex
	crls  map[string]*CRLInfo          // keyed by CRL distribution point URL
	ocsps map[string]*OCSPInfo         // keyed by cert serial + issuer hash
	certs map[string]*x509.Certificate // intermediate certs
}

// NewRevocationInfoArchive creates a new revocation info archive.
func NewRevocationInfoArchive() *RevocationInfoArchive {
	return &RevocationInfoArchive{
		crls:  make(map[string]*CRLInfo),
		ocsps: make(map[string]*OCSPInfo),
		certs: make(map[string]*x509.Certificate),
	}
}

// AddCRL adds a CRL to the archive.
func (a *RevocationInfoArchive) AddCRL(info *CRLInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.crls[info.URL] = info
}

// GetCRL retrieves a CRL from the archive.
func (a *RevocationInfoArchive) GetCRL(url string) *CRLInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.crls[url]
}

// AddOCSP adds an OCSP response to the archive.
func (a *RevocationInfoArchive) AddOCSP(cert *x509.Certificate, info *OCSPInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := certOCSPKey(cert)
	a.ocsps[key] = info
}

// GetOCSP retrieves an OCSP response from the archive.
func (a *RevocationInfoArchive) GetOCSP(cert *x509.Certificate) *OCSPInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	key := certOCSPKey(cert)
	return a.ocsps[key]
}

// AddCertificate adds an intermediate certificate to the archive.
func (a *RevocationInfoArchive) AddCertificate(cert *x509.Certificate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := certKey(cert)
	a.certs[key] = cert
}

// GetCertificate retrieves a certificate from the archive.
func (a *RevocationInfoArchive) GetCertificate(subject []byte, serial *big.Int) *x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	key := fmt.Sprintf("%x:%s", subject, serial.String())
	return a.certs[key]
}

// AllCRLs returns all CRLs in the archive.
func (a *RevocationInfoArchive) AllCRLs() []*CRLInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*CRLInfo, 0, len(a.crls))
	for _, crl := range a.crls {
		result = append(result, crl)
	}
	return result
}

// AllOCSPs returns all OCSP responses in the archive.
func (a *RevocationInfoArchive) AllOCSPs() []*OCSPInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*OCSPInfo, 0, len(a.ocsps))
	for _, ocspInfo := range a.ocsps {
		result = append(result, ocspInfo)
	}
	return result
}

// AllCertificates returns all certificates in the archive.
func (a *RevocationInfoArchive) AllCertificates() []*x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*x509.Certificate, 0, len(a.certs))
	for _, cert := range a.certs {
		result = append(result, cert)
	}
	return result
}

// RawCRLs returns all raw CRL data.
func (a *RevocationInfoArchive) RawCRLs() [][]byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([][]byte, 0, len(a.crls))
	for _, crl := range a.crls {
		result = append(result, crl.Raw)
	}
	return result
}

// RawOCSPs returns all raw OCSP response data.
func (a *RevocationInfoArchive) RawOCSPs() [][]byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([][]byte, 0, len(a.ocsps))
	for _, ocspInfo := range a.ocsps {
		result = append(result, ocspInfo.Raw)
	}
	return result
}

func certOCSPKey(cert *x509.Certificate) string {
	return fmt.Sprintf("%x:%s", cert.RawIssuer, cert.SerialNumber.String())
}

func certKey(cert *x509.Certificate) string {
	return fmt.Sprintf("%x:%s", cert.RawSubject, cert.SerialNumber.String())
}

// CRLValidator validates CRLs.
type CRLValidator struct {
	// TrustAnchors are trusted CA certificates
	TrustAnchors []*x509.Certificate
	// AllowExpired allows validation of expired CRLs
	AllowExpired bool
	// MaxAge is the maximum age of a CRL (0 for no limit)
	MaxAge time.Duration
}

// NewCRLValidator creates a new CRL validator.
func NewCRLValidator(anchors []*x509.Certificate) *CRLValidator {
	return &CRLValidator{
		TrustAnchors: anchors,
	}
}

// ValidateCRL validates a CRL.
func (v *CRLValidator) ValidateCRL(crl *x509.RevocationList, at time.Time) error {
	// Check validity period
	if !v.AllowExpired {
		if at.Before(crl.ThisUpdate) {
			return ErrCRLNotYetValid
		}
		if at.After(crl.NextUpdate) {
			return ErrCRLExpired
		}
	}

	// Check max age
	if v.MaxAge > 0 && time.Since(crl.ThisUpdate) > v.MaxAge {
		return fmt.Errorf("CRL is too old: %v", time.Since(crl.ThisUpdate))
	}

	// Verify signature against trust anchors
	for _, anchor := range v.TrustAnchors {
		if err := crl.CheckSignatureFrom(anchor); err == nil {
			return nil
		}
	}

	// Try to find issuer by subject match
	for _, anchor := range v.TrustAnchors {
		if bytes.Equal(anchor.RawSubject, crl.RawIssuer) {
			if err := crl.CheckSignatureFrom(anchor); err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
			}
			return nil
		}
	}

	return ErrIssuerMismatch
}

// OCSPValidator validates OCSP responses.
type OCSPValidator struct {
	// TrustAnchors are trusted CA certificates
	TrustAnchors []*x509.Certificate
	// AllowExpired allows validation of expired responses
	AllowExpired bool
	// MaxAge is the maximum age of an OCSP response (0 for no limit)
	MaxAge time.Duration
}

// NewOCSPValidator creates a new OCSP validator.
func NewOCSPValidator(anchors []*x509.Certificate) *OCSPValidator {
	return &OCSPValidator{
		TrustAnchors: anchors,
	}
}

// ValidateOCSP validates an OCSP response.
func (v *OCSPValidator) ValidateOCSP(resp *ocsp.Response, at time.Time) error {
	// Check validity period
	if !v.AllowExpired {
		if at.Before(resp.ThisUpdate) {
			return ErrOCSPNotYetValid
		}
		if !resp.NextUpdate.IsZero() && at.After(resp.NextUpdate) {
			return ErrOCSPExpired
		}
	}

	// Check max age
	if v.MaxAge > 0 && time.Since(resp.ThisUpdate) > v.MaxAge {
		return fmt.Errorf("OCSP response is too old: %v", time.Since(resp.ThisUpdate))
	}

	return nil
}

// RevocationChecker checks certificate revocation status.
type RevocationChecker struct {
	// Archive for storing/retrieving revocation info
	Archive *RevocationInfoArchive
	// CRLValidator for CRL validation
	CRLValidator *CRLValidator
	// OCSPValidator for OCSP validation
	OCSPValidator *OCSPValidator
	// PreferOCSP indicates whether to prefer OCSP over CRL
	PreferOCSP bool
	// RequireFresh requires fresh revocation info
	RequireFresh bool
	// FreshnessThreshold is the maximum age for "fresh" data
	FreshnessThreshold time.Duration
}

// NewRevocationChecker creates a new revocation checker.
func NewRevocationChecker(anchors []*x509.Certificate) *RevocationChecker {
	return &RevocationChecker{
		Archive:            NewRevocationInfoArchive(),
		CRLValidator:       NewCRLValidator(anchors),
		OCSPValidator:      NewOCSPValidator(anchors),
		PreferOCSP:         true,
		FreshnessThreshold: 24 * time.Hour,
	}
}

// CheckRevocation checks the revocation status of a certificate.
func (rc *RevocationChecker) CheckRevocation(ctx context.Context, cert, issuer *x509.Certificate, at time.Time) (*RevocationInfo, error) {
	if rc.PreferOCSP {
		// Try OCSP first
		info, err := rc.checkOCSP(ctx, cert, issuer, at)
		if err == nil && info.Status != StatusUnknown {
			return info, nil
		}

		// Fall back to CRL
		return rc.checkCRL(ctx, cert, issuer, at)
	}

	// Try CRL first
	info, err := rc.checkCRL(ctx, cert, issuer, at)
	if err == nil && info.Status != StatusUnknown {
		return info, nil
	}

	// Fall back to OCSP
	return rc.checkOCSP(ctx, cert, issuer, at)
}

func (rc *RevocationChecker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate, at time.Time) (*RevocationInfo, error) {
	// Check archive first
	ocspInfo := rc.Archive.GetOCSP(cert)
	if ocspInfo != nil {
		if err := ocspInfo.Validate(at); err == nil {
			// Check freshness
			if !rc.RequireFresh || time.Since(ocspInfo.Response.ThisUpdate) < rc.FreshnessThreshold {
				return ocspInfo.ToRevocationInfo(), nil
			}
		}
	}

	return &RevocationInfo{Status: StatusUnknown, Source: "OCSP"}, ErrNoRevocationInfo
}

func (rc *RevocationChecker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate, at time.Time) (*RevocationInfo, error) {
	// Check archive for each distribution point
	for _, dp := range cert.CRLDistributionPoints {
		crlInfo := rc.Archive.GetCRL(dp)
		if crlInfo != nil {
			if err := crlInfo.Validate(at); err == nil {
				// Check freshness
				if !rc.RequireFresh || time.Since(crlInfo.CRL.ThisUpdate) < rc.FreshnessThreshold {
					return crlInfo.CheckCertificate(cert), nil
				}
			}
		}
	}

	return &RevocationInfo{Status: StatusUnknown, Source: "CRL"}, ErrNoRevocationInfo
}

// RevocationPolicy defines a revocation checking policy.
type RevocationPolicy struct {
	// Mode is the revocation checking mode
	Mode RevocationMode
	// AllowMissing allows missing revocation info
	AllowMissing bool
	// HardFail fails validation if revocation check fails
	HardFail bool
	// PreferOCSP prefers OCSP over CRL
	PreferOCSP bool
	// MaxAge is the maximum age for revocation info
	MaxAge time.Duration
}

// RevocationMode defines how revocation checking is performed.
type RevocationMode int

const (
	// RevocationModeNone disables revocation checking
	RevocationModeNone RevocationMode = iota
	// RevocationModeSoft checks revocation but allows failures
	RevocationModeSoft
	// RevocationModeHard requires successful revocation check
	RevocationModeHard
)

// DefaultRevocationPolicy returns the default revocation policy.
func DefaultRevocationPolicy() *RevocationPolicy {
	return &RevocationPolicy{
		Mode:         RevocationModeSoft,
		AllowMissing: true,
		HardFail:     false,
		PreferOCSP:   true,
		MaxAge:       7 * 24 * time.Hour,
	}
}

// StrictRevocationPolicy returns a strict revocation policy.
func StrictRevocationPolicy() *RevocationPolicy {
	return &RevocationPolicy{
		Mode:         RevocationModeHard,
		AllowMissing: false,
		HardFail:     true,
		PreferOCSP:   true,
		MaxAge:       24 * time.Hour,
	}
}

// OCSPRequest represents an OCSP request.
type OCSPRequest struct {
	Certificate *x509.Certificate
	Issuer      *x509.Certificate
	Hash        crypto.Hash
}

// CreateOCSPRequest creates an OCSP request for a certificate.
func CreateOCSPRequest(cert, issuer *x509.Certificate, hash crypto.Hash) ([]byte, error) {
	if hash == 0 {
		hash = crypto.SHA256
	}
	return ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: hash})
}

// ParseOCSPResponse parses an OCSP response.
func ParseOCSPResponse(data []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	return ocsp.ParseResponse(data, issuer)
}

// IsOCSPGood checks if an OCSP response indicates good status.
func IsOCSPGood(resp *ocsp.Response) bool {
	return resp.Status == ocsp.Good
}

// IsOCSPRevoked checks if an OCSP response indicates revoked status.
func IsOCSPRevoked(resp *ocsp.Response) bool {
	return resp.Status == ocsp.Revoked
}

// CRLNumber returns the CRL number from a CRL.
func CRLNumber(crl *x509.RevocationList) *big.Int {
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 20}) { // cRLNumber
			var num big.Int
			if _, err := asn1.Unmarshal(ext.Value, &num); err == nil {
				return &num
			}
		}
	}
	return nil
}

// IsDeltaCRL checks if a CRL is a delta CRL.
func IsDeltaCRL(crl *x509.RevocationList) bool {
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) { // deltaCRLIndicator
			return true
		}
	}
	return false
}

// RevocationEntry represents a single revocation entry.
type RevocationEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	ReasonCode     RevocationReason
	Extensions     []CRLExtension
}

// CRLExtension represents an X.509 extension in a CRL entry.
type CRLExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// GetRevokedCertificates returns all revoked certificates from a CRL.
func GetRevokedCertificates(crl *x509.RevocationList) []RevocationEntry {
	entries := make([]RevocationEntry, 0, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		entries = append(entries, RevocationEntry{
			SerialNumber:   entry.SerialNumber,
			RevocationTime: entry.RevocationTime,
			ReasonCode:     RevocationReason(entry.ReasonCode),
		})
	}
	return entries
}

// FindRevokedCertificate searches for a certificate in a CRL.
func FindRevokedCertificate(crl *x509.RevocationList, serial *big.Int) *RevocationEntry {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return &RevocationEntry{
				SerialNumber:   entry.SerialNumber,
				RevocationTime: entry.RevocationTime,
				ReasonCode:     RevocationReason(entry.ReasonCode),
			}
		}
	}
	return nil
}

// CRLScope defines the scope of certificates covered by a CRL.
type CRLScope struct {
	// OnlyContainsUserCerts indicates the CRL only contains user certificates
	OnlyContainsUserCerts bool
	// OnlyContainsCACerts indicates the CRL only contains CA certificates
	OnlyContainsCACerts bool
	// OnlyContainsAttributeCerts indicates the CRL only contains attribute certificates
	OnlyContainsAttributeCerts bool
	// OnlySomeReasons indicates the CRL only covers some revocation reasons
	OnlySomeReasons ReasonFlags
	// IndirectCRL indicates this is an indirect CRL
	IndirectCRL bool
}

// ReasonFlags is a bitmask of revocation reasons.
type ReasonFlags uint16

const (
	ReasonFlagUnused             ReasonFlags = 1 << 0
	ReasonFlagKeyCompromise      ReasonFlags = 1 << 1
	ReasonFlagCACompromise       ReasonFlags = 1 << 2
	ReasonFlagAffiliationChanged ReasonFlags = 1 << 3
	ReasonFlagSuperseded         ReasonFlags = 1 << 4
	ReasonFlagCessationOfOp      ReasonFlags = 1 << 5
	ReasonFlagCertificateHold    ReasonFlags = 1 << 6
	ReasonFlagPrivilegeWithdrawn ReasonFlags = 1 << 7
	ReasonFlagAACompromise       ReasonFlags = 1 << 8
)

// AllReasons returns all reason flags.
func AllReasons() ReasonFlags {
	return ReasonFlagUnused | ReasonFlagKeyCompromise | ReasonFlagCACompromise |
		ReasonFlagAffiliationChanged | ReasonFlagSuperseded | ReasonFlagCessationOfOp |
		ReasonFlagCertificateHold | ReasonFlagPrivilegeWithdrawn | ReasonFlagAACompromise
}

// Contains checks if the reason flags contain a specific reason.
func (rf ReasonFlags) Contains(reason RevocationReason) bool {
	switch reason {
	case ReasonUnspecified:
		return rf&ReasonFlagUnused != 0
	case ReasonKeyCompromise:
		return rf&ReasonFlagKeyCompromise != 0
	case ReasonCACompromise:
		return rf&ReasonFlagCACompromise != 0
	case ReasonAffiliationChanged:
		return rf&ReasonFlagAffiliationChanged != 0
	case ReasonSuperseded:
		return rf&ReasonFlagSuperseded != 0
	case ReasonCessationOfOperation:
		return rf&ReasonFlagCessationOfOp != 0
	case ReasonCertificateHold:
		return rf&ReasonFlagCertificateHold != 0
	case ReasonPrivilegeWithdrawn:
		return rf&ReasonFlagPrivilegeWithdrawn != 0
	case ReasonAACompromise:
		return rf&ReasonFlagAACompromise != 0
	default:
		return false
	}
}
