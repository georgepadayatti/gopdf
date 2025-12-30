// Package ltv provides Long-Term Validation (LTV) support for certificate validation.
//
// LTV ensures that digital signatures can be validated long after they were created,
// even after certificates have expired or been revoked, by preserving all necessary
// validation data (certificates, CRLs, OCSP responses) and proof of existence.
package ltv

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Common errors
var (
	ErrNoPOE                = errors.New("no proof of existence available")
	ErrPOENotFound          = errors.New("proof of existence not found for data")
	ErrValidationTimeTooOld = errors.New("validation time is before proof of existence")
	ErrCertificateExpired   = errors.New("certificate was expired at validation time")
	ErrCertificateRevoked   = errors.New("certificate was revoked before validation time")
	ErrNoTrustAnchor        = errors.New("no trust anchor found for certificate chain")
	ErrChainBuildingFailed  = errors.New("failed to build certificate chain")
	ErrTimeSlideInvalid     = errors.New("time-slide validation failed")
	ErrInsufficientData     = errors.New("insufficient validation data for LTV")
	ErrTimestampInvalid     = errors.New("timestamp is invalid or missing")
)

// POEType represents the type of proof of existence.
type POEType int

const (
	// POETypeTimestamp indicates POE from a timestamp token
	POETypeTimestamp POEType = iota
	// POETypeSignature indicates POE from a signature
	POETypeSignature
	// POETypeCRL indicates POE from CRL thisUpdate
	POETypeCRL
	// POETypeOCSP indicates POE from OCSP producedAt
	POETypeOCSP
	// POETypeArchiveTimestamp indicates POE from an archive timestamp
	POETypeArchiveTimestamp
	// POETypeExternal indicates externally provided POE
	POETypeExternal
)

// String returns the string representation of POE type.
func (t POEType) String() string {
	switch t {
	case POETypeTimestamp:
		return "timestamp"
	case POETypeSignature:
		return "signature"
	case POETypeCRL:
		return "crl"
	case POETypeOCSP:
		return "ocsp"
	case POETypeArchiveTimestamp:
		return "archive_timestamp"
	case POETypeExternal:
		return "external"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// ProofOfExistence represents evidence that data existed at a specific time.
type ProofOfExistence struct {
	// Time is when the data was proven to exist
	Time time.Time
	// Type indicates the source of this POE
	Type POEType
	// DataHash is the hash of the data this POE applies to
	DataHash []byte
	// Description provides additional context
	Description string
	// Raw contains the raw POE data (e.g., timestamp token)
	Raw []byte
}

// IsValidAt checks if this POE is valid at the given time.
func (poe *ProofOfExistence) IsValidAt(at time.Time) bool {
	return !at.Before(poe.Time)
}

// POEManager manages proof of existence records.
type POEManager struct {
	mu   sync.RWMutex
	poes map[string][]*ProofOfExistence // keyed by hex-encoded data hash
}

// NewPOEManager creates a new POE manager.
func NewPOEManager() *POEManager {
	return &POEManager{
		poes: make(map[string][]*ProofOfExistence),
	}
}

// Add adds a proof of existence.
func (m *POEManager) Add(poe *ProofOfExistence) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%x", poe.DataHash)
	m.poes[key] = append(m.poes[key], poe)
}

// Get retrieves all POEs for a given data hash.
func (m *POEManager) Get(dataHash []byte) []*ProofOfExistence {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%x", dataHash)
	return m.poes[key]
}

// GetEarliest returns the earliest POE for a given data hash.
func (m *POEManager) GetEarliest(dataHash []byte) *ProofOfExistence {
	poes := m.Get(dataHash)
	if len(poes) == 0 {
		return nil
	}

	earliest := poes[0]
	for _, poe := range poes[1:] {
		if poe.Time.Before(earliest.Time) {
			earliest = poe
		}
	}
	return earliest
}

// GetLatest returns the latest POE for a given data hash.
func (m *POEManager) GetLatest(dataHash []byte) *ProofOfExistence {
	poes := m.Get(dataHash)
	if len(poes) == 0 {
		return nil
	}

	latest := poes[0]
	for _, poe := range poes[1:] {
		if poe.Time.After(latest.Time) {
			latest = poe
		}
	}
	return latest
}

// GetBefore returns all POEs before the given time.
func (m *POEManager) GetBefore(dataHash []byte, before time.Time) []*ProofOfExistence {
	poes := m.Get(dataHash)
	var result []*ProofOfExistence
	for _, poe := range poes {
		if poe.Time.Before(before) {
			result = append(result, poe)
		}
	}
	return result
}

// HasPOE checks if a POE exists for the data hash.
func (m *POEManager) HasPOE(dataHash []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%x", dataHash)
	return len(m.poes[key]) > 0
}

// All returns all POEs in the manager.
func (m *POEManager) All() []*ProofOfExistence {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*ProofOfExistence
	for _, poes := range m.poes {
		result = append(result, poes...)
	}
	return result
}

// ValidationTimeType represents the type of validation time reference.
type ValidationTimeType int

const (
	// ValidationTimeNow uses current time for validation
	ValidationTimeNow ValidationTimeType = iota
	// ValidationTimeSignature uses signature time
	ValidationTimeSignature
	// ValidationTimeTimestamp uses timestamp time
	ValidationTimeTimestamp
	// ValidationTimePOE uses earliest POE time
	ValidationTimePOE
	// ValidationTimeExplicit uses an explicitly provided time
	ValidationTimeExplicit
)

// String returns the string representation of validation time type.
func (t ValidationTimeType) String() string {
	switch t {
	case ValidationTimeNow:
		return "now"
	case ValidationTimeSignature:
		return "signature"
	case ValidationTimeTimestamp:
		return "timestamp"
	case ValidationTimePOE:
		return "poe"
	case ValidationTimeExplicit:
		return "explicit"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// ValidationTime represents a reference time for validation.
type ValidationTime struct {
	Type  ValidationTimeType
	Time  time.Time
	POE   *ProofOfExistence
	Label string
}

// NewValidationTimeNow creates a validation time for current time.
func NewValidationTimeNow() *ValidationTime {
	return &ValidationTime{
		Type:  ValidationTimeNow,
		Time:  time.Now(),
		Label: "current time",
	}
}

// NewValidationTimeExplicit creates a validation time for an explicit time.
func NewValidationTimeExplicit(t time.Time, label string) *ValidationTime {
	return &ValidationTime{
		Type:  ValidationTimeExplicit,
		Time:  t,
		Label: label,
	}
}

// NewValidationTimeFromPOE creates a validation time from a POE.
func NewValidationTimeFromPOE(poe *ProofOfExistence) *ValidationTime {
	return &ValidationTime{
		Type:  ValidationTimePOE,
		Time:  poe.Time,
		POE:   poe,
		Label: fmt.Sprintf("POE from %s", poe.Type),
	}
}

// LTVStatus represents the LTV validation status.
type LTVStatus int

const (
	// LTVStatusUnknown indicates unknown LTV status
	LTVStatusUnknown LTVStatus = iota
	// LTVStatusEnabled indicates LTV is enabled
	LTVStatusEnabled
	// LTVStatusDisabled indicates LTV is not available
	LTVStatusDisabled
	// LTVStatusPartial indicates partial LTV data available
	LTVStatusPartial
	// LTVStatusExpired indicates LTV data has expired
	LTVStatusExpired
)

// String returns the string representation of LTV status.
func (s LTVStatus) String() string {
	switch s {
	case LTVStatusEnabled:
		return "enabled"
	case LTVStatusDisabled:
		return "disabled"
	case LTVStatusPartial:
		return "partial"
	case LTVStatusExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// LTVInfo contains LTV validation information.
type LTVInfo struct {
	// Status is the overall LTV status
	Status LTVStatus
	// ValidationTime is the reference time used for validation
	ValidationTime *ValidationTime
	// CertificateCount is the number of certificates available
	CertificateCount int
	// CRLCount is the number of CRLs available
	CRLCount int
	// OCSPCount is the number of OCSP responses available
	OCSPCount int
	// TimestampCount is the number of timestamps available
	TimestampCount int
	// POEs are the available proofs of existence
	POEs []*ProofOfExistence
	// Errors contains any validation errors
	Errors []error
	// Warnings contains any validation warnings
	Warnings []string
}

// NewLTVInfo creates a new LTV info.
func NewLTVInfo() *LTVInfo {
	return &LTVInfo{
		Status: LTVStatusUnknown,
	}
}

// AddError adds an error to the LTV info.
func (info *LTVInfo) AddError(err error) {
	info.Errors = append(info.Errors, err)
}

// AddWarning adds a warning to the LTV info.
func (info *LTVInfo) AddWarning(warning string) {
	info.Warnings = append(info.Warnings, warning)
}

// HasErrors returns true if there are any errors.
func (info *LTVInfo) HasErrors() bool {
	return len(info.Errors) > 0
}

// IsValid returns true if LTV validation succeeded.
func (info *LTVInfo) IsValid() bool {
	return info.Status == LTVStatusEnabled && !info.HasErrors()
}

// TimeSlideResult represents the result of time-slide validation.
type TimeSlideResult struct {
	// Valid indicates if the validation succeeded
	Valid bool
	// ValidationTime is the time at which validation was performed
	ValidationTime time.Time
	// Certificate is the certificate being validated
	Certificate *x509.Certificate
	// Chain is the certificate chain
	Chain []*x509.Certificate
	// CertificateStatus indicates if the certificate was valid at the time
	CertificateStatus string
	// RevocationStatus indicates revocation status at the time
	RevocationStatus string
	// POE is the proof of existence used
	POE *ProofOfExistence
	// Errors contains any errors encountered
	Errors []error
}

// TimeSlideValidator performs time-slide validation.
type TimeSlideValidator struct {
	// TrustAnchors are the trusted CA certificates
	TrustAnchors []*x509.Certificate
	// POEManager manages proofs of existence
	POEManager *POEManager
	// AllowExpiredCerts allows validation of expired certificates
	AllowExpiredCerts bool
	// GracePeriod is the grace period after certificate expiration
	GracePeriod time.Duration
}

// NewTimeSlideValidator creates a new time-slide validator.
func NewTimeSlideValidator(anchors []*x509.Certificate) *TimeSlideValidator {
	return &TimeSlideValidator{
		TrustAnchors: anchors,
		POEManager:   NewPOEManager(),
	}
}

// ValidateAt performs time-slide validation at a specific time.
func (v *TimeSlideValidator) ValidateAt(cert *x509.Certificate, at time.Time) (*TimeSlideResult, error) {
	result := &TimeSlideResult{
		ValidationTime: at,
		Certificate:    cert,
	}

	// Check certificate validity period
	if at.Before(cert.NotBefore) {
		result.CertificateStatus = "not_yet_valid"
		result.Errors = append(result.Errors, fmt.Errorf("certificate not valid until %v", cert.NotBefore))
		return result, nil
	}

	effectiveNotAfter := cert.NotAfter
	if v.AllowExpiredCerts && v.GracePeriod > 0 {
		effectiveNotAfter = effectiveNotAfter.Add(v.GracePeriod)
	}

	if at.After(effectiveNotAfter) {
		result.CertificateStatus = "expired"
		if !v.AllowExpiredCerts {
			result.Errors = append(result.Errors, ErrCertificateExpired)
			return result, nil
		}
	} else {
		result.CertificateStatus = "valid"
	}

	// Build certificate chain
	chain, err := v.buildChain(cert, at)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return result, nil
	}
	result.Chain = chain

	// Check for POE
	poe := v.POEManager.GetEarliest(cert.Raw)
	if poe != nil && poe.Time.Before(at) {
		result.POE = poe
	}

	result.Valid = len(result.Errors) == 0
	return result, nil
}

// buildChain builds a certificate chain for validation.
func (v *TimeSlideValidator) buildChain(cert *x509.Certificate, at time.Time) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{cert}

	// Check if cert is self-signed (root)
	if cert.CheckSignatureFrom(cert) == nil {
		return chain, nil
	}

	// Try to find issuer in trust anchors
	for _, anchor := range v.TrustAnchors {
		if cert.CheckSignatureFrom(anchor) == nil {
			chain = append(chain, anchor)
			return chain, nil
		}
	}

	return nil, ErrNoTrustAnchor
}

// ValidateWithPOE performs validation using POE as the reference time.
func (v *TimeSlideValidator) ValidateWithPOE(cert *x509.Certificate, poe *ProofOfExistence) (*TimeSlideResult, error) {
	if poe == nil {
		return nil, ErrNoPOE
	}
	return v.ValidateAt(cert, poe.Time)
}

// AdESValidationLevel represents the AdES validation level.
type AdESValidationLevel int

const (
	// AdESLevelBES is basic electronic signature
	AdESLevelBES AdESValidationLevel = iota
	// AdESLevelT adds a timestamp
	AdESLevelT
	// AdESLevelC adds complete validation data references
	AdESLevelC
	// AdESLevelX adds timestamps on validation data
	AdESLevelX
	// AdESLevelXL adds complete validation data
	AdESLevelXL
	// AdESLevelA adds archival timestamps
	AdESLevelA
)

// String returns the string representation of AdES level.
func (l AdESValidationLevel) String() string {
	switch l {
	case AdESLevelBES:
		return "BES"
	case AdESLevelT:
		return "T"
	case AdESLevelC:
		return "C"
	case AdESLevelX:
		return "X"
	case AdESLevelXL:
		return "XL"
	case AdESLevelA:
		return "A"
	default:
		return fmt.Sprintf("unknown(%d)", l)
	}
}

// AdESPastValidationResult represents the result of AdES past validation.
type AdESPastValidationResult struct {
	// Valid indicates if validation succeeded
	Valid bool
	// Level is the determined AdES level
	Level AdESValidationLevel
	// ValidationTime is the control time used for validation
	ValidationTime time.Time
	// SignatureTime is when the signature was created
	SignatureTime *time.Time
	// BestPOE is the best proof of existence
	BestPOE *ProofOfExistence
	// CertificateChain is the validated certificate chain
	CertificateChain []*x509.Certificate
	// Indication is the validation indication (PASSED, FAILED, INDETERMINATE)
	Indication string
	// SubIndication provides more detail on non-PASSED results
	SubIndication string
	// Errors contains any validation errors
	Errors []error
}

// AdESPastValidator performs AdES past signature validation.
type AdESPastValidator struct {
	// TrustAnchors are trusted CA certificates
	TrustAnchors []*x509.Certificate
	// POEManager manages proofs of existence
	POEManager *POEManager
	// TimeSlideValidator for time-based validation
	TimeSlide *TimeSlideValidator
	// ControlTime is the time for validation (nil = current time)
	ControlTime *time.Time
	// AllowExpired allows validation of expired certificates using POE
	AllowExpired bool
}

// NewAdESPastValidator creates a new AdES past validator.
func NewAdESPastValidator(anchors []*x509.Certificate) *AdESPastValidator {
	poeManager := NewPOEManager()
	return &AdESPastValidator{
		TrustAnchors: anchors,
		POEManager:   poeManager,
		TimeSlide: &TimeSlideValidator{
			TrustAnchors: anchors,
			POEManager:   poeManager,
		},
		AllowExpired: true,
	}
}

// Validate performs AdES past validation on a certificate.
func (v *AdESPastValidator) Validate(cert *x509.Certificate, signatureTime *time.Time) (*AdESPastValidationResult, error) {
	result := &AdESPastValidationResult{
		SignatureTime: signatureTime,
	}

	// Determine control time
	controlTime := time.Now()
	if v.ControlTime != nil {
		controlTime = *v.ControlTime
	}
	result.ValidationTime = controlTime

	// Get best POE for the certificate
	result.BestPOE = v.POEManager.GetEarliest(cert.Raw)

	// Determine validation reference time
	validationTime := controlTime
	if result.BestPOE != nil && v.AllowExpired {
		// Use POE time if certificate might be expired
		if controlTime.After(cert.NotAfter) && result.BestPOE.Time.Before(cert.NotAfter) {
			validationTime = result.BestPOE.Time
		}
	}

	// Perform time-slide validation
	slideResult, err := v.TimeSlide.ValidateAt(cert, validationTime)
	if err != nil {
		result.Errors = append(result.Errors, err)
		result.Indication = "FAILED"
		result.SubIndication = "CHAIN_BUILDING_FAILED"
		return result, nil
	}

	result.CertificateChain = slideResult.Chain
	result.Errors = append(result.Errors, slideResult.Errors...)

	// Determine validation result
	if slideResult.Valid {
		result.Valid = true
		result.Indication = "PASSED"
		result.Level = v.determineLevel(result)
	} else {
		result.Indication = "FAILED"
		if len(slideResult.Errors) > 0 {
			result.SubIndication = "CERTIFICATE_CHAIN_INVALID"
		}
	}

	return result, nil
}

// determineLevel determines the AdES level based on available data.
func (v *AdESPastValidator) determineLevel(result *AdESPastValidationResult) AdESValidationLevel {
	// Basic level if we have a valid signature
	level := AdESLevelBES

	// T level if we have a timestamp
	if result.BestPOE != nil && result.BestPOE.Type == POETypeTimestamp {
		level = AdESLevelT
	}

	// Higher levels require additional validation data checks
	// which would be implemented based on specific requirements

	return level
}

// LTVValidator performs LTV validation.
type LTVValidator struct {
	// TrustAnchors are trusted CA certificates
	TrustAnchors []*x509.Certificate
	// POEManager manages proofs of existence
	POEManager *POEManager
	// Certificates are available intermediate certificates
	Certificates []*x509.Certificate
	// CRLs are available CRLs
	CRLs []*x509.RevocationList
	// OCSPResponses are available OCSP responses (raw)
	OCSPResponses [][]byte
	// Timestamps are available timestamp tokens (raw)
	Timestamps [][]byte
}

// NewLTVValidator creates a new LTV validator.
func NewLTVValidator(anchors []*x509.Certificate) *LTVValidator {
	return &LTVValidator{
		TrustAnchors: anchors,
		POEManager:   NewPOEManager(),
	}
}

// AddCertificate adds an intermediate certificate.
func (v *LTVValidator) AddCertificate(cert *x509.Certificate) {
	v.Certificates = append(v.Certificates, cert)
}

// AddCRL adds a CRL.
func (v *LTVValidator) AddCRL(crl *x509.RevocationList) {
	v.CRLs = append(v.CRLs, crl)
	// Add POE from CRL thisUpdate
	v.POEManager.Add(&ProofOfExistence{
		Time:        crl.ThisUpdate,
		Type:        POETypeCRL,
		DataHash:    crl.RawIssuer,
		Description: fmt.Sprintf("CRL #%s", crl.Number),
	})
}

// AddOCSPResponse adds an OCSP response.
func (v *LTVValidator) AddOCSPResponse(raw []byte) {
	v.OCSPResponses = append(v.OCSPResponses, raw)
}

// AddTimestamp adds a timestamp token.
func (v *LTVValidator) AddTimestamp(raw []byte) {
	v.Timestamps = append(v.Timestamps, raw)
}

// CheckLTV checks if a certificate has LTV enabled.
func (v *LTVValidator) CheckLTV(cert *x509.Certificate) *LTVInfo {
	info := NewLTVInfo()
	info.CertificateCount = len(v.Certificates)
	info.CRLCount = len(v.CRLs)
	info.OCSPCount = len(v.OCSPResponses)
	info.TimestampCount = len(v.Timestamps)

	// Check for POEs
	info.POEs = v.POEManager.Get(cert.Raw)

	// Determine LTV status
	if len(v.CRLs) > 0 || len(v.OCSPResponses) > 0 {
		if len(v.Timestamps) > 0 {
			info.Status = LTVStatusEnabled
		} else {
			info.Status = LTVStatusPartial
			info.AddWarning("No timestamps available for full LTV")
		}
	} else {
		info.Status = LTVStatusDisabled
		info.AddWarning("No revocation information available")
	}

	// Validate certificate chain availability
	hasChainData := false
	for _, anchor := range v.TrustAnchors {
		if cert.CheckSignatureFrom(anchor) == nil {
			hasChainData = true
			break
		}
	}
	for _, intermediate := range v.Certificates {
		if cert.CheckSignatureFrom(intermediate) == nil {
			hasChainData = true
			break
		}
	}

	if !hasChainData && info.Status == LTVStatusEnabled {
		info.Status = LTVStatusPartial
		info.AddWarning("Certificate chain may be incomplete")
	}

	return info
}

// ValidationDataSet represents a set of validation data for LTV.
type ValidationDataSet struct {
	// Certificates are intermediate and issuer certificates
	Certificates []*x509.Certificate
	// CRLs are certificate revocation lists
	CRLs []*x509.RevocationList
	// OCSPResponses are OCSP response data
	OCSPResponses [][]byte
	// Timestamps are timestamp token data
	Timestamps [][]byte
	// POEs are proofs of existence
	POEs []*ProofOfExistence
}

// NewValidationDataSet creates a new validation data set.
func NewValidationDataSet() *ValidationDataSet {
	return &ValidationDataSet{}
}

// AddCertificate adds a certificate to the set.
func (s *ValidationDataSet) AddCertificate(cert *x509.Certificate) {
	s.Certificates = append(s.Certificates, cert)
}

// AddCRL adds a CRL to the set.
func (s *ValidationDataSet) AddCRL(crl *x509.RevocationList) {
	s.CRLs = append(s.CRLs, crl)
}

// AddOCSPResponse adds an OCSP response to the set.
func (s *ValidationDataSet) AddOCSPResponse(raw []byte) {
	s.OCSPResponses = append(s.OCSPResponses, raw)
}

// AddTimestamp adds a timestamp to the set.
func (s *ValidationDataSet) AddTimestamp(raw []byte) {
	s.Timestamps = append(s.Timestamps, raw)
}

// AddPOE adds a proof of existence to the set.
func (s *ValidationDataSet) AddPOE(poe *ProofOfExistence) {
	s.POEs = append(s.POEs, poe)
}

// IsEmpty checks if the set is empty.
func (s *ValidationDataSet) IsEmpty() bool {
	return len(s.Certificates) == 0 &&
		len(s.CRLs) == 0 &&
		len(s.OCSPResponses) == 0 &&
		len(s.Timestamps) == 0
}

// Merge merges another validation data set into this one.
func (s *ValidationDataSet) Merge(other *ValidationDataSet) {
	if other == nil {
		return
	}
	s.Certificates = append(s.Certificates, other.Certificates...)
	s.CRLs = append(s.CRLs, other.CRLs...)
	s.OCSPResponses = append(s.OCSPResponses, other.OCSPResponses...)
	s.Timestamps = append(s.Timestamps, other.Timestamps...)
	s.POEs = append(s.POEs, other.POEs...)
}

// ArchivalInfo contains information about archived validation data.
type ArchivalInfo struct {
	// ArchiveTime is when the data was archived
	ArchiveTime time.Time
	// ValidationData is the archived validation data
	ValidationData *ValidationDataSet
	// ArchiveTimestamp is the archive timestamp token
	ArchiveTimestamp []byte
	// PreviousArchive links to previous archive (for chain of archives)
	PreviousArchive *ArchivalInfo
}

// NewArchivalInfo creates a new archival info.
func NewArchivalInfo(at time.Time) *ArchivalInfo {
	return &ArchivalInfo{
		ArchiveTime:    at,
		ValidationData: NewValidationDataSet(),
	}
}

// ChainLength returns the length of the archive chain.
func (a *ArchivalInfo) ChainLength() int {
	length := 1
	current := a.PreviousArchive
	for current != nil {
		length++
		current = current.PreviousArchive
	}
	return length
}

// AllValidationData returns all validation data from the archive chain.
func (a *ArchivalInfo) AllValidationData() *ValidationDataSet {
	result := NewValidationDataSet()
	current := a
	for current != nil {
		if current.ValidationData != nil {
			result.Merge(current.ValidationData)
		}
		current = current.PreviousArchive
	}
	return result
}

// RevocationFreshness represents freshness requirements for revocation data.
type RevocationFreshness struct {
	// MaxCRLAge is the maximum age for a CRL
	MaxCRLAge time.Duration
	// MaxOCSPAge is the maximum age for an OCSP response
	MaxOCSPAge time.Duration
	// RequireFresh requires fresh revocation data
	RequireFresh bool
}

// DefaultRevocationFreshness returns default freshness settings.
func DefaultRevocationFreshness() *RevocationFreshness {
	return &RevocationFreshness{
		MaxCRLAge:    7 * 24 * time.Hour, // 7 days
		MaxOCSPAge:   24 * time.Hour,     // 1 day
		RequireFresh: false,
	}
}

// StrictRevocationFreshness returns strict freshness settings.
func StrictRevocationFreshness() *RevocationFreshness {
	return &RevocationFreshness{
		MaxCRLAge:    24 * time.Hour, // 1 day
		MaxOCSPAge:   4 * time.Hour,  // 4 hours
		RequireFresh: true,
	}
}

// IsCRLFresh checks if a CRL is fresh according to these settings.
func (f *RevocationFreshness) IsCRLFresh(crl *x509.RevocationList, at time.Time) bool {
	age := at.Sub(crl.ThisUpdate)
	return age <= f.MaxCRLAge
}

// LTVPolicy defines the LTV validation policy.
type LTVPolicy struct {
	// RequireTimestamp requires a timestamp for LTV
	RequireTimestamp bool
	// RequireRevocationInfo requires revocation information
	RequireRevocationInfo bool
	// AllowExpiredWithPOE allows expired certificates if POE exists
	AllowExpiredWithPOE bool
	// RevocationFreshness defines freshness requirements
	RevocationFreshness *RevocationFreshness
	// RequireCompleteChain requires complete certificate chain
	RequireCompleteChain bool
}

// DefaultLTVPolicy returns the default LTV policy.
func DefaultLTVPolicy() *LTVPolicy {
	return &LTVPolicy{
		RequireTimestamp:      false,
		RequireRevocationInfo: true,
		AllowExpiredWithPOE:   true,
		RevocationFreshness:   DefaultRevocationFreshness(),
		RequireCompleteChain:  true,
	}
}

// StrictLTVPolicy returns a strict LTV policy.
func StrictLTVPolicy() *LTVPolicy {
	return &LTVPolicy{
		RequireTimestamp:      true,
		RequireRevocationInfo: true,
		AllowExpiredWithPOE:   true,
		RevocationFreshness:   StrictRevocationFreshness(),
		RequireCompleteChain:  true,
	}
}

// CertificateTimelineEvent represents an event in a certificate's timeline.
type CertificateTimelineEvent struct {
	Time        time.Time
	Type        string
	Description string
}

// CertificateTimeline tracks important events for a certificate.
type CertificateTimeline struct {
	Certificate *x509.Certificate
	Events      []CertificateTimelineEvent
}

// NewCertificateTimeline creates a timeline for a certificate.
func NewCertificateTimeline(cert *x509.Certificate) *CertificateTimeline {
	timeline := &CertificateTimeline{
		Certificate: cert,
	}

	// Add standard events
	timeline.AddEvent(cert.NotBefore, "validity_start", "Certificate validity period begins")
	timeline.AddEvent(cert.NotAfter, "validity_end", "Certificate validity period ends")

	return timeline
}

// AddEvent adds an event to the timeline.
func (t *CertificateTimeline) AddEvent(at time.Time, eventType, description string) {
	t.Events = append(t.Events, CertificateTimelineEvent{
		Time:        at,
		Type:        eventType,
		Description: description,
	})
}

// WasValidAt checks if the certificate was valid at a given time.
func (t *CertificateTimeline) WasValidAt(at time.Time) bool {
	return !at.Before(t.Certificate.NotBefore) && !at.After(t.Certificate.NotAfter)
}

// StatusAt returns the certificate status at a given time.
func (t *CertificateTimeline) StatusAt(at time.Time) string {
	if at.Before(t.Certificate.NotBefore) {
		return "not_yet_valid"
	}
	if at.After(t.Certificate.NotAfter) {
		return "expired"
	}
	return "valid"
}
