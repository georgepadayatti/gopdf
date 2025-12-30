// Package ltv provides Long-Term Validation (LTV) support for certificate validation.
// This file contains the ETSI EN 319 102-1 time-slide algorithm implementation.
package ltv

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ValidationPath represents a certification path being validated.
// This is a local copy to avoid circular imports with the parent certvalidator package.
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

// PKIXLen returns the PKIX path length (excludes trust anchor).
func (p *ValidationPath) PKIXLen() int {
	count := len(p.Intermediates)
	if p.EECert != nil {
		count++
	}
	return count
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

// Leaf returns the leaf certificate in the path.
func (p *ValidationPath) Leaf() *x509.Certificate {
	if p.EECert != nil {
		return p.EECert
	}
	if len(p.Intermediates) > 0 {
		return p.Intermediates[len(p.Intermediates)-1]
	}
	return p.TrustAnchor
}

// AddIntermediate adds an intermediate certificate to the path.
func (p *ValidationPath) AddIntermediate(cert *x509.Certificate) {
	p.Intermediates = append(p.Intermediates, cert)
}

// SetEECert sets the end-entity certificate.
func (p *ValidationPath) SetEECert(cert *x509.Certificate) {
	p.EECert = cert
}

// Time-slide specific errors
var (
	ErrInsufficientPOE     = errors.New("no proof of existence available at control time")
	ErrInsufficientRevinfo = errors.New("no revocation information available at control time")
	ErrDisallowedAlgorithm = errors.New("algorithm is not allowed")
	ErrTimeSlideFailure    = errors.New("time-slide validation failed")
)

// ValidationTimingInfo contains timing information for validation.
type ValidationTimingInfo struct {
	// ValidationTime is the time at which validation is performed
	ValidationTime time.Time

	// BestSignatureTime is the best known signature time
	BestSignatureTime time.Time

	// PointInTimeValidation indicates if validation is at a specific point in time
	PointInTimeValidation bool
}

// Now creates a ValidationTimingInfo for the current time.
func (ValidationTimingInfo) Now() ValidationTimingInfo {
	now := time.Now().UTC()
	return ValidationTimingInfo{
		ValidationTime:        now,
		BestSignatureTime:     now,
		PointInTimeValidation: false,
	}
}

// ValidationTimingParams contains timing parameters for validation.
type ValidationTimingParams struct {
	// TimingInfo is the timing information
	TimingInfo ValidationTimingInfo

	// TimeTolerance is the tolerance for time comparisons
	TimeTolerance time.Duration
}

// ValidationTime returns the validation time.
func (p *ValidationTimingParams) ValidationTime() time.Time {
	return p.TimingInfo.ValidationTime
}

// BestSignatureTime returns the best signature time.
func (p *ValidationTimingParams) BestSignatureTime() time.Time {
	return p.TimingInfo.BestSignatureTime
}

// PointInTimeValidation returns whether this is point-in-time validation.
func (p *ValidationTimingParams) PointInTimeValidation() bool {
	return p.TimingInfo.PointInTimeValidation
}

// RevinfoUsabilityRating indicates how usable revocation info is.
type RevinfoUsabilityRating int

const (
	// RevinfoUsabilityUnknown indicates unknown usability
	RevinfoUsabilityUnknown RevinfoUsabilityRating = iota
	// RevinfoUsabilityUsable indicates the revinfo is usable
	RevinfoUsabilityUsable
	// RevinfoUsabilityStale indicates the revinfo is stale
	RevinfoUsabilityStale
	// RevinfoUsabilityTooNew indicates the revinfo is too new (issued after signature)
	RevinfoUsabilityTooNew
	// RevinfoUsabilityExpired indicates the revinfo has expired
	RevinfoUsabilityExpired
)

// String returns the string representation.
func (r RevinfoUsabilityRating) String() string {
	switch r {
	case RevinfoUsabilityUsable:
		return "usable"
	case RevinfoUsabilityStale:
		return "stale"
	case RevinfoUsabilityTooNew:
		return "too_new"
	case RevinfoUsabilityExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// UsableAdES returns true if the rating indicates AdES usability.
func (r RevinfoUsabilityRating) UsableAdES() bool {
	return r == RevinfoUsabilityUsable
}

// RevinfoUsability contains usability assessment for revocation info.
type RevinfoUsability struct {
	// Rating is the usability rating
	Rating RevinfoUsabilityRating

	// LastUsableAt is the last time this revinfo was usable
	LastUsableAt *time.Time

	// Reason explains why the revinfo has this rating
	Reason string
}

// RevinfoContainer wraps revocation information with metadata.
type RevinfoContainer struct {
	// IssuanceDate is when the revinfo was issued
	IssuanceDate *time.Time

	// NextUpdate is when new revinfo should be available
	NextUpdate *time.Time

	// SignatureAlgorithm is the algorithm used to sign the revinfo
	SignatureAlgorithm string

	// IssuerCert is the issuer's certificate
	IssuerCert *x509.Certificate

	// Raw is the raw revinfo data
	Raw []byte

	// Type is "CRL" or "OCSP"
	Type string
}

// UsableAt checks if the revinfo is usable at the given timing params.
func (c *RevinfoContainer) UsableAt(params *ValidationTimingParams) *RevinfoUsability {
	if c.IssuanceDate == nil {
		return &RevinfoUsability{
			Rating: RevinfoUsabilityUnknown,
			Reason: "no issuance date",
		}
	}

	validationTime := params.ValidationTime()
	tolerance := params.TimeTolerance

	// Check if issued after validation time (too new)
	if c.IssuanceDate.After(validationTime.Add(tolerance)) {
		return &RevinfoUsability{
			Rating: RevinfoUsabilityTooNew,
			Reason: fmt.Sprintf("issued at %s, after validation time %s",
				c.IssuanceDate.Format(time.RFC3339),
				validationTime.Format(time.RFC3339)),
		}
	}

	// Check if expired
	if c.NextUpdate != nil && validationTime.After(c.NextUpdate.Add(tolerance)) {
		lastUsable := *c.NextUpdate
		return &RevinfoUsability{
			Rating:       RevinfoUsabilityExpired,
			LastUsableAt: &lastUsable,
			Reason: fmt.Sprintf("expired at %s",
				c.NextUpdate.Format(time.RFC3339)),
		}
	}

	return &RevinfoUsability{
		Rating: RevinfoUsabilityUsable,
		Reason: "revinfo is fresh and valid",
	}
}

// CRLOfInterest represents a CRL relevant to validation.
type CRLOfInterest struct {
	// CRL is the parsed revocation list
	CRL *x509.RevocationList

	// Container is the revinfo container
	Container *RevinfoContainer

	// ProvPaths are the provisioning paths (issuer chains)
	ProvPaths []*CRLPath

	// IssuanceDate is when the CRL was issued
	IssuanceDate *time.Time
}

// CRLPath represents a path to validate a CRL issuer.
type CRLPath struct {
	// Path is the validation path
	Path *ValidationPath

	// Delta is the delta CRL if applicable
	Delta *x509.RevocationList
}

// OCSPResponseOfInterest represents an OCSP response relevant to validation.
type OCSPResponseOfInterest struct {
	// OCSPResponse is the container for the response
	OCSPResponse *RevinfoContainer

	// ProvPath is the provisioning path (responder chain)
	ProvPath *ValidationPath

	// IssuanceDate is when the response was produced
	IssuanceDate *time.Time
}

// AlgorithmConstraint represents a constraint on algorithm usage.
type AlgorithmConstraint struct {
	// Allowed indicates if the algorithm is allowed
	Allowed bool

	// NotAllowedAfter is when the algorithm becomes disallowed
	NotAllowedAfter *time.Time

	// FailureReason explains why the algorithm is not allowed
	FailureReason string
}

// AlgorithmUsagePolicy defines policies for algorithm usage over time.
type AlgorithmUsagePolicy interface {
	// SignatureAlgorithmAllowed checks if a signature algorithm is allowed
	// at the given time with the given public key.
	SignatureAlgorithmAllowed(algorithm string, at time.Time, publicKey interface{}) *AlgorithmConstraint
}

// DefaultAlgorithmUsagePolicy is the default algorithm policy.
type DefaultAlgorithmUsagePolicy struct {
	// BannedAlgorithms maps algorithm names to their ban date (nil = always allowed)
	BannedAlgorithms map[string]*time.Time

	// MinKeySize maps algorithm types to minimum key sizes
	MinKeySize map[string]int
}

// NewDefaultAlgorithmUsagePolicy creates a default algorithm policy.
func NewDefaultAlgorithmUsagePolicy() *DefaultAlgorithmUsagePolicy {
	// SHA-1 was deprecated in 2017 for signatures
	sha1BanDate := time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)

	return &DefaultAlgorithmUsagePolicy{
		BannedAlgorithms: map[string]*time.Time{
			"SHA1-RSA":   &sha1BanDate,
			"SHA1-ECDSA": &sha1BanDate,
			"MD5-RSA":    nil, // Always banned
			"MD2-RSA":    nil, // Always banned
		},
		MinKeySize: map[string]int{
			"RSA":   2048,
			"ECDSA": 256,
		},
	}
}

// SignatureAlgorithmAllowed checks if a signature algorithm is allowed.
func (p *DefaultAlgorithmUsagePolicy) SignatureAlgorithmAllowed(algorithm string, at time.Time, publicKey interface{}) *AlgorithmConstraint {
	// Check if algorithm is banned
	if banDate, exists := p.BannedAlgorithms[algorithm]; exists {
		if banDate == nil {
			// Always banned
			return &AlgorithmConstraint{
				Allowed:       false,
				FailureReason: fmt.Sprintf("algorithm %s is permanently banned", algorithm),
			}
		}
		if at.After(*banDate) {
			return &AlgorithmConstraint{
				Allowed:         false,
				NotAllowedAfter: banDate,
				FailureReason:   fmt.Sprintf("algorithm %s banned after %s", algorithm, banDate.Format(time.RFC3339)),
			}
		}
	}

	return &AlgorithmConstraint{
		Allowed: true,
	}
}

// RevocationCheckingRule defines how revocation checking should be performed.
type RevocationCheckingRule struct {
	// OCSPRelevant indicates if OCSP should be checked
	OCSPRelevant bool

	// CRLRelevant indicates if CRLs should be checked
	CRLRelevant bool

	// RequireRevocationInfo indicates if revocation info is required
	RequireRevocationInfo bool

	// AllowNoRevCheck allows certificates with OCSP noCheck extension
	AllowNoRevCheck bool
}

// DefaultRevocationCheckingRule returns the default checking rule.
func DefaultRevocationCheckingRule() *RevocationCheckingRule {
	return &RevocationCheckingRule{
		OCSPRelevant:          true,
		CRLRelevant:           true,
		RequireRevocationInfo: true,
		AllowNoRevCheck:       true,
	}
}

// RevocationCheckingPolicy defines rules for different certificate types.
type RevocationCheckingPolicy struct {
	// EECertificateRule is for end-entity certificates
	EECertificateRule *RevocationCheckingRule

	// IntermediateCACertRule is for intermediate CA certificates
	IntermediateCACertRule *RevocationCheckingRule
}

// DefaultRevocationCheckingPolicy returns the default policy.
func DefaultRevocationCheckingPolicy() *RevocationCheckingPolicy {
	return &RevocationCheckingPolicy{
		EECertificateRule:      DefaultRevocationCheckingRule(),
		IntermediateCACertRule: DefaultRevocationCheckingRule(),
	}
}

// CertRevTrustPolicy combines revocation checking settings.
type CertRevTrustPolicy struct {
	// RevocationCheckingPolicy defines the checking rules
	RevocationCheckingPolicy *RevocationCheckingPolicy

	// FreshnessPolicy defines freshness requirements
	FreshnessPolicy *RevocationFreshness
}

// DefaultCertRevTrustPolicy returns the default policy.
func DefaultCertRevTrustPolicy() *CertRevTrustPolicy {
	return &CertRevTrustPolicy{
		RevocationCheckingPolicy: DefaultRevocationCheckingPolicy(),
		FreshnessPolicy:          DefaultRevocationFreshness(),
	}
}

// TimeSlideContext holds context for the time-slide algorithm.
type TimeSlideContext struct {
	// POEManager manages proofs of existence
	POEManager *POEManager

	// RevTrustPolicy is the revocation trust policy
	RevTrustPolicy *CertRevTrustPolicy

	// AlgoPolicy is the algorithm usage policy
	AlgoPolicy AlgorithmUsagePolicy

	// TimeTolerance is the time tolerance for comparisons
	TimeTolerance time.Duration

	// CRLs are available CRLs
	CRLs []*CRLOfInterest

	// OCSPs are available OCSP responses
	OCSPs []*OCSPResponseOfInterest

	// ProcessedCerts tracks certificates already processed (to prevent cycles)
	ProcessedCerts map[string]bool

	// ProcessedPaths tracks paths already processed
	ProcessedPaths map[string]bool
}

// NewTimeSlideContext creates a new time-slide context.
func NewTimeSlideContext(poeManager *POEManager) *TimeSlideContext {
	if poeManager == nil {
		poeManager = NewPOEManager()
	}
	return &TimeSlideContext{
		POEManager:     poeManager,
		RevTrustPolicy: DefaultCertRevTrustPolicy(),
		AlgoPolicy:     NewDefaultAlgorithmUsagePolicy(),
		TimeTolerance:  time.Minute,
		ProcessedCerts: make(map[string]bool),
		ProcessedPaths: make(map[string]bool),
	}
}

// TimeSlideInput contains input for the time-slide algorithm.
type TimeSlideInput struct {
	// Path is the validation path
	Path *ValidationPath

	// InitControlTime is the initial control time
	InitControlTime time.Time

	// Context is the time-slide context
	Context *TimeSlideContext
}

// TimeSlideOutput contains output from the time-slide algorithm.
type TimeSlideOutput struct {
	// ControlTime is the resulting control time
	ControlTime time.Time

	// Success indicates if time-slide succeeded
	Success bool

	// Errors contains any errors encountered
	Errors []error

	// CertificateStatuses maps certificates to their status at control time
	CertificateStatuses map[string]string

	// RevinfoUsed lists revocation info that was used
	RevinfoUsed []string
}

// TimeSlide executes the ETSI EN 319 102-1 time-slide algorithm.
//
// The time-slide algorithm validates a certification path by "sliding" backwards
// in time from the initial control time to find a point where the entire path
// was valid. It considers:
// - Certificate validity periods
// - Revocation status
// - Algorithm constraints
// - Proof of existence
//
// The algorithm returns the resulting control time, which may be earlier than
// the initial control time if constraints were found.
func TimeSlide(input *TimeSlideInput) (*TimeSlideOutput, error) {
	if input == nil || input.Path == nil {
		return nil, errors.New("invalid input: path is required")
	}

	output := &TimeSlideOutput{
		ControlTime:         input.InitControlTime,
		Success:             true,
		CertificateStatuses: make(map[string]string),
		RevinfoUsed:         make([]string, 0),
	}

	// Empty path is trivially valid
	if input.Path.PKIXLen() == 0 {
		return output, nil
	}

	// Process path from root to leaf
	controlTime, err := timeSlideInternal(input, output)
	if err != nil {
		output.Success = false
		output.Errors = append(output.Errors, err)
		return output, nil
	}

	output.ControlTime = controlTime
	return output, nil
}

// timeSlideInternal is the internal recursive implementation.
func timeSlideInternal(input *TimeSlideInput, output *TimeSlideOutput) (time.Time, error) {
	ctx := input.Context
	path := input.Path
	controlTime := input.InitControlTime
	poeManager := ctx.POEManager

	// Get all certificates in the path (excluding trust anchor for revocation check)
	certs := path.AllCerts()
	if len(certs) == 0 {
		return controlTime, nil
	}

	// Process each certificate from root towards leaf
	for i, cert := range certs {
		isEE := (i == len(certs)-1)
		certKey := fmt.Sprintf("%x", cert.Raw[:32]) // Use first 32 bytes as key

		// Skip if already processed (cycle detection)
		if ctx.ProcessedCerts[certKey] {
			continue
		}
		ctx.ProcessedCerts[certKey] = true

		// Check POE for certificate
		poe := poeManager.GetEarliest(cert.Raw)
		if poe != nil && poe.Time.After(controlTime) {
			return controlTime, fmt.Errorf("%w: certificate %s has POE at %s, after control time %s",
				ErrInsufficientPOE,
				cert.Subject.CommonName,
				poe.Time.Format(time.RFC3339),
				controlTime.Format(time.RFC3339))
		}

		// Skip trust anchor for revocation checking
		if i == 0 && path.TrustAnchor != nil && cert == path.TrustAnchor {
			output.CertificateStatuses[certKey] = "trust_anchor"
			continue
		}

		// Check for OCSP noCheck extension (responder certificates)
		if hasOCSPNoCheck(cert) && ctx.RevTrustPolicy.RevocationCheckingPolicy.EECertificateRule.AllowNoRevCheck {
			output.CertificateStatuses[certKey] = "ocsp_no_check"
			continue
		}

		// Determine which revocation checking rule to use
		var checkingRule *RevocationCheckingRule
		if isEE {
			checkingRule = ctx.RevTrustPolicy.RevocationCheckingPolicy.EECertificateRule
		} else {
			checkingRule = ctx.RevTrustPolicy.RevocationCheckingPolicy.IntermediateCACertRule
		}

		// Gather revocation info for this certificate
		revoked, revTime, newControlTime, err := checkRevocationAtTime(cert, path, ctx, controlTime, checkingRule, output)
		if err != nil {
			// No revocation info found
			if checkingRule.RequireRevocationInfo {
				return controlTime, fmt.Errorf("%w: %v", ErrInsufficientRevinfo, err)
			}
			output.CertificateStatuses[certKey] = "no_revinfo"
			continue
		}

		if revoked {
			output.CertificateStatuses[certKey] = fmt.Sprintf("revoked at %s", revTime.Format(time.RFC3339))
			// Update control time to revocation time
			if revTime.Before(controlTime) {
				controlTime = *revTime
			}
		} else {
			output.CertificateStatuses[certKey] = "good"
		}

		// Update control time if revinfo pushed it back
		if newControlTime.Before(controlTime) {
			controlTime = newControlTime
		}

		// Apply algorithm policy for certificate signature
		if ctx.AlgoPolicy != nil && i > 0 {
			issuer := certs[i-1]
			controlTime, err = applyAlgorithmPolicy(ctx.AlgoPolicy, cert.SignatureAlgorithm.String(), controlTime, issuer.PublicKey)
			if err != nil {
				return controlTime, err
			}
		}
	}

	return controlTime, nil
}

// checkRevocationAtTime checks revocation status at the given control time.
func checkRevocationAtTime(
	cert *x509.Certificate,
	path *ValidationPath,
	ctx *TimeSlideContext,
	controlTime time.Time,
	rule *RevocationCheckingRule,
	output *TimeSlideOutput,
) (revoked bool, revTime *time.Time, newControlTime time.Time, err error) {
	newControlTime = controlTime
	var foundRevinfo bool

	// Check CRLs if relevant
	if rule.CRLRelevant {
		for _, crlInterest := range ctx.CRLs {
			if crlInterest.CRL == nil || crlInterest.IssuanceDate == nil {
				continue
			}

			// Skip CRLs issued after control time
			if crlInterest.IssuanceDate.After(controlTime) {
				continue
			}

			// Check POE for CRL
			if ctx.POEManager != nil {
				crlPOE := ctx.POEManager.GetEarliest(crlInterest.CRL.Raw)
				if crlPOE != nil && crlPOE.Time.After(controlTime) {
					continue
				}
			}

			// Check if certificate is in CRL
			for _, entry := range crlInterest.CRL.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					revTime = &entry.RevocationTime
					revoked = true
					output.RevinfoUsed = append(output.RevinfoUsed,
						fmt.Sprintf("CRL issued %s", crlInterest.IssuanceDate.Format(time.RFC3339)))

					if revTime.Before(newControlTime) {
						newControlTime = *revTime
					}
					break
				}
			}

			foundRevinfo = true

			// Update control time based on CRL freshness if not revoked
			if !revoked && crlInterest.Container != nil {
				params := &ValidationTimingParams{
					TimingInfo: ValidationTimingInfo{
						ValidationTime:        controlTime,
						BestSignatureTime:     controlTime,
						PointInTimeValidation: true,
					},
					TimeTolerance: ctx.TimeTolerance,
				}
				usability := crlInterest.Container.UsableAt(params)
				if !usability.Rating.UsableAdES() && usability.LastUsableAt != nil {
					if usability.LastUsableAt.Before(newControlTime) {
						newControlTime = *usability.LastUsableAt
					}
				}
			}
		}
	}

	// Check OCSP responses if relevant
	if rule.OCSPRelevant {
		for _, ocspInterest := range ctx.OCSPs {
			if ocspInterest.OCSPResponse == nil || ocspInterest.IssuanceDate == nil {
				continue
			}

			// Skip OCSP responses issued after control time
			if ocspInterest.IssuanceDate.After(controlTime) {
				continue
			}

			// Check POE for OCSP response
			if ctx.POEManager != nil && ocspInterest.OCSPResponse.Raw != nil {
				ocspPOE := ctx.POEManager.GetEarliest(ocspInterest.OCSPResponse.Raw)
				if ocspPOE != nil && ocspPOE.Time.After(controlTime) {
					continue
				}
			}

			foundRevinfo = true
			output.RevinfoUsed = append(output.RevinfoUsed,
				fmt.Sprintf("OCSP issued %s", ocspInterest.IssuanceDate.Format(time.RFC3339)))

			// Update control time based on OCSP freshness
			params := &ValidationTimingParams{
				TimingInfo: ValidationTimingInfo{
					ValidationTime:        controlTime,
					BestSignatureTime:     controlTime,
					PointInTimeValidation: true,
				},
				TimeTolerance: ctx.TimeTolerance,
			}
			usability := ocspInterest.OCSPResponse.UsableAt(params)
			if !usability.Rating.UsableAdES() && usability.LastUsableAt != nil {
				if usability.LastUsableAt.Before(newControlTime) {
					newControlTime = *usability.LastUsableAt
				}
			}
		}
	}

	if !foundRevinfo {
		err = fmt.Errorf("no revocation info found for certificate %s", cert.Subject.CommonName)
	}

	return
}

// applyAlgorithmPolicy applies algorithm policy and returns updated control time.
func applyAlgorithmPolicy(
	policy AlgorithmUsagePolicy,
	algorithm string,
	controlTime time.Time,
	publicKey interface{},
) (time.Time, error) {
	constraint := policy.SignatureAlgorithmAllowed(algorithm, controlTime, publicKey)

	if !constraint.Allowed {
		if constraint.NotAllowedAfter != nil {
			// Slide control time back to when algorithm was allowed
			if constraint.NotAllowedAfter.Before(controlTime) {
				return *constraint.NotAllowedAfter, nil
			}
		} else {
			// Algorithm is completely banned
			return controlTime, fmt.Errorf("%w: %s", ErrDisallowedAlgorithm, constraint.FailureReason)
		}
	}

	return controlTime, nil
}

// hasOCSPNoCheck checks if a certificate has the OCSP noCheck extension.
func hasOCSPNoCheck(cert *x509.Certificate) bool {
	// OID for id-pkix-ocsp-nocheck is 1.3.6.1.5.5.7.48.1.5
	ocspNoCheckOID := []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

	for _, ext := range cert.Extensions {
		if len(ext.Id) == len(ocspNoCheckOID) {
			match := true
			for i, v := range ext.Id {
				if v != ocspNoCheckOID[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// GatherPrimaFacieRevinfo gathers potentially relevant revocation information
// for the leaf certificate of a validation path.
func GatherPrimaFacieRevinfo(
	path *ValidationPath,
	ctx *TimeSlideContext,
	controlTime time.Time,
	rule *RevocationCheckingRule,
) ([]*CRLOfInterest, []*OCSPResponseOfInterest) {
	var crls []*CRLOfInterest
	var ocsps []*OCSPResponseOfInterest

	if path == nil || path.Leaf() == nil {
		return crls, ocsps
	}

	// Filter CRLs relevant to this path
	if rule.CRLRelevant {
		for _, crl := range ctx.CRLs {
			if crl.IssuanceDate != nil && !crl.IssuanceDate.After(controlTime) {
				crls = append(crls, crl)
			}
		}
	}

	// Filter OCSP responses relevant to this path
	if rule.OCSPRelevant {
		for _, ocsp := range ctx.OCSPs {
			if ocsp.IssuanceDate != nil && !ocsp.IssuanceDate.After(controlTime) {
				ocsps = append(ocsps, ocsp)
			}
		}
	}

	return crls, ocsps
}

// TimeSlideWithDefaults runs time-slide with default settings.
func TimeSlideWithDefaults(path *ValidationPath, initControlTime time.Time, poeManager *POEManager) (*TimeSlideOutput, error) {
	ctx := NewTimeSlideContext(poeManager)

	input := &TimeSlideInput{
		Path:            path,
		InitControlTime: initControlTime,
		Context:         ctx,
	}

	return TimeSlide(input)
}

// AddCRL adds a CRL to the time-slide context.
func (ctx *TimeSlideContext) AddCRL(crl *x509.RevocationList, issuer *x509.Certificate) {
	issuanceDate := crl.ThisUpdate
	container := &RevinfoContainer{
		IssuanceDate: &issuanceDate,
		NextUpdate:   &crl.NextUpdate,
		IssuerCert:   issuer,
		Raw:          crl.Raw,
		Type:         "CRL",
	}

	interest := &CRLOfInterest{
		CRL:          crl,
		Container:    container,
		IssuanceDate: &issuanceDate,
	}

	ctx.CRLs = append(ctx.CRLs, interest)
}

// AddOCSPResponse adds an OCSP response to the time-slide context.
func (ctx *TimeSlideContext) AddOCSPResponse(raw []byte, producedAt time.Time, nextUpdate *time.Time, responderCert *x509.Certificate) {
	container := &RevinfoContainer{
		IssuanceDate: &producedAt,
		NextUpdate:   nextUpdate,
		IssuerCert:   responderCert,
		Raw:          raw,
		Type:         "OCSP",
	}

	interest := &OCSPResponseOfInterest{
		OCSPResponse: container,
		IssuanceDate: &producedAt,
	}

	ctx.OCSPs = append(ctx.OCSPs, interest)
}

// PastValidatePrecheckResult contains the result of past validation precheck.
type PastValidatePrecheckResult struct {
	// Passed indicates if precheck passed
	Passed bool

	// FailureReason explains why precheck failed
	FailureReason string

	// SuggestedControlTime is the suggested control time if precheck suggests one
	SuggestedControlTime *time.Time
}

// PastValidatePrecheck performs preliminary checks before past validation.
// This implements a simplified version of the ETSI EN 319 102-1 past validation precheck.
func PastValidatePrecheck(
	path *ValidationPath,
	controlTime time.Time,
	poeManager *POEManager,
) (*PastValidatePrecheckResult, error) {
	result := &PastValidatePrecheckResult{Passed: true}

	if path == nil {
		return nil, errors.New("path is required")
	}

	// Check that all certificates have POE before control time
	for _, cert := range path.AllCerts() {
		poe := poeManager.GetEarliest(cert.Raw)
		if poe != nil && poe.Time.After(controlTime) {
			result.Passed = false
			result.FailureReason = fmt.Sprintf(
				"certificate %s has POE at %s, after control time %s",
				cert.Subject.CommonName,
				poe.Time.Format(time.RFC3339),
				controlTime.Format(time.RFC3339),
			)
			suggested := poe.Time
			result.SuggestedControlTime = &suggested
			return result, nil
		}
	}

	// Check that leaf certificate validity includes some time before control time
	leaf := path.Leaf()
	if leaf != nil {
		if controlTime.Before(leaf.NotBefore) {
			result.Passed = false
			result.FailureReason = fmt.Sprintf(
				"control time %s is before certificate validity start %s",
				controlTime.Format(time.RFC3339),
				leaf.NotBefore.Format(time.RFC3339),
			)
			return result, nil
		}
	}

	return result, nil
}
