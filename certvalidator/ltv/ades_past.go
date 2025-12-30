// Package ltv provides Long-Term Validation (LTV) support for certificate validation.
// This file contains the ETSI EN 319 102-1 past certificate validation algorithm implementation.
package ltv

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// AdES past validation specific errors
var (
	ErrPastValidatePrecheckFailure = errors.New("past validation precheck failed")
	ErrEmptyValidityIntersection   = errors.New("validity period intersection is empty")
	ErrPathValidationFailed        = errors.New("path validation failed during past validation")
)

// CertValidationPolicySpec defines the certificate validation policy specification.
type CertValidationPolicySpec struct {
	// RevInfoPolicy is the revocation information policy
	RevInfoPolicy *CertRevTrustPolicy

	// AlgorithmUsagePolicy is the algorithm usage policy
	AlgorithmUsagePolicy AlgorithmUsagePolicy

	// TimeTolerance is the tolerance for time comparisons
	TimeTolerance time.Duration

	// PKIXValidationParams contains additional PKIX validation parameters
	PKIXValidationParams *PKIXValidationParams

	// TrustAnchors are the trusted root certificates
	TrustAnchors []*x509.Certificate

	// AllowFetching indicates if remote fetching is allowed
	AllowFetching bool
}

// DefaultCertValidationPolicySpec creates a default policy specification.
func DefaultCertValidationPolicySpec() *CertValidationPolicySpec {
	return &CertValidationPolicySpec{
		RevInfoPolicy:        DefaultCertRevTrustPolicy(),
		AlgorithmUsagePolicy: NewDefaultAlgorithmUsagePolicy(),
		TimeTolerance:        time.Second,
		PKIXValidationParams: DefaultPKIXValidationParams(),
		AllowFetching:        false,
	}
}

// PKIXValidationParams contains PKIX validation parameters.
type PKIXValidationParams struct {
	// InitialPolicySet is the initial policy set for policy processing
	InitialPolicySet []string

	// InitialPolicyMappingInhibit indicates if policy mapping is initially inhibited
	InitialPolicyMappingInhibit bool

	// InitialExplicitPolicy indicates if explicit policy is initially required
	InitialExplicitPolicy bool

	// InitialAnyPolicyInhibit indicates if anyPolicy is initially inhibited
	InitialAnyPolicyInhibit bool

	// UserConstrainedPolicySet is the user-constrained policy set
	UserConstrainedPolicySet []string
}

// DefaultPKIXValidationParams creates default PKIX validation parameters.
func DefaultPKIXValidationParams() *PKIXValidationParams {
	return &PKIXValidationParams{
		InitialPolicySet:            []string{"2.5.29.32.0"}, // anyPolicy
		InitialPolicyMappingInhibit: false,
		InitialExplicitPolicy:       false,
		InitialAnyPolicyInhibit:     false,
	}
}

// ValidationDataHandlers holds handlers for validation data management.
type ValidationDataHandlers struct {
	// RevInfoManager manages revocation information
	RevInfoManager *RevInfoManager

	// POEManager manages proofs of existence
	POEManager *POEManager

	// CertificateStore stores intermediate certificates
	CertificateStore []*x509.Certificate
}

// NewValidationDataHandlers creates new validation data handlers.
func NewValidationDataHandlers() *ValidationDataHandlers {
	return &ValidationDataHandlers{
		RevInfoManager:   NewRevInfoManager(),
		POEManager:       NewPOEManager(),
		CertificateStore: make([]*x509.Certificate, 0),
	}
}

// RevInfoManager manages revocation information for validation.
type RevInfoManager struct {
	// CRLs are available CRLs
	CRLs []*x509.RevocationList

	// OCSPResponses are available OCSP responses (raw)
	OCSPResponses [][]byte

	// POEManager for tracking proof of existence
	POEManager *POEManager
}

// NewRevInfoManager creates a new revocation info manager.
func NewRevInfoManager() *RevInfoManager {
	return &RevInfoManager{
		CRLs:          make([]*x509.RevocationList, 0),
		OCSPResponses: make([][]byte, 0),
		POEManager:    NewPOEManager(),
	}
}

// AddCRL adds a CRL to the manager.
func (m *RevInfoManager) AddCRL(crl *x509.RevocationList) {
	m.CRLs = append(m.CRLs, crl)
	// Add POE from CRL thisUpdate
	m.POEManager.Add(&ProofOfExistence{
		Time:        crl.ThisUpdate,
		Type:        POETypeCRL,
		DataHash:    crl.Raw,
		Description: fmt.Sprintf("CRL #%s", crl.Number),
	})
}

// AddOCSPResponse adds an OCSP response to the manager.
func (m *RevInfoManager) AddOCSPResponse(raw []byte, producedAt time.Time) {
	m.OCSPResponses = append(m.OCSPResponses, raw)
	// Add POE from OCSP producedAt
	m.POEManager.Add(&ProofOfExistence{
		Time:        producedAt,
		Type:        POETypeOCSP,
		DataHash:    raw,
		Description: "OCSP response",
	})
}

// PastValidateInput contains input for the past validation algorithm.
type PastValidateInput struct {
	// Path is the validation path to validate
	Path *ValidationPath

	// PolicySpec is the validation policy specification
	PolicySpec *CertValidationPolicySpec

	// DataHandlers provides validation data (revinfo, certificates, etc.)
	DataHandlers *ValidationDataHandlers

	// InitControlTime is the initial control time (nil = current time)
	InitControlTime *time.Time

	// BestSignatureTime is the usage time for freshness computations
	BestSignatureTime *time.Time
}

// PastValidateOutput contains output from the past validation algorithm.
type PastValidateOutput struct {
	// ControlTime is the resulting control time from time-slide
	ControlTime time.Time

	// Valid indicates if validation succeeded
	Valid bool

	// ValidationPath is the validated path
	ValidationPath *ValidationPath

	// Indication is the validation indication (PASSED, FAILED, INDETERMINATE)
	Indication string

	// SubIndication provides more detail on non-PASSED results
	SubIndication string

	// Errors contains any validation errors
	Errors []error

	// PrecheckPassed indicates if the precheck passed
	PrecheckPassed bool

	// TimeSlideSucceeded indicates if time-slide succeeded
	TimeSlideSucceeded bool
}

// pastValidatePrecheck performs preliminary validation before past validation.
// This validates the path at a known-good time without revocation or algorithm checks.
func pastValidatePrecheck(path *ValidationPath, policySpec *CertValidationPolicySpec) error {
	if path == nil || path.PKIXLen() == 0 {
		return nil // Empty paths trivially pass
	}

	// Get all certificates excluding trust anchor
	certs := path.AllCerts()
	if len(certs) == 0 {
		return nil
	}

	// Shell model: intersect the validity windows of all certs
	var lowerBound, upperBound time.Time
	first := true

	for _, cert := range certs {
		if first {
			lowerBound = cert.NotBefore
			upperBound = cert.NotAfter
			first = false
		} else {
			if cert.NotBefore.After(lowerBound) {
				lowerBound = cert.NotBefore
			}
			if cert.NotAfter.Before(upperBound) {
				upperBound = cert.NotAfter
			}
		}
	}

	// Check if intersection is valid
	if !lowerBound.Before(upperBound) {
		return fmt.Errorf("%w: lower bound %s >= upper bound %s",
			ErrEmptyValidityIntersection,
			lowerBound.Format(time.RFC3339),
			upperBound.Format(time.RFC3339))
	}

	// Validate path at the upper bound (latest time all certs are valid)
	// with no revocation checking and accepting all algorithms
	err := validatePathBasic(path, upperBound, policySpec.TrustAnchors)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPastValidatePrecheckFailure, err)
	}

	return nil
}

// validatePathBasic performs basic path validation (signature chain only).
func validatePathBasic(path *ValidationPath, at time.Time, trustAnchors []*x509.Certificate) error {
	certs := path.AllCerts()
	if len(certs) == 0 {
		return nil
	}

	// Check validity periods
	for _, cert := range certs {
		if at.Before(cert.NotBefore) {
			return fmt.Errorf("certificate %s not yet valid at %s",
				cert.Subject.CommonName, at.Format(time.RFC3339))
		}
		if at.After(cert.NotAfter) {
			return fmt.Errorf("certificate %s expired at %s",
				cert.Subject.CommonName, at.Format(time.RFC3339))
		}
	}

	// Verify signature chain
	for i := len(certs) - 1; i > 0; i-- {
		cert := certs[i]
		issuer := certs[i-1]

		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("signature verification failed for %s: %w",
				cert.Subject.CommonName, err)
		}
	}

	// Check trust anchor
	if path.TrustAnchor != nil {
		// Verify trust anchor is in the trusted set
		found := false
		for _, anchor := range trustAnchors {
			if anchor.Equal(path.TrustAnchor) {
				found = true
				break
			}
		}
		if !found && len(trustAnchors) > 0 {
			// Self-signed check as fallback
			if path.TrustAnchor.CheckSignatureFrom(path.TrustAnchor) != nil {
				return fmt.Errorf("trust anchor %s not found in trusted set",
					path.TrustAnchor.Subject.CommonName)
			}
		}
	}

	return nil
}

// PastValidate executes the ETSI EN 319 102-1 past certificate validation algorithm.
//
// The algorithm performs a full point-in-time reevaluation of the path at the
// control time mandated by the specification. This includes:
// 1. Precheck - validates the path at a known-good time without revocation checks
// 2. Time-slide - determines the control time based on revocation info and algorithm constraints
// 3. Final validation - validates the path at the determined control time
//
// Returns the control time at which the certificate was known to be valid.
func PastValidate(input *PastValidateInput) (*PastValidateOutput, error) {
	if input == nil {
		return nil, errors.New("input is required")
	}

	output := &PastValidateOutput{
		ValidationPath: input.Path,
	}

	if input.Path == nil {
		return nil, errors.New("path is required")
	}

	if input.PolicySpec == nil {
		input.PolicySpec = DefaultCertValidationPolicySpec()
	}

	if input.DataHandlers == nil {
		input.DataHandlers = NewValidationDataHandlers()
	}

	// Step 1: Precheck
	if input.Path.PKIXLen() > 0 {
		err := pastValidatePrecheck(input.Path, input.PolicySpec)
		if err != nil {
			output.Valid = false
			output.Indication = "FAILED"
			output.SubIndication = "PAST_VALIDATE_PRECHECK_FAILURE"
			output.Errors = append(output.Errors, err)
			return output, nil
		}
	}
	output.PrecheckPassed = true

	// Step 2: Time-slide
	initControlTime := time.Now().UTC()
	if input.InitControlTime != nil {
		initControlTime = *input.InitControlTime
	}

	// Build time-slide context from data handlers
	tsContext := NewTimeSlideContext(input.DataHandlers.POEManager)
	tsContext.RevTrustPolicy = input.PolicySpec.RevInfoPolicy
	tsContext.AlgoPolicy = input.PolicySpec.AlgorithmUsagePolicy
	tsContext.TimeTolerance = input.PolicySpec.TimeTolerance

	// Add CRLs from data handlers
	if input.DataHandlers.RevInfoManager != nil {
		for _, crl := range input.DataHandlers.RevInfoManager.CRLs {
			tsContext.AddCRL(crl, nil)
		}
	}

	tsInput := &TimeSlideInput{
		Path:            input.Path,
		InitControlTime: initControlTime,
		Context:         tsContext,
	}

	tsOutput, err := TimeSlide(tsInput)
	if err != nil {
		output.Valid = false
		output.Indication = "FAILED"
		output.SubIndication = "TIME_SLIDE_FAILURE"
		output.Errors = append(output.Errors, fmt.Errorf("%w: %v", ErrTimeSlideFailure, err))
		return output, nil
	}

	if !tsOutput.Success {
		output.Valid = false
		output.Indication = "FAILED"
		output.SubIndication = "TIME_SLIDE_FAILURE"
		output.Errors = append(output.Errors, tsOutput.Errors...)
		return output, nil
	}

	output.TimeSlideSucceeded = true
	output.ControlTime = tsOutput.ControlTime

	// Step 3: Final validation at control time
	bestSigTime := output.ControlTime
	if input.BestSignatureTime != nil {
		bestSigTime = *input.BestSignatureTime
	}

	err = validatePathAtTime(input.Path, output.ControlTime, bestSigTime, input.PolicySpec, input.DataHandlers)
	if err != nil {
		output.Valid = false
		output.Indication = "FAILED"
		output.SubIndication = "PATH_VALIDATION_FAILED"
		output.Errors = append(output.Errors, fmt.Errorf("%w: %v", ErrPathValidationFailed, err))
		return output, nil
	}

	output.Valid = true
	output.Indication = "PASSED"
	return output, nil
}

// validatePathAtTime validates the path at a specific point in time.
func validatePathAtTime(
	path *ValidationPath,
	validationTime, bestSignatureTime time.Time,
	policySpec *CertValidationPolicySpec,
	dataHandlers *ValidationDataHandlers,
) error {
	if path == nil {
		return errors.New("path is nil")
	}

	certs := path.AllCerts()
	if len(certs) == 0 {
		return nil
	}

	// Check validity periods
	for _, cert := range certs {
		if validationTime.Before(cert.NotBefore) {
			return fmt.Errorf("certificate %s not yet valid at %s",
				cert.Subject.CommonName, validationTime.Format(time.RFC3339))
		}
		if validationTime.After(cert.NotAfter) {
			return fmt.Errorf("certificate %s expired at %s",
				cert.Subject.CommonName, validationTime.Format(time.RFC3339))
		}
	}

	// Check signature chain
	for i := len(certs) - 1; i > 0; i-- {
		cert := certs[i]
		issuer := certs[i-1]

		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("signature verification failed for %s: %w",
				cert.Subject.CommonName, err)
		}

		// Check algorithm policy
		if policySpec.AlgorithmUsagePolicy != nil {
			constraint := policySpec.AlgorithmUsagePolicy.SignatureAlgorithmAllowed(
				cert.SignatureAlgorithm.String(),
				validationTime,
				issuer.PublicKey,
			)
			if !constraint.Allowed {
				return fmt.Errorf("algorithm %s not allowed at %s: %s",
					cert.SignatureAlgorithm.String(),
					validationTime.Format(time.RFC3339),
					constraint.FailureReason)
			}
		}
	}

	// Check revocation (if required)
	if policySpec.RevInfoPolicy != nil && dataHandlers != nil && dataHandlers.RevInfoManager != nil {
		for _, cert := range certs[1:] { // Skip trust anchor
			revoked, err := checkRevocation(cert, validationTime, dataHandlers.RevInfoManager)
			if err != nil {
				// Soft-fail based on policy
				if policySpec.RevInfoPolicy.RevocationCheckingPolicy != nil &&
					policySpec.RevInfoPolicy.RevocationCheckingPolicy.EECertificateRule != nil &&
					!policySpec.RevInfoPolicy.RevocationCheckingPolicy.EECertificateRule.RequireRevocationInfo {
					continue
				}
				return fmt.Errorf("revocation check failed for %s: %w", cert.Subject.CommonName, err)
			}
			if revoked {
				return fmt.Errorf("certificate %s was revoked before %s",
					cert.Subject.CommonName, validationTime.Format(time.RFC3339))
			}
		}
	}

	return nil
}

// checkRevocation checks if a certificate was revoked before the given time.
func checkRevocation(cert *x509.Certificate, at time.Time, revInfoManager *RevInfoManager) (bool, error) {
	if revInfoManager == nil {
		return false, nil
	}

	// Check CRLs
	for _, crl := range revInfoManager.CRLs {
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				if entry.RevocationTime.Before(at) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// PastValidateWithDefaults runs past validation with default settings.
func PastValidateWithDefaults(path *ValidationPath) (*PastValidateOutput, error) {
	input := &PastValidateInput{
		Path:         path,
		PolicySpec:   DefaultCertValidationPolicySpec(),
		DataHandlers: NewValidationDataHandlers(),
	}
	return PastValidate(input)
}

// PastValidateSimple is a simplified interface for past validation.
func PastValidateSimple(
	path *ValidationPath,
	trustAnchors []*x509.Certificate,
	crls []*x509.RevocationList,
	initControlTime *time.Time,
) (*PastValidateOutput, error) {
	policySpec := DefaultCertValidationPolicySpec()
	policySpec.TrustAnchors = trustAnchors

	dataHandlers := NewValidationDataHandlers()
	for _, crl := range crls {
		dataHandlers.RevInfoManager.AddCRL(crl)
	}

	input := &PastValidateInput{
		Path:            path,
		PolicySpec:      policySpec,
		DataHandlers:    dataHandlers,
		InitControlTime: initControlTime,
	}

	return PastValidate(input)
}

// GetValidityWindowIntersection calculates the intersection of validity periods
// for all certificates in a path.
func GetValidityWindowIntersection(path *ValidationPath) (lower, upper time.Time, err error) {
	certs := path.AllCerts()
	if len(certs) == 0 {
		return time.Time{}, time.Time{}, errors.New("no certificates in path")
	}

	lower = certs[0].NotBefore
	upper = certs[0].NotAfter

	for _, cert := range certs[1:] {
		if cert.NotBefore.After(lower) {
			lower = cert.NotBefore
		}
		if cert.NotAfter.Before(upper) {
			upper = cert.NotAfter
		}
	}

	if !lower.Before(upper) {
		return time.Time{}, time.Time{}, ErrEmptyValidityIntersection
	}

	return lower, upper, nil
}

// DetermineAdESLevel determines the AdES level based on available validation data.
func DetermineAdESLevel(output *PastValidateOutput, hasTimestamp bool, hasLTVData bool) AdESValidationLevel {
	if !output.Valid {
		return AdESLevelBES
	}

	level := AdESLevelBES

	// T level requires a timestamp
	if hasTimestamp {
		level = AdESLevelT
	}

	// Higher levels require LTV data
	if hasLTVData {
		if level == AdESLevelT {
			level = AdESLevelXL
		}
	}

	return level
}
