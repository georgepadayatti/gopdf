// Package certvalidator provides X.509 certificate path validation.
// This file contains enhanced validation context and related types.
package certvalidator

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator/fetchers"
	"github.com/georgepadayatti/gopdf/certvalidator/ltv"
	"github.com/georgepadayatti/gopdf/certvalidator/revinfo"
)

// ContextRevocationMode specifies how revocation checking should be performed.
type ContextRevocationMode string

const (
	// ContextRevocationModeSoftFail ignores failures in fetching/locating revocation info.
	ContextRevocationModeSoftFail ContextRevocationMode = "soft-fail"
	// ContextRevocationModeHardFail treats fetch failures as revocation failures.
	ContextRevocationModeHardFail ContextRevocationMode = "hard-fail"
	// ContextRevocationModeRequire requires revocation info for every certificate.
	ContextRevocationModeRequire ContextRevocationMode = "require"
)

// ValidationTimingInfo holds timing information for validation.
type ValidationTimingInfo struct {
	// ValidationTime is the time at which validation is performed.
	ValidationTime time.Time

	// BestSignatureTime is the presumptive time at which the certificate was used.
	BestSignatureTime time.Time

	// PointInTimeValidation indicates if this is a point-in-time validation.
	PointInTimeValidation bool
}

// NewValidationTimingInfo creates a new ValidationTimingInfo.
func NewValidationTimingInfo(validationTime, bestSignatureTime time.Time, pointInTime bool) *ValidationTimingInfo {
	return &ValidationTimingInfo{
		ValidationTime:        validationTime,
		BestSignatureTime:     bestSignatureTime,
		PointInTimeValidation: pointInTime,
	}
}

// ValidationTimingParams holds timing parameters for validation.
type ValidationTimingParams struct {
	Info          *ValidationTimingInfo
	TimeTolerance time.Duration
}

// NewValidationTimingParams creates new ValidationTimingParams.
func NewValidationTimingParams(info *ValidationTimingInfo, tolerance time.Duration) *ValidationTimingParams {
	if tolerance < 0 {
		tolerance = -tolerance
	}
	return &ValidationTimingParams{
		Info:          info,
		TimeTolerance: tolerance,
	}
}

// ValidationTime returns the validation time.
func (p *ValidationTimingParams) ValidationTime() time.Time {
	if p.Info == nil {
		return time.Now()
	}
	return p.Info.ValidationTime
}

// BestSignatureTime returns the best signature time.
func (p *ValidationTimingParams) BestSignatureTime() time.Time {
	if p.Info == nil {
		return time.Now()
	}
	return p.Info.BestSignatureTime
}

// EnhancedValidationContext extends the basic ValidationContext with
type EnhancedValidationContext struct {
	mu sync.RWMutex

	// Core validation components
	CertificateRegistry *CertificateRegistry
	PathBuilder         *PathBuilder
	TrustManager        TrustManager
	RevInfoManager      *revinfo.RevocationInfoArchive

	// Revocation policy
	RevInfoPolicy *CertRevTrustPolicy

	// Algorithm policy
	AlgorithmPolicy AlgorithmUsagePolicy

	// Timing parameters
	TimingParams *ValidationTimingParams

	// Whitelisted certificate SHA-1 fingerprints
	whitelistedCerts map[string]bool

	// Validation cache (signature -> validation path)
	validateMap map[string]*ValidationPath

	// Soft-fail exceptions that were ignored
	softFailExceptions []error

	// Acceptable AC targets
	AcceptableACTargets *ACTargetDescription

	// Signature validator
	SigValidator SignatureValidator

	// POE manager
	POEManager *ltv.POEManager

	// Fetchers configuration
	Fetchers *fetchers.Fetcher

	// FetchingAllowed indicates whether remote fetching is enabled
	FetchingAllowed bool
}

// EnhancedValidationContextOption is a functional option for EnhancedValidationContext.
type EnhancedValidationContextOption func(*EnhancedValidationContext) error

// WithTrustRoots sets the trust roots.
func WithTrustRoots(roots []*x509.Certificate) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		if ctx.TrustManager == nil {
			tm := NewSimpleTrustManager()
			for _, root := range roots {
				tm.AddRoot(root, true)
			}
			ctx.TrustManager = tm
		} else {
			// Add to existing trust manager if possible
			if stm, ok := ctx.TrustManager.(*SimpleTrustManager); ok {
				for _, root := range roots {
					stm.AddRoot(root, true)
				}
			}
		}
		return nil
	}
}

// WithOtherCerts sets additional intermediate certificates.
func WithOtherCerts(certs []*x509.Certificate) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		if ctx.CertificateRegistry != nil {
			ctx.CertificateRegistry.RegisterMultiple(certs)
		}
		return nil
	}
}

// WithWhitelistedCerts sets whitelisted certificate fingerprints.
func WithWhitelistedCerts(fingerprints []string) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		for _, fp := range fingerprints {
			// Normalize fingerprint (remove spaces, colons, convert to lowercase)
			fp = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, " ", ""), ":", ""))
			ctx.whitelistedCerts[fp] = true
		}
		return nil
	}
}

// WithMoment sets the validation time.
func WithMoment(moment time.Time) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		if ctx.TimingParams == nil {
			ctx.TimingParams = &ValidationTimingParams{
				Info: &ValidationTimingInfo{
					ValidationTime:        moment,
					BestSignatureTime:     moment,
					PointInTimeValidation: true,
				},
				TimeTolerance: time.Second,
			}
		} else {
			ctx.TimingParams.Info.ValidationTime = moment
			ctx.TimingParams.Info.PointInTimeValidation = true
		}
		return nil
	}
}

// WithBestSignatureTime sets the best signature time.
func WithBestSignatureTime(t time.Time) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		if ctx.TimingParams != nil && ctx.TimingParams.Info != nil {
			ctx.TimingParams.Info.BestSignatureTime = t
		}
		return nil
	}
}

// WithTimeTolerance sets the time tolerance.
func WithTimeTolerance(tolerance time.Duration) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		if ctx.TimingParams == nil {
			ctx.TimingParams = &ValidationTimingParams{
				Info:          &ValidationTimingInfo{},
				TimeTolerance: tolerance,
			}
		} else {
			ctx.TimingParams.TimeTolerance = tolerance
		}
		return nil
	}
}

// WithRevocationMode sets the revocation mode.
func WithRevocationMode(mode ContextRevocationMode) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		policy, _ := RevocationPolicyFromLegacy(string(mode))
		ctx.RevInfoPolicy = &CertRevTrustPolicy{
			RevocationCheckingPolicy: policy,
		}
		return nil
	}
}

// WithAllowFetching enables or disables remote fetching.
func WithAllowFetching(allow bool) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.FetchingAllowed = allow
		return nil
	}
}

// WithWeakHashAlgos sets the weak hash algorithms.
func WithWeakHashAlgos(algos []string) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		// Create a policy with default weak algorithms
		// Note: The Go version uses crypto.Hash enums, not string names
		ctx.AlgorithmPolicy = NewDisallowWeakAlgorithmsPolicy()
		return nil
	}
}

// WithAcceptableACTargets sets the acceptable AC targets.
func WithAcceptableACTargets(targets *ACTargetDescription) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.AcceptableACTargets = targets
		return nil
	}
}

// WithPOEManager sets the POE manager.
func WithPOEManager(poe *ltv.POEManager) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.POEManager = poe
		return nil
	}
}

// WithRevInfoManager sets the revocation info manager.
func WithRevInfoManager(manager *revinfo.RevocationInfoArchive) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.RevInfoManager = manager
		return nil
	}
}

// WithCertificateRegistry sets the certificate registry.
func WithCertificateRegistry(registry *CertificateRegistry) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.CertificateRegistry = registry
		return nil
	}
}

// WithTrustManager sets the trust manager.
func WithTrustManager(tm TrustManager) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.TrustManager = tm
		return nil
	}
}

// WithAlgorithmUsagePolicy sets the algorithm usage policy.
func WithAlgorithmUsagePolicy(policy AlgorithmUsagePolicy) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.AlgorithmPolicy = policy
		return nil
	}
}

// WithSignatureValidator sets the signature validator.
func WithSignatureValidator(validator SignatureValidator) EnhancedValidationContextOption {
	return func(ctx *EnhancedValidationContext) error {
		ctx.SigValidator = validator
		return nil
	}
}

// NewEnhancedValidationContext creates a new enhanced validation context.
func NewEnhancedValidationContext(opts ...EnhancedValidationContextOption) (*EnhancedValidationContext, error) {
	ctx := &EnhancedValidationContext{
		whitelistedCerts:   make(map[string]bool),
		validateMap:        make(map[string]*ValidationPath),
		softFailExceptions: make([]error, 0),
		FetchingAllowed:    false,
	}

	// Set defaults
	now := time.Now().UTC()
	ctx.TimingParams = &ValidationTimingParams{
		Info: &ValidationTimingInfo{
			ValidationTime:        now,
			BestSignatureTime:     now,
			PointInTimeValidation: false,
		},
		TimeTolerance: time.Second,
	}

	ctx.AlgorithmPolicy = NewDisallowWeakAlgorithmsPolicy()
	ctx.SigValidator = &DefaultSignatureValidator{}
	ctx.CertificateRegistry = NewCertificateRegistry(nil)
	ctx.TrustManager = NewSimpleTrustManager()
	ctx.POEManager = ltv.NewPOEManager()
	softFailPolicy, _ := RevocationPolicyFromLegacy("soft-fail")
	ctx.RevInfoPolicy = &CertRevTrustPolicy{
		RevocationCheckingPolicy: softFailPolicy,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(ctx); err != nil {
			return nil, err
		}
	}

	// Build path builder
	ctx.PathBuilder = NewPathBuilder(ctx.TrustManager, ctx.CertificateRegistry)

	return ctx, nil
}

// Moment returns the validation time.
func (ctx *EnhancedValidationContext) Moment() time.Time {
	if ctx.TimingParams != nil {
		return ctx.TimingParams.ValidationTime()
	}
	return time.Now().UTC()
}

// BestSignatureTime returns the best signature time.
func (ctx *EnhancedValidationContext) BestSignatureTime() time.Time {
	if ctx.TimingParams != nil {
		return ctx.TimingParams.BestSignatureTime()
	}
	return time.Now().UTC()
}

// TimeTolerance returns the time tolerance.
func (ctx *EnhancedValidationContext) TimeTolerance() time.Duration {
	if ctx.TimingParams != nil {
		return ctx.TimingParams.TimeTolerance
	}
	return time.Second
}

// RetroactiveRevInfo returns whether retroactive revinfo is allowed.
func (ctx *EnhancedValidationContext) RetroactiveRevInfo() bool {
	if ctx.RevInfoPolicy != nil {
		return ctx.RevInfoPolicy.RetroactiveRevInfo
	}
	return false
}

// IsWhitelisted checks if a certificate is whitelisted.
func (ctx *EnhancedValidationContext) IsWhitelisted(cert *x509.Certificate) bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	hash := sha1.Sum(cert.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	return ctx.whitelistedCerts[fingerprint]
}

// AddWhitelistedCert adds a certificate fingerprint to the whitelist.
func (ctx *EnhancedValidationContext) AddWhitelistedCert(fingerprint string) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Normalize
	fingerprint = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fingerprint, " ", ""), ":", ""))
	ctx.whitelistedCerts[fingerprint] = true
}

// RecordValidation records that a certificate has been validated.
func (ctx *EnhancedValidationContext) RecordValidation(cert *x509.Certificate, path *ValidationPath) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	key := fmt.Sprintf("%x", cert.Signature)
	ctx.validateMap[key] = path
}

// CheckValidation checks if a certificate has been validated.
func (ctx *EnhancedValidationContext) CheckValidation(cert *x509.Certificate) *ValidationPath {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	key := fmt.Sprintf("%x", cert.Signature)
	return ctx.validateMap[key]
}

// ClearValidation clears the validation record for a certificate.
func (ctx *EnhancedValidationContext) ClearValidation(cert *x509.Certificate) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	key := fmt.Sprintf("%x", cert.Signature)
	delete(ctx.validateMap, key)
}

// ReportSoftFail records a soft-fail exception.
func (ctx *EnhancedValidationContext) ReportSoftFail(err error) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.softFailExceptions = append(ctx.softFailExceptions, err)
}

// SoftFailExceptions returns the recorded soft-fail exceptions.
func (ctx *EnhancedValidationContext) SoftFailExceptions() []error {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	result := make([]error, len(ctx.softFailExceptions))
	copy(result, ctx.softFailExceptions)
	return result
}

// ClearSoftFailExceptions clears the soft-fail exceptions.
func (ctx *EnhancedValidationContext) ClearSoftFailExceptions() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.softFailExceptions = ctx.softFailExceptions[:0]
}

// ValidationDataHandlers holds manager/registry objects for certificate validation.
type ValidationDataHandlers struct {
	// RevInfoManager manages revocation information.
	RevInfoManager *revinfo.RevocationInfoArchive

	// POEManager manages proof-of-existence records.
	POEManager *ltv.POEManager

	// CertRegistry holds certificates (trustless construct).
	CertRegistry *CertificateRegistry
}

// NewValidationDataHandlers creates a new ValidationDataHandlers.
func NewValidationDataHandlers(revInfoManager *revinfo.RevocationInfoArchive, poeManager *ltv.POEManager, certRegistry *CertificateRegistry) *ValidationDataHandlers {
	return &ValidationDataHandlers{
		RevInfoManager: revInfoManager,
		POEManager:     poeManager,
		CertRegistry:   certRegistry,
	}
}

// BootstrapValidationDataHandlers creates ValidationDataHandlers with reasonable defaults.
func BootstrapValidationDataHandlers(
	fetcherConfig *fetchers.FetcherConfig,
	certs []*x509.Certificate,
	poeManager *ltv.POEManager,
) *ValidationDataHandlers {
	if poeManager == nil {
		poeManager = ltv.NewPOEManager()
	}

	var certFetcher *fetchers.CertFetcher
	if fetcherConfig != nil {
		certFetcher = fetchers.NewCertFetcher(fetcherConfig)
	}

	certRegistry := NewCertificateRegistry(certFetcher)
	certRegistry.RegisterMultiple(certs)

	revInfoManager := revinfo.NewRevocationInfoArchive()

	return &ValidationDataHandlers{
		RevInfoManager: revInfoManager,
		POEManager:     poeManager,
		CertRegistry:   certRegistry,
	}
}

// CertValidationPolicySpec describes how to validate certificates at a high level.
// Unlike ValidationContext, this is stateless and can be reused.
type CertValidationPolicySpec struct {
	// TrustManager defines the trust anchors.
	TrustManager TrustManager

	// RevInfoPolicy handles certificate revocation.
	RevInfoPolicy *CertRevTrustPolicy

	// TimeTolerance is the time drift tolerated during validation.
	TimeTolerance time.Duration

	// AcceptableACTargets defines targets for attribute certificate scope.
	AcceptableACTargets *ACTargetDescription

	// AlgorithmUsagePolicy defines cryptographic algorithm restrictions.
	AlgorithmUsagePolicy AlgorithmUsagePolicy

	// PKIXValidationParams contains PKIX validation parameters (RFC 5280).
	PKIXValidationParams *PKIXValidationParams

	// SignatureValidator validates signatures.
	SignatureValidator SignatureValidator
}

// NewCertValidationPolicySpec creates a new CertValidationPolicySpec with defaults.
func NewCertValidationPolicySpec(trustManager TrustManager) *CertValidationPolicySpec {
	return &CertValidationPolicySpec{
		TrustManager:         trustManager,
		RevInfoPolicy:        &CertRevTrustPolicy{},
		TimeTolerance:        time.Second,
		AlgorithmUsagePolicy: NewDisallowWeakAlgorithmsPolicy(),
		SignatureValidator:   &DefaultSignatureValidator{},
	}
}

// BuildValidationContext builds a validation context from this policy.
func (spec *CertValidationPolicySpec) BuildValidationContext(
	timingInfo *ValidationTimingInfo,
	handlers *ValidationDataHandlers,
) (*EnhancedValidationContext, error) {
	opts := []EnhancedValidationContextOption{
		WithTrustManager(spec.TrustManager),
	}

	if timingInfo != nil {
		opts = append(opts, WithMoment(timingInfo.ValidationTime))
		if !timingInfo.BestSignatureTime.IsZero() {
			opts = append(opts, WithBestSignatureTime(timingInfo.BestSignatureTime))
		}
	}

	opts = append(opts, WithTimeTolerance(spec.TimeTolerance))

	if spec.AcceptableACTargets != nil {
		opts = append(opts, WithAcceptableACTargets(spec.AcceptableACTargets))
	}

	if spec.AlgorithmUsagePolicy != nil {
		opts = append(opts, WithAlgorithmUsagePolicy(spec.AlgorithmUsagePolicy))
	}

	if spec.SignatureValidator != nil {
		opts = append(opts, WithSignatureValidator(spec.SignatureValidator))
	}

	if handlers != nil {
		if handlers.CertRegistry != nil {
			opts = append(opts, WithCertificateRegistry(handlers.CertRegistry))
		}
		if handlers.POEManager != nil {
			opts = append(opts, WithPOEManager(handlers.POEManager))
		}
		if handlers.RevInfoManager != nil {
			opts = append(opts, WithRevInfoManager(handlers.RevInfoManager))
		}
	}

	return NewEnhancedValidationContext(opts...)
}

// ContextGeneralName represents an X.509 GeneralName for context purposes.
// This wraps the existing GeneralNameType from name_trees.go.
type ContextGeneralName struct {
	Type  GeneralNameType
	Value interface{}
}

// NewContextGeneralNameFromEmail creates a ContextGeneralName from an email address.
func NewContextGeneralNameFromEmail(email string) *ContextGeneralName {
	return &ContextGeneralName{Type: GeneralNameRFC822Name, Value: email}
}

// NewContextGeneralNameFromDNS creates a ContextGeneralName from a DNS name.
func NewContextGeneralNameFromDNS(dns string) *ContextGeneralName {
	return &ContextGeneralName{Type: GeneralNameDNSName, Value: dns}
}

// NewContextGeneralNameFromURI creates a ContextGeneralName from a URI.
func NewContextGeneralNameFromURI(uri string) *ContextGeneralName {
	return &ContextGeneralName{Type: GeneralNameURI, Value: uri}
}

// NewContextGeneralNameFromIP creates a ContextGeneralName from an IP address.
func NewContextGeneralNameFromIP(ip string) *ContextGeneralName {
	return &ContextGeneralName{Type: GeneralNameIPAddress, Value: ip}
}

// NewContextGeneralNameFromDirectory creates a ContextGeneralName from a directory name.
func NewContextGeneralNameFromDirectory(name pkix.Name) *ContextGeneralName {
	return &ContextGeneralName{Type: GeneralNameDirectoryName, Value: name}
}
