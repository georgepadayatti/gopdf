// Package certvalidator provides X.509 certificate path validation.
// This file contains PKIX validation parameters and policy declarations.
package certvalidator

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// DefaultWeakHashAlgos contains digest algorithms considered weak by default.
// Note: MD2 is not supported in Go's crypto package, so we only include MD5 and SHA1.
var DefaultWeakHashAlgos = map[crypto.Hash]bool{
	crypto.MD5:  true,
	crypto.SHA1: true,
}

// FreshnessFallbackValidityDefault is the default freshness used when revocation
// information does not specify a next update time.
var FreshnessFallbackValidityDefault = 30 * time.Minute

// NonRevokedStatusAssertion asserts that a certificate was not revoked at some given date.
type NonRevokedStatusAssertion struct {
	// CertSHA256 is the SHA-256 hash of the certificate.
	CertSHA256 []byte

	// At is the moment in time at which the assertion is valid.
	At time.Time
}

// RevocationCheckingRule determines when and how revocation data must be checked.
type RevocationCheckingRule int

const (
	// RevocationRuleCRLRequired requires CRL check.
	RevocationRuleCRLRequired RevocationCheckingRule = iota
	// RevocationRuleOCSPRequired requires OCSP check.
	RevocationRuleOCSPRequired
	// RevocationRuleCRLAndOCSPRequired requires both CRL and OCSP check.
	RevocationRuleCRLAndOCSPRequired
	// RevocationRuleCRLOrOCSPRequired requires either CRL or OCSP check.
	RevocationRuleCRLOrOCSPRequired
	// RevocationRuleNoCheck does not require revocation check.
	RevocationRuleNoCheck
	// RevocationRuleCheckIfDeclared checks revocation if declared in certificate.
	RevocationRuleCheckIfDeclared
	// RevocationRuleCheckIfDeclaredSoft checks revocation if declared, but doesn't fail.
	RevocationRuleCheckIfDeclaredSoft
)

// String returns the string representation of the revocation checking rule.
func (r RevocationCheckingRule) String() string {
	switch r {
	case RevocationRuleCRLRequired:
		return "clrcheck"
	case RevocationRuleOCSPRequired:
		return "ocspcheck"
	case RevocationRuleCRLAndOCSPRequired:
		return "bothcheck"
	case RevocationRuleCRLOrOCSPRequired:
		return "eithercheck"
	case RevocationRuleNoCheck:
		return "nocheck"
	case RevocationRuleCheckIfDeclared:
		return "ifdeclaredcheck"
	case RevocationRuleCheckIfDeclaredSoft:
		return "ifdeclaredsoftcheck"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// IsStrict returns true if the rule requires strict revocation checking.
func (r RevocationCheckingRule) IsStrict() bool {
	return r != RevocationRuleCheckIfDeclared &&
		r != RevocationRuleCheckIfDeclaredSoft &&
		r != RevocationRuleNoCheck
}

// IsTolerant returns true if the rule allows validation to proceed without revocation info.
func (r RevocationCheckingRule) IsTolerant() bool {
	return r == RevocationRuleCheckIfDeclaredSoft || r == RevocationRuleNoCheck
}

// IsCRLMandatory returns true if CRL checking is mandatory.
func (r RevocationCheckingRule) IsCRLMandatory() bool {
	return r == RevocationRuleCRLRequired || r == RevocationRuleCRLAndOCSPRequired
}

// IsCRLRelevant returns true if CRL checking is relevant.
func (r RevocationCheckingRule) IsCRLRelevant() bool {
	return r != RevocationRuleNoCheck && r != RevocationRuleOCSPRequired
}

// IsOCSPMandatory returns true if OCSP checking is mandatory.
func (r RevocationCheckingRule) IsOCSPMandatory() bool {
	return r == RevocationRuleOCSPRequired || r == RevocationRuleCRLAndOCSPRequired
}

// IsOCSPRelevant returns true if OCSP checking is relevant.
func (r RevocationCheckingRule) IsOCSPRelevant() bool {
	return r != RevocationRuleNoCheck && r != RevocationRuleCRLRequired
}

// RevocationCheckingPolicy describes a revocation checking policy.
type RevocationCheckingPolicy struct {
	// EECertificateRule is applied to end-entity certificates.
	EECertificateRule RevocationCheckingRule

	// IntermediateCACertRule is applied to intermediate CA certificates.
	IntermediateCACertRule RevocationCheckingRule
}

// NewRevocationCheckingPolicy creates a new revocation checking policy.
func NewRevocationCheckingPolicy(eeRule, caRule RevocationCheckingRule) *RevocationCheckingPolicy {
	return &RevocationCheckingPolicy{
		EECertificateRule:      eeRule,
		IntermediateCACertRule: caRule,
	}
}

// FromLegacy creates a RevocationCheckingPolicy from a legacy policy string.
func RevocationPolicyFromLegacy(policy string) (*RevocationCheckingPolicy, error) {
	switch policy {
	case "none":
		return NoRevocation, nil
	case "soft-fail":
		return NewRevocationCheckingPolicy(
			RevocationRuleCheckIfDeclaredSoft,
			RevocationRuleCheckIfDeclaredSoft,
		), nil
	case "hard-fail":
		return NewRevocationCheckingPolicy(
			RevocationRuleCheckIfDeclared,
			RevocationRuleCheckIfDeclared,
		), nil
	case "require":
		return RequireRevInfo, nil
	default:
		return nil, fmt.Errorf("'%s' is not a valid revocation mode", policy)
	}
}

// IsEssential returns true if revocation checking is essential for validation.
func (p *RevocationCheckingPolicy) IsEssential() bool {
	return !p.EECertificateRule.IsTolerant() || !p.IntermediateCACertRule.IsTolerant()
}

// RequireRevInfo requires revocation information for all certificates.
var RequireRevInfo = &RevocationCheckingPolicy{
	EECertificateRule:      RevocationRuleCRLOrOCSPRequired,
	IntermediateCACertRule: RevocationRuleCRLOrOCSPRequired,
}

// NoRevocation does not require revocation information.
var NoRevocation = &RevocationCheckingPolicy{
	EECertificateRule:      RevocationRuleNoCheck,
	IntermediateCACertRule: RevocationRuleNoCheck,
}

// FreshnessReqType defines the freshness requirement type.
type FreshnessReqType int

const (
	// FreshnessDefault uses the default freshness policy.
	FreshnessDefault FreshnessReqType = iota
	// FreshnessMaxDiffRevocationValidation requires revocation info to be recent.
	FreshnessMaxDiffRevocationValidation
	// FreshnessTimeAfterSignature requires revocation info after signature creation.
	FreshnessTimeAfterSignature
)

// String returns the string representation of the freshness requirement type.
func (f FreshnessReqType) String() string {
	switch f {
	case FreshnessDefault:
		return "default"
	case FreshnessMaxDiffRevocationValidation:
		return "max_diff_revocation_validation"
	case FreshnessTimeAfterSignature:
		return "time_after_signature"
	default:
		return fmt.Sprintf("unknown(%d)", f)
	}
}

// CertRevTrustPolicy describes conditions for trusting revocation info.
type CertRevTrustPolicy struct {
	// RevocationCheckingPolicy defines the revocation checking requirements.
	RevocationCheckingPolicy *RevocationCheckingPolicy

	// Freshness interval. If zero, defaults to distance between thisUpdate and nextUpdate.
	Freshness time.Duration

	// FreshnessReqType defines the methodology for evaluating freshness.
	FreshnessReqType FreshnessReqType

	// ExpectedPostExpiryRevInfoTime is how long the CA is expected to supply
	// status information after a certificate expires.
	ExpectedPostExpiryRevInfoTime time.Duration

	// RetroactiveRevInfo treats revocation info as retroactively valid.
	RetroactiveRevInfo bool
}

// NewCertRevTrustPolicy creates a new CertRevTrustPolicy with defaults.
func NewCertRevTrustPolicy(revPolicy *RevocationCheckingPolicy) *CertRevTrustPolicy {
	return &CertRevTrustPolicy{
		RevocationCheckingPolicy: revPolicy,
		FreshnessReqType:         FreshnessDefault,
	}
}

// IntersectPolicySets intersects two sets of policies, handling any_policy.
func IntersectPolicySets(aPols, bPols map[string]bool) map[string]bool {
	aAny := aPols[AnyPolicy]
	bAny := bPols[AnyPolicy]

	if aAny && bAny {
		return map[string]bool{AnyPolicy: true}
	} else if aAny {
		result := make(map[string]bool)
		for k, v := range bPols {
			result[k] = v
		}
		return result
	} else if bAny {
		result := make(map[string]bool)
		for k, v := range aPols {
			result[k] = v
		}
		return result
	}

	// Intersection
	result := make(map[string]bool)
	for k := range aPols {
		if bPols[k] {
			result[k] = true
		}
	}
	return result
}

// PKIXValidationParams contains parameters for PKIX path validation.
type PKIXValidationParams struct {
	// UserInitialPolicySet is the set of acceptable policies.
	UserInitialPolicySet map[string]bool

	// InitialPolicyMappingInhibit forbids policy mapping along the entire chain.
	InitialPolicyMappingInhibit bool

	// InitialExplicitPolicy requires path validation to terminate with a permissible policy.
	InitialExplicitPolicy bool

	// InitialAnyPolicyInhibit leaves anyPolicy unprocessed when it appears.
	InitialAnyPolicyInhibit bool

	// InitialPermittedSubtrees restricts permitted subject names.
	InitialPermittedSubtrees *PermittedSubtrees

	// InitialExcludedSubtrees restricts excluded subject names.
	InitialExcludedSubtrees *ExcludedSubtrees
}

// DefaultPKIXValidationParams returns default PKIX validation parameters.
func DefaultPKIXValidationParams() *PKIXValidationParams {
	return &PKIXValidationParams{
		UserInitialPolicySet: map[string]bool{AnyPolicy: true},
	}
}

// Merge combines these PKIX validation params with another set.
func (p *PKIXValidationParams) Merge(other *PKIXValidationParams) *PKIXValidationParams {
	var initPolicySet map[string]bool

	if p.UserInitialPolicySet[AnyPolicy] {
		initPolicySet = other.UserInitialPolicySet
	} else if other.UserInitialPolicySet[AnyPolicy] {
		initPolicySet = p.UserInitialPolicySet
	} else {
		initPolicySet = IntersectPolicySets(p.UserInitialPolicySet, other.UserInitialPolicySet)
	}

	return &PKIXValidationParams{
		UserInitialPolicySet:        initPolicySet,
		InitialAnyPolicyInhibit:     p.InitialAnyPolicyInhibit && other.InitialAnyPolicyInhibit,
		InitialExplicitPolicy:       p.InitialExplicitPolicy && other.InitialExplicitPolicy,
		InitialPolicyMappingInhibit: p.InitialPolicyMappingInhibit && other.InitialPolicyMappingInhibit,
	}
}

// AlgorithmUsageConstraint expresses a constraint on algorithm usage.
type AlgorithmUsageConstraint struct {
	// Allowed indicates whether the algorithm can be used.
	Allowed bool

	// NotAllowedAfter indicates when the algorithm became unavailable.
	NotAllowedAfter *time.Time

	// FailureReason provides a human-readable description of the failure.
	FailureReason string
}

// NewAlgorithmUsageConstraint creates a new constraint.
func NewAlgorithmUsageConstraint(allowed bool) *AlgorithmUsageConstraint {
	return &AlgorithmUsageConstraint{Allowed: allowed}
}

// NewAlgorithmUsageConstraintWithReason creates a constraint with a failure reason.
func NewAlgorithmUsageConstraintWithReason(allowed bool, reason string) *AlgorithmUsageConstraint {
	return &AlgorithmUsageConstraint{
		Allowed:       allowed,
		FailureReason: reason,
	}
}

// IsAllowed returns true if the algorithm is allowed.
func (c *AlgorithmUsageConstraint) IsAllowed() bool {
	return c.Allowed
}

// AlgorithmUsagePolicy defines a policy for cryptographic algorithm usage.
type AlgorithmUsagePolicy interface {
	// DigestAlgorithmAllowed checks if a digest algorithm is allowed.
	DigestAlgorithmAllowed(algo crypto.Hash, moment *time.Time) *AlgorithmUsageConstraint

	// SignatureAlgorithmAllowed checks if a signature algorithm is allowed.
	SignatureAlgorithmAllowed(algo x509.SignatureAlgorithm, moment *time.Time, publicKey crypto.PublicKey) *AlgorithmUsageConstraint
}

// DisallowWeakAlgorithmsPolicy forbids weak algorithms and allows everything else.
type DisallowWeakAlgorithmsPolicy struct {
	// WeakHashAlgos contains digest algorithms considered weak.
	WeakHashAlgos map[crypto.Hash]bool

	// WeakSignatureAlgos contains signature algorithms considered weak.
	WeakSignatureAlgos map[x509.SignatureAlgorithm]bool

	// RSAKeySizeThreshold is the minimum RSA key size in bits.
	RSAKeySizeThreshold int

	// DSAKeySizeThreshold is the minimum DSA key size in bits.
	DSAKeySizeThreshold int
}

// NewDisallowWeakAlgorithmsPolicy creates a new policy with defaults.
func NewDisallowWeakAlgorithmsPolicy() *DisallowWeakAlgorithmsPolicy {
	return &DisallowWeakAlgorithmsPolicy{
		WeakHashAlgos:       DefaultWeakHashAlgos,
		WeakSignatureAlgos:  make(map[x509.SignatureAlgorithm]bool),
		RSAKeySizeThreshold: 2048,
		DSAKeySizeThreshold: 3192,
	}
}

// DigestAlgorithmAllowed checks if a digest algorithm is allowed.
func (p *DisallowWeakAlgorithmsPolicy) DigestAlgorithmAllowed(algo crypto.Hash, moment *time.Time) *AlgorithmUsageConstraint {
	return NewAlgorithmUsageConstraint(!p.WeakHashAlgos[algo])
}

// SignatureAlgorithmAllowed checks if a signature algorithm is allowed.
func (p *DisallowWeakAlgorithmsPolicy) SignatureAlgorithmAllowed(algo x509.SignatureAlgorithm, moment *time.Time, publicKey crypto.PublicKey) *AlgorithmUsageConstraint {
	if p.WeakSignatureAlgos[algo] {
		return NewAlgorithmUsageConstraintWithReason(false, fmt.Sprintf("signature algorithm %v is not allowed", algo))
	}

	// Check key size for RSA/DSA
	if publicKey != nil {
		keySize := getPublicKeySize(publicKey)
		algoName := algo.String()

		if isRSAAlgorithm(algo) && keySize < p.RSAKeySizeThreshold {
			return NewAlgorithmUsageConstraintWithReason(false,
				fmt.Sprintf("Key size %d for algorithm %s is too small; policy mandates >= %d",
					keySize, algoName, p.RSAKeySizeThreshold))
		}

		if isDSAAlgorithm(algo) && keySize < p.DSAKeySizeThreshold {
			return NewAlgorithmUsageConstraintWithReason(false,
				fmt.Sprintf("Key size %d for algorithm %s is too small; policy mandates >= %d",
					keySize, algoName, p.DSAKeySizeThreshold))
		}
	}

	// Check the hash algorithm
	hashAlgo := getHashFromSignatureAlgorithm(algo)
	if hashAlgo != crypto.Hash(0) {
		digestConstraint := p.DigestAlgorithmAllowed(hashAlgo, moment)
		if !digestConstraint.Allowed {
			return NewAlgorithmUsageConstraintWithReason(false,
				fmt.Sprintf("Digest algorithm %v is not allowed, which disqualifies signature mechanism %v",
					hashAlgo, algo))
		}
	}

	return NewAlgorithmUsageConstraint(true)
}

// AcceptAllAlgorithmsPolicy accepts all algorithms.
type AcceptAllAlgorithmsPolicy struct{}

// DigestAlgorithmAllowed always returns allowed.
func (p *AcceptAllAlgorithmsPolicy) DigestAlgorithmAllowed(algo crypto.Hash, moment *time.Time) *AlgorithmUsageConstraint {
	return NewAlgorithmUsageConstraint(true)
}

// SignatureAlgorithmAllowed always returns allowed.
func (p *AcceptAllAlgorithmsPolicy) SignatureAlgorithmAllowed(algo x509.SignatureAlgorithm, moment *time.Time, publicKey crypto.PublicKey) *AlgorithmUsageConstraint {
	return NewAlgorithmUsageConstraint(true)
}

// Helper functions

func getPublicKeySize(publicKey crypto.PublicKey) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *dsa.PublicKey:
		return key.P.BitLen()
	case *ecdsa.PublicKey:
		if key.Curve != nil {
			return key.Curve.Params().BitSize
		}
		return 0
	case interface{ Size() int }:
		return key.Size() * 8
	default:
		return 0
	}
}

func isRSAAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.MD5WithRSA, x509.SHA1WithRSA:
		return true
	}
	return false
}

func isDSAAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		return true
	}
	return false
}

func getHashFromSignatureAlgorithm(algo x509.SignatureAlgorithm) crypto.Hash {
	switch algo {
	case x509.MD5WithRSA:
		return crypto.MD5
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return crypto.SHA1
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}
