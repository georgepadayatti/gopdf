// Package validation provides utilities for signature validation.
package validation

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Common OIDs for hash algorithms.
var (
	OIDDigestAlgorithmMD5      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	OIDDigestAlgorithmSHA1     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDDigestAlgorithmSHA224   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	OIDDigestAlgorithmSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmSHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	OIDDigestAlgorithmSHA3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	OIDDigestAlgorithmSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
	OIDDigestAlgorithmSHAKE256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 12}
)

// Common OIDs for signature algorithms.
var (
	OIDSignatureRSAMD5      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OIDSignatureRSASHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDSignatureRSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureRSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureRSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSignatureRSAPSS      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSignatureECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDSignatureECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDSignatureEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
	OIDSignatureEd448       = asn1.ObjectIdentifier{1, 3, 101, 113}
)

// DefaultWeakHashAlgorithms are hash algorithms considered too weak for security.
var DefaultWeakHashAlgorithms = map[string]bool{
	"sha1":   true,
	"md5":    true,
	"md2":    true,
	"sha224": false, // SHA-224 is weak but sometimes tolerated
}

// AlgorithmUsageConstraint represents the result of an algorithm usage check.
type AlgorithmUsageConstraint struct {
	Allowed       bool
	FailureReason string
}

// NewAllowedConstraint creates an allowed constraint.
func NewAllowedConstraint() AlgorithmUsageConstraint {
	return AlgorithmUsageConstraint{Allowed: true}
}

// NewDisallowedConstraint creates a disallowed constraint with a reason.
func NewDisallowedConstraint(reason string) AlgorithmUsageConstraint {
	return AlgorithmUsageConstraint{
		Allowed:       false,
		FailureReason: reason,
	}
}

// AlgorithmUsagePolicy defines how algorithm usage is checked.
type AlgorithmUsagePolicy interface {
	// DigestAlgorithmAllowed checks if a digest algorithm is allowed.
	DigestAlgorithmAllowed(algo crypto.Hash, moment time.Time) AlgorithmUsageConstraint

	// SignatureAlgorithmAllowed checks if a signature algorithm is allowed.
	SignatureAlgorithmAllowed(algo x509.SignatureAlgorithm, moment time.Time, pubKey interface{}) AlgorithmUsageConstraint
}

// CMSAlgorithmUsagePolicy is an algorithm usage policy for CMS signatures.
type CMSAlgorithmUsagePolicy interface {
	AlgorithmUsagePolicy

	// DigestCombinationAllowed verifies whether a digest algorithm is compatible
	// with the digest algorithm implied by the provided signature algorithm.
	DigestCombinationAllowed(
		sigAlgo x509.SignatureAlgorithm,
		digestAlgo crypto.Hash,
		moment time.Time,
	) AlgorithmUsageConstraint
}

// DisallowWeakAlgorithmsPolicy disallows weak hash algorithms.
type DisallowWeakAlgorithmsPolicy struct {
	WeakHashAlgorithms map[string]bool
}

// NewDisallowWeakAlgorithmsPolicy creates a new policy disallowing weak algorithms.
func NewDisallowWeakAlgorithmsPolicy(weakAlgos map[string]bool) *DisallowWeakAlgorithmsPolicy {
	if weakAlgos == nil {
		weakAlgos = DefaultWeakHashAlgorithms
	}
	return &DisallowWeakAlgorithmsPolicy{
		WeakHashAlgorithms: weakAlgos,
	}
}

// DigestAlgorithmAllowed checks if a digest algorithm is allowed.
func (p *DisallowWeakAlgorithmsPolicy) DigestAlgorithmAllowed(algo crypto.Hash, moment time.Time) AlgorithmUsageConstraint {
	name := HashAlgorithmName(algo)
	if p.WeakHashAlgorithms[name] {
		return NewDisallowedConstraint(fmt.Sprintf("weak hash algorithm %s is not allowed", name))
	}
	return NewAllowedConstraint()
}

// SignatureAlgorithmAllowed checks if a signature algorithm is allowed.
func (p *DisallowWeakAlgorithmsPolicy) SignatureAlgorithmAllowed(algo x509.SignatureAlgorithm, moment time.Time, pubKey interface{}) AlgorithmUsageConstraint {
	hash := SignatureAlgorithmHash(algo)
	if hash == 0 {
		// Unknown algorithm, allow it (be permissive)
		return NewAllowedConstraint()
	}
	return p.DigestAlgorithmAllowed(hash, moment)
}

// DefaultCMSAlgorithmUsagePolicy is a default CMS algorithm usage policy.
type DefaultCMSAlgorithmUsagePolicy struct {
	*DisallowWeakAlgorithmsPolicy
}

// NewDefaultCMSAlgorithmUsagePolicy creates a new default CMS algorithm usage policy.
func NewDefaultCMSAlgorithmUsagePolicy() *DefaultCMSAlgorithmUsagePolicy {
	return &DefaultCMSAlgorithmUsagePolicy{
		DisallowWeakAlgorithmsPolicy: NewDisallowWeakAlgorithmsPolicy(nil),
	}
}

// DigestCombinationAllowed verifies that digest matches signature algorithm.
func (p *DefaultCMSAlgorithmUsagePolicy) DigestCombinationAllowed(
	sigAlgo x509.SignatureAlgorithm,
	digestAlgo crypto.Hash,
	moment time.Time,
) AlgorithmUsageConstraint {
	return EnsureDigestMatch(sigAlgo, digestAlgo)
}

// LiftToCMSPolicy lifts a base AlgorithmUsagePolicy to a CMSAlgorithmUsagePolicy.
func LiftToCMSPolicy(policy AlgorithmUsagePolicy) CMSAlgorithmUsagePolicy {
	if cmsPolicy, ok := policy.(CMSAlgorithmUsagePolicy); ok {
		return cmsPolicy
	}
	return &liftedCMSPolicy{underlying: policy}
}

// liftedCMSPolicy wraps an AlgorithmUsagePolicy to implement CMSAlgorithmUsagePolicy.
type liftedCMSPolicy struct {
	underlying AlgorithmUsagePolicy
}

func (p *liftedCMSPolicy) DigestAlgorithmAllowed(algo crypto.Hash, moment time.Time) AlgorithmUsageConstraint {
	return p.underlying.DigestAlgorithmAllowed(algo, moment)
}

func (p *liftedCMSPolicy) SignatureAlgorithmAllowed(algo x509.SignatureAlgorithm, moment time.Time, pubKey interface{}) AlgorithmUsageConstraint {
	return p.underlying.SignatureAlgorithmAllowed(algo, moment, pubKey)
}

func (p *liftedCMSPolicy) DigestCombinationAllowed(sigAlgo x509.SignatureAlgorithm, digestAlgo crypto.Hash, moment time.Time) AlgorithmUsageConstraint {
	return EnsureDigestMatch(sigAlgo, digestAlgo)
}

// EnsureDigestMatch ensures the digest algorithm matches the signature algorithm.
func EnsureDigestMatch(sigAlgo x509.SignatureAlgorithm, digestAlgo crypto.Hash) AlgorithmUsageConstraint {
	// Handle Ed448 specially (uses SHAKE256)
	if sigAlgo == x509.PureEd25519 {
		// Ed25519 has no separate digest algorithm
		return NewAllowedConstraint()
	}

	expectedHash := SignatureAlgorithmHash(sigAlgo)
	if expectedHash == 0 {
		// Unknown signature algorithm, can't check
		return NewAllowedConstraint()
	}

	if expectedHash != digestAlgo {
		return NewDisallowedConstraint(fmt.Sprintf(
			"digest algorithm %s does not match value implied by signature algorithm %s",
			HashAlgorithmName(digestAlgo),
			sigAlgo.String(),
		))
	}

	return NewAllowedConstraint()
}

// SignatureAlgorithmHash returns the hash algorithm used by a signature algorithm.
func SignatureAlgorithmHash(algo x509.SignatureAlgorithm) crypto.Hash {
	switch algo {
	case x509.MD5WithRSA:
		return crypto.MD5
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return crypto.SHA1
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512
	case x509.PureEd25519:
		return 0 // Ed25519 doesn't use a separate hash
	default:
		return 0
	}
}

// HashAlgorithmName returns the name of a hash algorithm.
func HashAlgorithmName(algo crypto.Hash) string {
	switch algo {
	case crypto.MD5:
		return "md5"
	case crypto.SHA1:
		return "sha1"
	case crypto.SHA224:
		return "sha224"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	case crypto.SHA3_256:
		return "sha3_256"
	case crypto.SHA3_384:
		return "sha3_384"
	case crypto.SHA3_512:
		return "sha3_512"
	default:
		return "unknown"
	}
}

// HashAlgorithmFromName returns the hash algorithm from its name.
func HashAlgorithmFromName(name string) crypto.Hash {
	switch name {
	case "md5":
		return crypto.MD5
	case "sha1":
		return crypto.SHA1
	case "sha224":
		return crypto.SHA224
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "sha3_256", "sha3-256":
		return crypto.SHA3_256
	case "sha3_384", "sha3-384":
		return crypto.SHA3_384
	case "sha3_512", "sha3-512":
		return crypto.SHA3_512
	default:
		return 0
	}
}

// HashAlgorithmFromOID returns the hash algorithm from its OID.
func HashAlgorithmFromOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(OIDDigestAlgorithmMD5):
		return crypto.MD5
	case oid.Equal(OIDDigestAlgorithmSHA1):
		return crypto.SHA1
	case oid.Equal(OIDDigestAlgorithmSHA224):
		return crypto.SHA224
	case oid.Equal(OIDDigestAlgorithmSHA256):
		return crypto.SHA256
	case oid.Equal(OIDDigestAlgorithmSHA384):
		return crypto.SHA384
	case oid.Equal(OIDDigestAlgorithmSHA512):
		return crypto.SHA512
	case oid.Equal(OIDDigestAlgorithmSHA3_256):
		return crypto.SHA3_256
	case oid.Equal(OIDDigestAlgorithmSHA3_384):
		return crypto.SHA3_384
	case oid.Equal(OIDDigestAlgorithmSHA3_512):
		return crypto.SHA3_512
	default:
		return 0
	}
}

// HashAlgorithmOID returns the OID for a hash algorithm.
func HashAlgorithmOID(algo crypto.Hash) asn1.ObjectIdentifier {
	switch algo {
	case crypto.MD5:
		return OIDDigestAlgorithmMD5
	case crypto.SHA1:
		return OIDDigestAlgorithmSHA1
	case crypto.SHA224:
		return OIDDigestAlgorithmSHA224
	case crypto.SHA256:
		return OIDDigestAlgorithmSHA256
	case crypto.SHA384:
		return OIDDigestAlgorithmSHA384
	case crypto.SHA512:
		return OIDDigestAlgorithmSHA512
	case crypto.SHA3_256:
		return OIDDigestAlgorithmSHA3_256
	case crypto.SHA3_384:
		return OIDDigestAlgorithmSHA3_384
	case crypto.SHA3_512:
		return OIDDigestAlgorithmSHA3_512
	default:
		return nil
	}
}

// Validation utility errors.
var (
	ErrMessageDigestNotFound  = errors.New("message digest not found in signature")
	ErrMultipleMessageDigests = errors.New("multiple message digest attributes present")
	ErrInvalidAttribute       = errors.New("invalid attribute in signature")
)

// ExtractMessageDigest extracts the message digest from signed attributes.
func ExtractMessageDigest(signedAttrs []SignedAttribute) ([]byte, error) {
	var digest []byte
	found := false

	for _, attr := range signedAttrs {
		if attr.Type == "messageDigest" || attr.Type == "1.2.840.113549.1.9.4" {
			if found {
				return nil, ErrMultipleMessageDigests
			}
			var ok bool
			digest, ok = attr.Value.([]byte)
			if !ok {
				return nil, ErrInvalidAttribute
			}
			found = true
		}
	}

	if !found {
		return nil, ErrMessageDigestNotFound
	}

	return digest, nil
}

// SignedAttribute represents a signed attribute in CMS.
type SignedAttribute struct {
	Type  string
	Value interface{}
}

// ExtractSigningTime extracts the signing time from signed attributes.
func ExtractSigningTime(signedAttrs []SignedAttribute) (time.Time, error) {
	for _, attr := range signedAttrs {
		if attr.Type == "signingTime" || attr.Type == "1.2.840.113549.1.9.5" {
			if t, ok := attr.Value.(time.Time); ok {
				return t, nil
			}
		}
	}
	return time.Time{}, errors.New("signing time not found")
}

// ExtractContentType extracts the content type from signed attributes.
func ExtractContentType(signedAttrs []SignedAttribute) (string, error) {
	for _, attr := range signedAttrs {
		if attr.Type == "contentType" || attr.Type == "1.2.840.113549.1.9.3" {
			if ct, ok := attr.Value.(string); ok {
				return ct, nil
			}
		}
	}
	return "", errors.New("content type not found")
}

// ValidateSignedAttributes validates the signed attributes in a CMS signature.
func ValidateSignedAttributes(signedAttrs []SignedAttribute) error {
	// Check for required attributes
	hasContentType := false
	hasMessageDigest := false

	for _, attr := range signedAttrs {
		switch attr.Type {
		case "contentType", "1.2.840.113549.1.9.3":
			hasContentType = true
		case "messageDigest", "1.2.840.113549.1.9.4":
			hasMessageDigest = true
		}
	}

	if !hasContentType {
		return errors.New("content type attribute is required in signed attributes")
	}
	if !hasMessageDigest {
		return ErrMessageDigestNotFound
	}

	return nil
}

// CompareOIDs compares two OIDs for equality.
func CompareOIDs(a, b asn1.ObjectIdentifier) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SignatureAlgorithmFromOID returns the signature algorithm from its OID.
func SignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case CompareOIDs(oid, OIDSignatureRSAMD5):
		return x509.MD5WithRSA
	case CompareOIDs(oid, OIDSignatureRSASHA1):
		return x509.SHA1WithRSA
	case CompareOIDs(oid, OIDSignatureRSASHA256):
		return x509.SHA256WithRSA
	case CompareOIDs(oid, OIDSignatureRSASHA384):
		return x509.SHA384WithRSA
	case CompareOIDs(oid, OIDSignatureRSASHA512):
		return x509.SHA512WithRSA
	case CompareOIDs(oid, OIDSignatureECDSASHA1):
		return x509.ECDSAWithSHA1
	case CompareOIDs(oid, OIDSignatureECDSASHA256):
		return x509.ECDSAWithSHA256
	case CompareOIDs(oid, OIDSignatureECDSASHA384):
		return x509.ECDSAWithSHA384
	case CompareOIDs(oid, OIDSignatureECDSASHA512):
		return x509.ECDSAWithSHA512
	case CompareOIDs(oid, OIDSignatureEd25519):
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// IsWeakAlgorithm checks if an algorithm is considered weak.
func IsWeakAlgorithm(algo crypto.Hash) bool {
	name := HashAlgorithmName(algo)
	return DefaultWeakHashAlgorithms[name]
}

// ValidateAlgorithmStrength validates that algorithms meet minimum strength requirements.
func ValidateAlgorithmStrength(sigAlgo x509.SignatureAlgorithm, digestAlgo crypto.Hash, policy CMSAlgorithmUsagePolicy, moment time.Time) error {
	// Check signature algorithm
	sigConstraint := policy.SignatureAlgorithmAllowed(sigAlgo, moment, nil)
	if !sigConstraint.Allowed {
		return fmt.Errorf("signature algorithm not allowed: %s", sigConstraint.FailureReason)
	}

	// Check digest algorithm
	digestConstraint := policy.DigestAlgorithmAllowed(digestAlgo, moment)
	if !digestConstraint.Allowed {
		return fmt.Errorf("digest algorithm not allowed: %s", digestConstraint.FailureReason)
	}

	// Check combination
	comboConstraint := policy.DigestCombinationAllowed(sigAlgo, digestAlgo, moment)
	if !comboConstraint.Allowed {
		return fmt.Errorf("algorithm combination not allowed: %s", comboConstraint.FailureReason)
	}

	return nil
}

// DefaultAlgorithmUsagePolicy is the default algorithm usage policy.
var DefaultAlgorithmUsagePolicy = NewDefaultCMSAlgorithmUsagePolicy()

// StrictAlgorithmUsagePolicy is a stricter algorithm usage policy.
var StrictAlgorithmUsagePolicy = &DefaultCMSAlgorithmUsagePolicy{
	DisallowWeakAlgorithmsPolicy: NewDisallowWeakAlgorithmsPolicy(map[string]bool{
		"sha1":   true,
		"md5":    true,
		"md2":    true,
		"sha224": true, // SHA-224 also considered weak in strict mode
	}),
}
