// Package certvalidator provides X.509 certificate path validation.
// This file contains signature validation abstractions.
package certvalidator

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Signature validation errors
var (
	// ErrAlgorithmNotSupported is returned when a signature algorithm is not supported.
	ErrAlgorithmNotSupported = errors.New("algorithm not supported")

	// ErrDSAParametersUnavailable is returned when DSA public key parameters are missing.
	ErrDSAParametersUnavailable = errors.New("DSA public key parameters unavailable")

	// ErrPSSParameterMismatch is returned when RSA-PSS parameters don't match.
	ErrPSSParameterMismatch = errors.New("PSS parameter mismatch")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")
)

// SignatureAlgorithm represents a signature algorithm identifier.
type SignatureAlgorithm int

const (
	// SigAlgoUnknown represents an unknown algorithm.
	SigAlgoUnknown SignatureAlgorithm = iota
	// SigAlgoRSAPKCS1v15 represents RSA PKCS#1 v1.5.
	SigAlgoRSAPKCS1v15
	// SigAlgoRSAPSS represents RSA-PSS.
	SigAlgoRSAPSS
	// SigAlgoDSA represents DSA.
	SigAlgoDSA
	// SigAlgoECDSA represents ECDSA.
	SigAlgoECDSA
	// SigAlgoEd25519 represents Ed25519.
	SigAlgoEd25519
	// SigAlgoEd448 represents Ed448.
	SigAlgoEd448
)

// String returns the string representation of the signature algorithm.
func (a SignatureAlgorithm) String() string {
	switch a {
	case SigAlgoRSAPKCS1v15:
		return "rsassa_pkcs1v15"
	case SigAlgoRSAPSS:
		return "rsassa_pss"
	case SigAlgoDSA:
		return "dsa"
	case SigAlgoECDSA:
		return "ecdsa"
	case SigAlgoEd25519:
		return "ed25519"
	case SigAlgoEd448:
		return "ed448"
	default:
		return "unknown"
	}
}

// OIDs for signature algorithms
var (
	// RSA algorithms
	OIDRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDRSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDRSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDRSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDRSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

	// DSA algorithms
	OIDDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OIDDSAWithSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}

	// ECDSA algorithms
	OIDECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OIDECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// EdDSA algorithms
	OIDEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	OIDEd448   = asn1.ObjectIdentifier{1, 3, 101, 113}

	// Hash algorithms
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// GetSignatureAlgorithmFromOID returns the signature algorithm for an OID.
func GetSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) SignatureAlgorithm {
	switch {
	case oid.Equal(OIDRSAWithSHA1), oid.Equal(OIDRSAWithSHA256),
		oid.Equal(OIDRSAWithSHA384), oid.Equal(OIDRSAWithSHA512),
		oid.Equal(OIDRSAEncryption):
		return SigAlgoRSAPKCS1v15
	case oid.Equal(OIDRSAPSS):
		return SigAlgoRSAPSS
	case oid.Equal(OIDDSAWithSHA1), oid.Equal(OIDDSAWithSHA256):
		return SigAlgoDSA
	case oid.Equal(OIDECDSAWithSHA1), oid.Equal(OIDECDSAWithSHA256),
		oid.Equal(OIDECDSAWithSHA384), oid.Equal(OIDECDSAWithSHA512):
		return SigAlgoECDSA
	case oid.Equal(OIDEd25519):
		return SigAlgoEd25519
	case oid.Equal(OIDEd448):
		return SigAlgoEd448
	default:
		return SigAlgoUnknown
	}
}

// GetHashAlgorithmFromOID returns the hash algorithm for an OID.
func GetHashAlgorithmFromOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(OIDSHA1):
		return crypto.SHA1
	case oid.Equal(OIDSHA256):
		return crypto.SHA256
	case oid.Equal(OIDSHA384):
		return crypto.SHA384
	case oid.Equal(OIDSHA512):
		return crypto.SHA512
	default:
		return 0
	}
}

// GetHashAlgorithmFromSigOID extracts the hash algorithm from a signature algorithm OID.
func GetHashAlgorithmFromSigOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(OIDRSAWithSHA1), oid.Equal(OIDDSAWithSHA1), oid.Equal(OIDECDSAWithSHA1):
		return crypto.SHA1
	case oid.Equal(OIDRSAWithSHA256), oid.Equal(OIDDSAWithSHA256), oid.Equal(OIDECDSAWithSHA256):
		return crypto.SHA256
	case oid.Equal(OIDRSAWithSHA384), oid.Equal(OIDECDSAWithSHA384):
		return crypto.SHA384
	case oid.Equal(OIDRSAWithSHA512), oid.Equal(OIDECDSAWithSHA512):
		return crypto.SHA512
	default:
		return 0
	}
}

// SignatureValidationContext provides additional context for signature validation.
type SignatureValidationContext struct {
	// ContextualMDAlgorithm is the digest algorithm inferred from context.
	// Used when the digest algorithm cannot be derived from the ASN.1 data.
	ContextualMDAlgorithm crypto.Hash

	// Prehashed indicates whether the payload was pre-hashed.
	Prehashed bool
}

// SignedDigestAlgorithm represents an ASN.1 SignedDigestAlgorithm structure.
type SignedDigestAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// GetSignatureAlgo returns the signature algorithm.
func (s *SignedDigestAlgorithm) GetSignatureAlgo() SignatureAlgorithm {
	return GetSignatureAlgorithmFromOID(s.Algorithm)
}

// GetHashAlgo returns the hash algorithm.
func (s *SignedDigestAlgorithm) GetHashAlgo() crypto.Hash {
	return GetHashAlgorithmFromSigOID(s.Algorithm)
}

// SignatureValidator abstracts cryptographic signature validation.
type SignatureValidator interface {
	// ValidateSignature validates a cryptographic signature.
	ValidateSignature(
		signature []byte,
		signedData []byte,
		publicKey crypto.PublicKey,
		sigAlgorithm *SignedDigestAlgorithm,
		context *SignatureValidationContext,
	) error
}

// DefaultSignatureValidator is the default implementation of SignatureValidator.
type DefaultSignatureValidator struct{}

// NewDefaultSignatureValidator creates a new default signature validator.
func NewDefaultSignatureValidator() *DefaultSignatureValidator {
	return &DefaultSignatureValidator{}
}

// ValidateSignature validates a signature using Go's crypto libraries.
func (v *DefaultSignatureValidator) ValidateSignature(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
	sigAlgorithm *SignedDigestAlgorithm,
	context *SignatureValidationContext,
) error {
	if context == nil {
		context = &SignatureValidationContext{}
	}

	sigAlgo := sigAlgorithm.GetSignatureAlgo()
	hashAlgo := sigAlgorithm.GetHashAlgo()

	// Use contextual hash algorithm if not determined from OID
	if hashAlgo == 0 {
		hashAlgo = context.ContextualMDAlgorithm
	}

	switch sigAlgo {
	case SigAlgoRSAPKCS1v15:
		return v.verifyRSAPKCS1v15(signature, signedData, publicKey, hashAlgo, context.Prehashed)

	case SigAlgoRSAPSS:
		return v.verifyRSAPSS(signature, signedData, publicKey, sigAlgorithm, context)

	case SigAlgoDSA:
		return v.verifyDSA(signature, signedData, publicKey, hashAlgo, context.Prehashed)

	case SigAlgoECDSA:
		return v.verifyECDSA(signature, signedData, publicKey, hashAlgo, context.Prehashed)

	case SigAlgoEd25519:
		return v.verifyEd25519(signature, signedData, publicKey)

	case SigAlgoEd448:
		return fmt.Errorf("%w: Ed448", ErrAlgorithmNotSupported)

	default:
		return fmt.Errorf("%w: %s", ErrAlgorithmNotSupported, sigAlgo.String())
	}
}

// verifyRSAPKCS1v15 verifies an RSA PKCS#1 v1.5 signature.
func (v *DefaultSignatureValidator) verifyRSAPKCS1v15(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
	hashAlgo crypto.Hash,
	prehashed bool,
) error {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected RSA public key, got %T", publicKey)
	}

	var hash []byte
	if prehashed {
		hash = signedData
	} else {
		h := hashAlgo.New()
		h.Write(signedData)
		hash = h.Sum(nil)
	}

	err := rsa.VerifyPKCS1v15(rsaKey, hashAlgo, hash, signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

// RSAPSSParams represents RSA-PSS parameters.
type RSAPSSParams struct {
	HashAlgorithm    AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength       int                 `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField     int                 `asn1:"optional,explicit,tag:3,default:1"`
}

// verifyRSAPSS verifies an RSA-PSS signature.
func (v *DefaultSignatureValidator) verifyRSAPSS(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
	sigAlgorithm *SignedDigestAlgorithm,
	context *SignatureValidationContext,
) error {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected RSA public key, got %T", publicKey)
	}

	// Parse PSS parameters
	var pssParams RSAPSSParams
	pssParams.SaltLength = 20 // Default
	if len(sigAlgorithm.Parameters.Bytes) > 0 {
		_, err := asn1.Unmarshal(sigAlgorithm.Parameters.FullBytes, &pssParams)
		if err != nil {
			return fmt.Errorf("failed to parse PSS parameters: %w", err)
		}
	}

	// Determine hash algorithm from PSS parameters or context
	hashAlgo := GetHashAlgorithmFromOID(pssParams.HashAlgorithm.Algorithm)
	if hashAlgo == 0 && context != nil {
		hashAlgo = context.ContextualMDAlgorithm
	}
	if hashAlgo == 0 {
		hashAlgo = crypto.SHA1 // Default for PSS
	}

	prehashed := context != nil && context.Prehashed
	var hash []byte
	if prehashed {
		hash = signedData
	} else {
		h := hashAlgo.New()
		h.Write(signedData)
		hash = h.Sum(nil)
	}

	opts := &rsa.PSSOptions{
		SaltLength: pssParams.SaltLength,
		Hash:       hashAlgo,
	}

	err := rsa.VerifyPSS(rsaKey, hashAlgo, hash, signature, opts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

// verifyDSA verifies a DSA signature.
func (v *DefaultSignatureValidator) verifyDSA(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
	hashAlgo crypto.Hash,
	prehashed bool,
) error {
	dsaKey, ok := publicKey.(*dsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected DSA public key, got %T", publicKey)
	}

	// Check for missing parameters
	if dsaKey.P == nil || dsaKey.Q == nil || dsaKey.G == nil {
		return ErrDSAParametersUnavailable
	}

	var hash []byte
	if prehashed {
		hash = signedData
	} else {
		h := hashAlgo.New()
		h.Write(signedData)
		hash = h.Sum(nil)
	}

	// Parse DSA signature (r, s)
	var dsaSig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(signature, &dsaSig)
	if err != nil {
		return fmt.Errorf("failed to parse DSA signature: %w", err)
	}

	if !dsa.Verify(dsaKey, hash, dsaSig.R, dsaSig.S) {
		return ErrInvalidSignature
	}
	return nil
}

// verifyECDSA verifies an ECDSA signature.
func (v *DefaultSignatureValidator) verifyECDSA(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
	hashAlgo crypto.Hash,
	prehashed bool,
) error {
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected ECDSA public key, got %T", publicKey)
	}

	var hash []byte
	if prehashed {
		hash = signedData
	} else {
		h := hashAlgo.New()
		h.Write(signedData)
		hash = h.Sum(nil)
	}

	// Try to parse as ASN.1 encoded signature first
	var ecdsaSig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(signature, &ecdsaSig)
	if err == nil {
		// ASN.1 encoded signature
		if !ecdsa.Verify(ecdsaKey, hash, ecdsaSig.R, ecdsaSig.S) {
			return ErrInvalidSignature
		}
		return nil
	}

	// Try raw signature format (r || s)
	keySize := (ecdsaKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature length")
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(ecdsaKey, hash, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// verifyEd25519 verifies an Ed25519 signature.
func (v *DefaultSignatureValidator) verifyEd25519(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
) error {
	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected Ed25519 public key, got %T", publicKey)
	}

	if !ed25519.Verify(ed25519Key, signedData, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// ValidateSignatureWithCert validates a signature using a certificate's public key.
func ValidateSignatureWithCert(
	signature []byte,
	signedData []byte,
	cert *x509.Certificate,
	sigAlgorithm *SignedDigestAlgorithm,
	context *SignatureValidationContext,
) error {
	validator := NewDefaultSignatureValidator()
	return validator.ValidateSignature(signature, signedData, cert.PublicKey, sigAlgorithm, context)
}

// ValidateSignatureRaw is a convenience function for raw signature validation.
func ValidateSignatureRaw(
	signature []byte,
	signedData []byte,
	publicKey crypto.PublicKey,
	sigAlgoOID asn1.ObjectIdentifier,
	hashAlgo crypto.Hash,
) error {
	sigAlgorithm := &SignedDigestAlgorithm{Algorithm: sigAlgoOID}
	context := &SignatureValidationContext{ContextualMDAlgorithm: hashAlgo}
	validator := NewDefaultSignatureValidator()
	return validator.ValidateSignature(signature, signedData, publicKey, sigAlgorithm, context)
}
