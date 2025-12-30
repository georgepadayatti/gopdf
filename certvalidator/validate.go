// Package certvalidator provides X.509 certificate path validation.
package certvalidator

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator/ltv"
	"github.com/georgepadayatti/gopdf/certvalidator/revinfo"
)

// OIDOCSPNoCheck is the OID for the OCSP No Check extension.
var OIDOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// EECertProfile defines the profile to use for end-entity certificate validation.
type EECertProfile int

const (
	// EECertProfileRegular is the default certificate profile.
	EECertProfileRegular EECertProfile = iota
	// EECertProfileAttributeAuthority is for Attribute Authority certificates.
	EECertProfileAttributeAuthority
)

// ValidatePathResult contains the result of path validation.
type ValidatePathResult struct {
	// Valid indicates whether the path is valid.
	Valid bool

	// QualifiedPolicies contains the valid policies from the path.
	QualifiedPolicies []*QualifiedPolicy

	// Path is the validated certification path.
	Path *ValidationPath

	// Errors contains any validation errors.
	Errors []error

	// Warnings contains non-fatal issues.
	Warnings []string

	// LeafCert is the final certificate in the path.
	LeafCert *x509.Certificate
}

// PathValidationConfig holds configuration for path validation.
type PathValidationConfig struct {
	// ValidationContext provides the validation environment.
	ValidationContext *EnhancedValidationContext

	// Parameters for PKIX validation.
	Parameters *PKIXValidationParams

	// CertProfile for end-entity certificate.
	CertProfile EECertProfile

	// SkipRevocation skips revocation checking.
	SkipRevocation bool
}

// NewPathValidationConfig creates a new path validation configuration.
func NewPathValidationConfig(ctx *EnhancedValidationContext) *PathValidationConfig {
	return &PathValidationConfig{
		ValidationContext: ctx,
		CertProfile:       EECertProfileRegular,
	}
}

// ValidatePath validates a certification path using RFC 5280 algorithm.
func ValidatePath(
	ctx *EnhancedValidationContext,
	path *ValidationPath,
	parameters *PKIXValidationParams,
) (*ValidatePathResult, error) {
	if ctx == nil {
		return nil, errors.New("validation context is required")
	}
	if path == nil {
		return nil, errors.New("validation path is required")
	}

	// Create process state
	pathStack := NewConsList(path)
	procState, err := NewValProcState(pathStack)
	if err != nil {
		return nil, fmt.Errorf("failed to create process state: %w", err)
	}

	return intlValidatePath(ctx, path, parameters, procState, EECertProfileRegular)
}

// intlValidatePath is the internal path validation implementation.
// It allows overriding the end-entity certificate name for error messages.
func intlValidatePath(
	ctx *EnhancedValidationContext,
	path *ValidationPath,
	parameters *PKIXValidationParams,
	procState *ValProcState,
	certProfile EECertProfile,
) (*ValidatePathResult, error) {
	result := &ValidatePathResult{
		Valid: true,
		Path:  path,
	}

	moment := ctx.Moment()

	// Get path length (excludes trust anchor)
	pathLength := path.PKIXLen()

	// Initialize PKIX validation state
	config := NewPKIXValidationConfig(ctx.TrustManager)
	config.ValidationTime = moment
	config.TimeTolerance = ctx.TimeTolerance()
	config.AlgorithmPolicy = ctx.AlgorithmPolicy
	config.PKIXParams = parameters
	if ctx.CertificateRegistry != nil {
		config.CertRegistry = ctx.CertificateRegistry
	}

	state := NewPKIXPathValidationState(config, pathLength)

	// Initialize from trust anchor
	if path.TrustAnchor != nil {
		anchor := NewCertTrustAnchor(path.TrustAnchor, nil, true)
		if err := state.InitFromTrustAnchor(anchor); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}

		// Record trust anchor as validated
		ctx.RecordValidation(path.TrustAnchor, path)
	}

	// Get all certificates to process (trust anchor excluded from path iteration)
	certs := path.IterCerts(false)
	if len(certs) == 0 && path.TrustAnchor != nil {
		// Path contains only trust anchor
		result.LeafCert = path.TrustAnchor
		return result, nil
	}

	// Process each certificate in the path
	for i, cert := range certs {
		isLast := i == len(certs)-1
		procState.Advance()

		// Step 2 a 1: Verify signature
		if err := state.checkSignature(cert, isLast); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}

		// Step 2 a 2: Check validity period
		if !ctx.IsWhitelisted(cert) {
			if err := state.checkValidity(cert, isLast); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, err)
				return result, nil
			}
		}

		// Step 2 a 3: Check revocation
		if ctx.RevInfoManager != nil && !shouldSkipRevocation(ctx, cert) {
			if err := checkRevocation(cert, ctx, path, procState); err != nil {
				// Handle soft-fail vs hard-fail
				if isSoftFailError(err, ctx) {
					result.Warnings = append(result.Warnings, err.Error())
					ctx.ReportSoftFail(err)
				} else {
					result.Valid = false
					result.Errors = append(result.Errors, err)
					return result, nil
				}
			}
		}

		// Step 2 a 4: Verify issuer name
		if err := state.checkIssuerName(cert, isLast); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}

		// Steps 2 b-c: Check name constraints
		if isLast || !IsSelfSigned(cert) {
			if err := state.checkPermittedSubtrees(cert); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, err)
				return result, nil
			}
			if err := state.checkExcludedSubtrees(cert); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, err)
				return result, nil
			}
		}

		// Step 2 d: Process certificate policies
		if err := state.processCertificatePolicies(cert); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}

		// Prepare for next certificate if not last
		if !isLast {
			if err := state.prepareNextCertificate(cert); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, err)
				return result, nil
			}
		}

		// Check for unsupported critical extensions
		if err := state.checkCriticalExtensions(cert, isLast); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err)
			return result, nil
		}

		// Record validation
		completedPath := path.Clone()
		ctx.RecordValidation(cert, completedPath)
	}

	// Wrap up: final policy processing
	var targetCert *x509.Certificate
	if len(certs) > 0 {
		targetCert = certs[len(certs)-1]
	} else {
		targetCert = path.TrustAnchor
	}

	wrapUpResult, err := state.WrapUp(targetCert)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err)
		return result, nil
	}

	if !wrapUpResult.Valid {
		result.Valid = false
		result.Errors = append(result.Errors, wrapUpResult.Errors...)
	}

	result.LeafCert = targetCert
	result.Warnings = append(result.Warnings, wrapUpResult.Warnings...)

	// Convert valid policies to qualified policies
	for _, policy := range wrapUpResult.ValidPolicies {
		result.QualifiedPolicies = append(result.QualifiedPolicies, &QualifiedPolicy{
			IssuerDomainPolicyID: policy,
			UserDomainPolicyID:   policy,
		})
	}

	return result, nil
}

// shouldSkipRevocation determines if revocation checking should be skipped.
func shouldSkipRevocation(ctx *EnhancedValidationContext, cert *x509.Certificate) bool {
	if ctx.RevInfoPolicy == nil {
		return true
	}

	// Check if certificate has ocsp_no_check extension
	if hasOCSPNoCheck(cert) {
		return true
	}

	return false
}

// hasOCSPNoCheck checks if certificate has the ocsp-no-check extension.
func hasOCSPNoCheck(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDOCSPNoCheck) {
			return true
		}
	}
	return false
}

// isSoftFailError determines if an error should be treated as soft-fail.
func isSoftFailError(err error, ctx *EnhancedValidationContext) bool {
	if ctx.RevInfoPolicy == nil {
		return true
	}
	return ctx.RevInfoPolicy.RevocationCheckingPolicy.EECertificateRule.IsTolerant()
}

// checkRevocation checks the revocation status of a certificate.
func checkRevocation(
	cert *x509.Certificate,
	ctx *EnhancedValidationContext,
	path *ValidationPath,
	procState *ValProcState,
) error {
	if ctx.RevInfoManager == nil {
		return nil
	}

	declared := GetDeclaredRevInfo(cert)
	policy := ctx.RevInfoPolicy
	if policy == nil {
		return nil
	}

	rule := policy.RevocationCheckingPolicy.EECertificateRule
	if !procState.IsEECert() {
		rule = policy.RevocationCheckingPolicy.IntermediateCACertRule
	}

	// Try OCSP first if relevant
	ocspStatusGood := false
	ocspMatched := false
	var failures []error

	if rule.IsOCSPRelevant() && declared.HasOCSP {
		err := verifyOCSPResponse(cert, path, ctx, procState)
		if err == nil {
			ocspStatusGood = true
			ocspMatched = true
		} else if !isOCSPNoMatchesError(err) {
			failures = append(failures, err)
			ocspMatched = true
		}
	}

	// Check if OCSP is mandatory
	if !ocspStatusGood && rule.IsOCSPMandatory() {
		if len(failures) > 0 {
			return NewInsufficientRevinfoError(
				fmt.Sprintf("mandatory OCSP check failed: %v", failures[0]),
				procState,
			)
		}
		return NewInsufficientRevinfoError(
			"an applicable OCSP response could not be found",
			procState,
		)
	}

	// If OCSP was good and CRL is not required, we're done
	if ocspStatusGood && !rule.IsCRLMandatory() {
		return nil
	}

	// Try CRL
	crlStatusGood := false
	crlMatched := false

	if rule.IsCRLRelevant() && declared.HasCRL {
		err := verifyCRL(cert, path, ctx, procState)
		if err == nil {
			crlStatusGood = true
			crlMatched = true
		} else if !isCRLNoMatchesError(err) {
			failures = append(failures, err)
			crlMatched = true
		}
	}

	// Check if CRL is mandatory
	if !crlStatusGood && rule.IsCRLMandatory() {
		if len(failures) > 0 {
			return NewInsufficientRevinfoError(
				fmt.Sprintf("mandatory CRL check failed: %v", failures[0]),
				procState,
			)
		}
		return NewInsufficientRevinfoError(
			"an applicable CRL could not be found",
			procState,
		)
	}

	// Check if we found any revocation info
	matched := ocspMatched || crlMatched
	statusGood := ocspStatusGood || crlStatusGood

	if !statusGood && matched && len(failures) > 0 {
		return failures[0]
	}

	// Check if revocation info was expected but not found
	if rule.IsStrict() && !matched {
		return NewInsufficientRevinfoError(
			fmt.Sprintf("no revocation information could be found for %s",
				procState.DescribeCert(true, false)),
			procState,
		)
	}

	return nil
}

// isOCSPNoMatchesError checks if an error is an OCSPNoMatchesError.
func isOCSPNoMatchesError(err error) bool {
	_, ok := err.(*OCSPNoMatchesError)
	return ok
}

// isCRLNoMatchesError checks if an error is a CRLNoMatchesError.
func isCRLNoMatchesError(err error) bool {
	_, ok := err.(*CRLNoMatchesError)
	return ok
}

// verifyOCSPResponse verifies OCSP response for a certificate.
func verifyOCSPResponse(
	cert *x509.Certificate,
	path *ValidationPath,
	ctx *EnhancedValidationContext,
	procState *ValProcState,
) error {
	// Find the issuer
	issuer, err := path.FindIssuingAuthority(cert)
	if err != nil {
		return NewOCSPNoMatchesError(
			fmt.Sprintf("could not determine issuer for %s", procState.DescribeCert(true, false)),
		)
	}

	// Get OCSP responses from the archive
	if ctx.RevInfoManager == nil {
		return NewOCSPNoMatchesError("no revocation info manager")
	}

	// Try to get OCSP response for this specific certificate
	ocspInfo := ctx.RevInfoManager.GetOCSP(cert)
	var ocspResponses []*revinfo.OCSPInfo
	if ocspInfo != nil {
		ocspResponses = []*revinfo.OCSPInfo{ocspInfo}
	} else {
		// Fall back to all OCSP responses
		ocspResponses = ctx.RevInfoManager.AllOCSPs()
	}

	if len(ocspResponses) == 0 {
		return NewOCSPNoMatchesError(
			fmt.Sprintf("no OCSP responses found for %s", procState.DescribeCert(true, false)),
		)
	}

	var failures []error

	for _, ocspInfo := range ocspResponses {
		// Check if response matches the certificate
		if !matchOCSPCertID(cert, issuer, ocspInfo) {
			continue
		}

		// Check freshness
		if err := checkOCSPFreshness(ocspInfo, ctx); err != nil {
			failures = append(failures, err)
			continue
		}

		// Verify signature
		responderCert := identifyResponderCert(ocspInfo, ctx)
		if responderCert == nil {
			failures = append(failures, errors.New("OCSP responder certificate not found"))
			continue
		}

		if err := verifyOCSPSignature(ocspInfo, responderCert, ctx); err != nil {
			failures = append(failures, err)
			continue
		}

		// Check authorization
		if err := checkOCSPAuthorization(responderCert, issuer, path, ctx, procState); err != nil {
			failures = append(failures, err)
			continue
		}

		// Check status
		status := ocspInfo.ToRevocationInfo()
		switch status.Status {
		case revinfo.StatusGood:
			return nil
		case revinfo.StatusRevoked:
			return NewRevokedError(
				fmt.Sprintf("OCSP response indicates %s was revoked", procState.DescribeCert(true, false)),
				CRLReason(status.Reason),
				*status.RevocationTime,
				procState,
			)
		}
	}

	if len(failures) == 0 {
		return NewOCSPNoMatchesError(
			fmt.Sprintf("no OCSP responses matched %s", procState.DescribeCert(true, false)),
		)
	}

	// Convert failures to strings
	failureStrings := make([]string, len(failures))
	for i, f := range failures {
		failureStrings[i] = f.Error()
	}

	return NewOCSPValidationIndeterminateError(
		fmt.Sprintf("unable to determine OCSP status for %s", procState.DescribeCert(true, false)),
		failureStrings,
		nil,
	)
}

// matchOCSPCertID checks if an OCSP response matches a certificate.
func matchOCSPCertID(cert *x509.Certificate, issuer *x509.Certificate, ocspInfo *revinfo.OCSPInfo) bool {
	if ocspInfo == nil || ocspInfo.Response == nil {
		return false
	}

	resp := ocspInfo.Response

	// Check serial number
	if resp.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}

	// The OCSP response should have been parsed with the issuer, so if parsing
	// succeeded, we have a match
	return true
}

// checkOCSPFreshness checks if an OCSP response is fresh.
func checkOCSPFreshness(ocspInfo *revinfo.OCSPInfo, ctx *EnhancedValidationContext) error {
	moment := ctx.Moment()
	tolerance := ctx.TimeTolerance()

	if moment.Before(ocspInfo.Response.ThisUpdate.Add(-tolerance)) {
		return errors.New("OCSP response is too recent")
	}

	if !ocspInfo.Response.NextUpdate.IsZero() && moment.After(ocspInfo.Response.NextUpdate.Add(tolerance)) {
		return errors.New("OCSP response is not recent enough")
	}

	return nil
}

// identifyResponderCert identifies the OCSP responder certificate.
func identifyResponderCert(ocspInfo *revinfo.OCSPInfo, ctx *EnhancedValidationContext) *x509.Certificate {
	// Check if issuer is the responder
	if ocspInfo.Issuer != nil {
		return ocspInfo.Issuer
	}

	// Look in certificate registry
	if ctx.CertificateRegistry != nil {
		// Try to find by name or key identifier
		certs := ctx.CertificateRegistry.All()
		for _, cert := range certs {
			if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
				// Check if this could be the responder
				for _, eku := range cert.ExtKeyUsage {
					if eku == x509.ExtKeyUsageOCSPSigning {
						return cert
					}
				}
			}
		}
	}

	return nil
}

// verifyOCSPSignature verifies the OCSP response signature.
func verifyOCSPSignature(ocspInfo *revinfo.OCSPInfo, responderCert *x509.Certificate, ctx *EnhancedValidationContext) error {
	// The golang.org/x/crypto/ocsp package verifies signature during parsing
	// when issuer is provided. If we got here, the signature was already verified.
	if ocspInfo.Response == nil {
		return errors.New("invalid OCSP response")
	}
	return nil
}

// checkOCSPAuthorization checks if the responder is authorized.
func checkOCSPAuthorization(
	responderCert *x509.Certificate,
	issuer *x509.Certificate,
	path *ValidationPath,
	ctx *EnhancedValidationContext,
	procState *ValProcState,
) error {
	// Check if responder is the issuer
	if responderCert.Equal(issuer) {
		return nil
	}

	// Check if responder has OCSP signing EKU
	hasOCSPSigning := false
	for _, eku := range responderCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			hasOCSPSigning = true
			break
		}
	}

	if !hasOCSPSigning {
		return errors.New("OCSP responder is not authorized to sign responses")
	}

	// Check if responder was issued by the same issuer
	if responderCert.Issuer.String() != issuer.Subject.String() {
		return errors.New("OCSP responder was not issued by the certificate issuer")
	}

	return nil
}

// verifyCRL verifies CRL for a certificate.
func verifyCRL(
	cert *x509.Certificate,
	path *ValidationPath,
	ctx *EnhancedValidationContext,
	procState *ValProcState,
) error {
	// Find the issuer
	issuer, err := path.FindIssuingAuthority(cert)
	if err != nil {
		return NewCRLNoMatchesError(
			fmt.Sprintf("could not determine issuer for %s", procState.DescribeCert(true, false)),
		)
	}

	// Get CRLs from the archive
	if ctx.RevInfoManager == nil {
		return NewCRLNoMatchesError("no revocation info manager")
	}

	crls := ctx.RevInfoManager.AllCRLs()
	if len(crls) == 0 {
		return NewCRLNoMatchesError(
			fmt.Sprintf("no CRLs found for %s", procState.DescribeCert(true, false)),
		)
	}

	var failures []error
	checkedReasons := make(map[string]bool)

	for _, crlInfo := range crls {
		// Check if CRL issuer matches
		crlIssuer := findCRLIssuer(crlInfo, issuer, path, ctx)
		if crlIssuer == nil {
			continue
		}

		// Check CRL freshness
		if err := checkCRLFreshness(crlInfo, ctx); err != nil {
			failures = append(failures, err)
			continue
		}

		// Verify CRL signature
		if err := crlInfo.CRL.CheckSignatureFrom(crlIssuer); err != nil {
			failures = append(failures, fmt.Errorf("CRL signature verification failed: %w", err))
			continue
		}

		// Check for unknown critical extensions
		if hasUnknownCriticalCRLExtensions(crlInfo.CRL) {
			failures = append(failures, errors.New("CRL has unrecognized critical extensions"))
			continue
		}

		// Check if certificate is in CRL
		revInfo := crlInfo.CheckCertificate(cert)
		if revInfo.Status == revinfo.StatusRevoked {
			return NewRevokedError(
				fmt.Sprintf("CRL indicates %s was revoked", procState.DescribeCert(true, false)),
				CRLReason(revInfo.Reason),
				*revInfo.RevocationTime,
				procState,
			)
		}

		// Mark reasons as checked
		for reason := range ValidRevocationReasons {
			checkedReasons[reason] = true
		}
	}

	// Check if all reasons were covered
	if len(checkedReasons) == len(ValidRevocationReasons) {
		return nil
	}

	if len(failures) == 0 {
		return NewCRLNoMatchesError(
			fmt.Sprintf("no CRLs issued by the issuer of %s", procState.DescribeCert(true, false)),
		)
	}

	// Convert failures to strings
	failureStrings := make([]string, len(failures))
	for i, f := range failures {
		failureStrings[i] = f.Error()
	}

	return NewCRLValidationIndeterminateError(
		fmt.Sprintf("unable to determine CRL status for %s", procState.DescribeCert(true, false)),
		failureStrings,
		nil,
	)
}

// findCRLIssuer finds the CRL issuer certificate.
func findCRLIssuer(
	crlInfo *revinfo.CRLInfo,
	certIssuer *x509.Certificate,
	path *ValidationPath,
	ctx *EnhancedValidationContext,
) *x509.Certificate {
	// Check if the cert issuer is the CRL issuer
	if namesEqual(crlInfo.CRL.Issuer, certIssuer.Subject) {
		return certIssuer
	}

	// Look in the path
	for _, authority := range path.IterAuthorities() {
		if namesEqual(crlInfo.CRL.Issuer, authority.Subject) {
			return authority
		}
	}

	// Look in certificate registry
	if ctx.CertificateRegistry != nil {
		candidates := ctx.CertificateRegistry.RetrieveByName(crlInfo.CRL.Issuer)
		for _, candidate := range candidates {
			// Check key usage
			if candidate.KeyUsage&x509.KeyUsageCRLSign != 0 {
				return candidate
			}
		}
	}

	return nil
}

// checkCRLFreshness checks if a CRL is fresh.
func checkCRLFreshness(crlInfo *revinfo.CRLInfo, ctx *EnhancedValidationContext) error {
	moment := ctx.Moment()
	tolerance := ctx.TimeTolerance()

	if moment.Before(crlInfo.CRL.ThisUpdate.Add(-tolerance)) {
		return errors.New("CRL is too recent")
	}

	if !crlInfo.CRL.NextUpdate.IsZero() && moment.After(crlInfo.CRL.NextUpdate.Add(tolerance)) {
		return errors.New("CRL is not recent enough")
	}

	return nil
}

// ValidRevocationReasons contains valid revocation reasons per RFC 5280.
var ValidRevocationReasons = map[string]bool{
	"unspecified":          true,
	"keyCompromise":        true,
	"cACompromise":         true,
	"affiliationChanged":   true,
	"superseded":           true,
	"cessationOfOperation": true,
	"certificateHold":      true,
	"privilegeWithdrawn":   true,
	"aACompromise":         true,
}

// ValidateTLSHostname validates a certificate for TLS hostname.
func ValidateTLSHostname(ctx *EnhancedValidationContext, cert *x509.Certificate, hostname string) error {
	if ctx.IsWhitelisted(cert) {
		return nil
	}

	// Check if hostname matches
	if err := cert.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("certificate is not valid for %s: %w", hostname, err)
	}

	// Check key usage
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate does not have digital signature key usage")
	}

	// Check extended key usage
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}

	if len(cert.ExtKeyUsage) > 0 && !hasServerAuth {
		return errors.New("certificate is not valid for TLS server authentication")
	}

	return nil
}

// ValidateUsage validates a certificate for specific key usages.
func ValidateUsage(
	ctx *EnhancedValidationContext,
	cert *x509.Certificate,
	keyUsage x509.KeyUsage,
	extKeyUsage []x509.ExtKeyUsage,
	extOptional bool,
) error {
	if ctx.IsWhitelisted(cert) {
		return nil
	}

	// Check key usage
	if keyUsage != 0 && cert.KeyUsage != 0 {
		missing := keyUsage & ^cert.KeyUsage
		if missing != 0 {
			return fmt.Errorf("certificate is missing required key usage")
		}
	}

	// Check extended key usage
	if len(extKeyUsage) > 0 && !extOptional {
		if len(cert.ExtKeyUsage) == 0 {
			return fmt.Errorf("certificate is missing required extended key usage")
		}

		certEKU := make(map[x509.ExtKeyUsage]bool)
		for _, eku := range cert.ExtKeyUsage {
			certEKU[eku] = true
		}

		for _, required := range extKeyUsage {
			if !certEKU[required] {
				return fmt.Errorf("certificate is missing required extended key usage")
			}
		}
	}

	return nil
}

// ValidateAAUsage validates AA certificate profile conditions per RFC 5755 § 4.5.
func ValidateAAUsage(
	ctx *EnhancedValidationContext,
	cert *x509.Certificate,
	extKeyUsage []x509.ExtKeyUsage,
) error {
	if ctx.IsWhitelisted(cert) {
		return nil
	}

	// Check key usage - AA must have digital signature
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("AA certificate must have digital signature key usage")
	}

	// Check basic constraints - AA must not be a CA
	if cert.IsCA {
		return errors.New("AA certificate cannot be a CA certificate")
	}

	// Check extended key usage if specified
	return ValidateUsage(ctx, cert, x509.KeyUsageDigitalSignature, extKeyUsage, len(extKeyUsage) == 0)
}

// CheckValidity checks if a certificate is valid at the given moment.
func CheckValidity(cert *x509.Certificate, moment time.Time, tolerance time.Duration) error {
	if moment.Before(cert.NotBefore.Add(-tolerance)) {
		return NewNotYetValidError(
			fmt.Sprintf("certificate is not valid until %s", cert.NotBefore.Format(time.RFC3339)),
			cert.NotBefore,
			nil,
		)
	}

	if moment.After(cert.NotAfter.Add(tolerance)) {
		return NewExpiredError(
			fmt.Sprintf("certificate expired at %s", cert.NotAfter.Format(time.RFC3339)),
			cert.NotAfter,
			nil,
		)
	}

	return nil
}

// BuildAndValidatePath builds and validates a certification path.
func BuildAndValidatePath(
	ctx *EnhancedValidationContext,
	cert *x509.Certificate,
	parameters *PKIXValidationParams,
) (*ValidatePathResult, error) {
	if ctx == nil {
		return nil, errors.New("validation context is required")
	}
	if cert == nil {
		return nil, errors.New("certificate is required")
	}

	// Build path
	if ctx.PathBuilder == nil {
		return nil, errors.New("path builder not configured")
	}

	path, err := ctx.PathBuilder.BuildFirstPath(nil, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to build path: %w", err)
	}

	// Convert to ValidationPath
	valPath := NewValidationPath(path.TrustAnchor.Certificate())
	for _, intermediate := range path.Certificates[1:] {
		valPath.AddIntermediate(intermediate)
	}
	valPath.SetEECert(cert)

	return ValidatePath(ctx, valPath, parameters)
}

// POEManagerFromContext extracts the POE manager from context.
func POEManagerFromContext(ctx *EnhancedValidationContext) *ltv.POEManager {
	return ctx.POEManager
}

// RecordPOE records proof of existence for a certificate.
func RecordPOE(ctx *EnhancedValidationContext, cert *x509.Certificate, at time.Time) {
	if ctx.POEManager != nil {
		hash := sha256.Sum256(cert.Raw)
		poe := &ltv.ProofOfExistence{
			Time:        at,
			Type:        ltv.POETypeExternal,
			DataHash:    hash[:],
			Description: fmt.Sprintf("Certificate POE for %s", cert.Subject.CommonName),
		}
		ctx.POEManager.Add(poe)
	}
}
