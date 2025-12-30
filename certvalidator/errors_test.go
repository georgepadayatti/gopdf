package certvalidator

import (
	"testing"
	"time"
)

func TestCRLReasonString(t *testing.T) {
	tests := []struct {
		reason   CRLReason
		expected string
	}{
		{CRLReasonUnspecified, "unspecified"},
		{CRLReasonKeyCompromise, "key compromise"},
		{CRLReasonCACompromise, "CA compromise"},
		{CRLReasonAffiliationChanged, "affiliation changed"},
		{CRLReasonSuperseded, "superseded"},
		{CRLReasonCessationOfOperation, "cessation of operation"},
		{CRLReasonCertificateHold, "certificate hold"},
		{CRLReasonRemoveFromCRL, "remove from CRL"},
		{CRLReasonPrivilegeWithdrawn, "privilege withdrawn"},
		{CRLReasonAACompromise, "AA compromise"},
		{CRLReason(99), "unknown reason (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.reason.String(); got != tt.expected {
				t.Errorf("CRLReason.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPathError(t *testing.T) {
	err := NewPathError("path error message")
	if err.Error() != "path error message" {
		t.Errorf("PathError.Error() = %v, want %v", err.Error(), "path error message")
	}
}

func TestPathBuildingError(t *testing.T) {
	err := NewPathBuildingError("could not build path")
	if err.Error() != "could not build path" {
		t.Errorf("PathBuildingError.Error() = %v, want %v", err.Error(), "could not build path")
	}
}

func TestCertificateFetchError(t *testing.T) {
	err := NewCertificateFetchError("could not fetch certificate")
	if err.Error() != "could not fetch certificate" {
		t.Errorf("CertificateFetchError.Error() = %v, want %v", err.Error(), "could not fetch certificate")
	}
}

func TestCRLValidationError(t *testing.T) {
	err := NewCRLValidationError("CRL validation failed")
	if err.Error() != "CRL validation failed" {
		t.Errorf("CRLValidationError.Error() = %v, want %v", err.Error(), "CRL validation failed")
	}
}

func TestCRLNoMatchesError(t *testing.T) {
	err := NewCRLNoMatchesError("no matching CRL found")
	if err.Error() != "no matching CRL found" {
		t.Errorf("CRLNoMatchesError.Error() = %v, want %v", err.Error(), "no matching CRL found")
	}
}

func TestCRLFetchError(t *testing.T) {
	err := NewCRLFetchError("could not fetch CRL")
	if err.Error() != "could not fetch CRL" {
		t.Errorf("CRLFetchError.Error() = %v, want %v", err.Error(), "could not fetch CRL")
	}
}

func TestCRLValidationIndeterminateError(t *testing.T) {
	staleTime := time.Now().Add(-24 * time.Hour)
	failures := []string{"failure 1", "failure 2"}
	err := NewCRLValidationIndeterminateError("CRL validation indeterminate", failures, &staleTime)

	if err.Error() != "CRL validation indeterminate" {
		t.Errorf("CRLValidationIndeterminateError.Error() = %v, want %v", err.Error(), "CRL validation indeterminate")
	}
	if len(err.Failures) != 2 {
		t.Errorf("CRLValidationIndeterminateError.Failures = %v, want 2 elements", len(err.Failures))
	}
	if err.SuspectStale == nil {
		t.Error("CRLValidationIndeterminateError.SuspectStale should not be nil")
	}
}

func TestOCSPValidationError(t *testing.T) {
	err := NewOCSPValidationError("OCSP validation failed")
	if err.Error() != "OCSP validation failed" {
		t.Errorf("OCSPValidationError.Error() = %v, want %v", err.Error(), "OCSP validation failed")
	}
}

func TestOCSPNoMatchesError(t *testing.T) {
	err := NewOCSPNoMatchesError("no matching OCSP response found")
	if err.Error() != "no matching OCSP response found" {
		t.Errorf("OCSPNoMatchesError.Error() = %v, want %v", err.Error(), "no matching OCSP response found")
	}
}

func TestOCSPFetchError(t *testing.T) {
	err := NewOCSPFetchError("could not fetch OCSP response")
	if err.Error() != "could not fetch OCSP response" {
		t.Errorf("OCSPFetchError.Error() = %v, want %v", err.Error(), "could not fetch OCSP response")
	}
}

func TestOCSPValidationIndeterminateError(t *testing.T) {
	failures := []string{"failure 1"}
	err := NewOCSPValidationIndeterminateError("OCSP validation indeterminate", failures, nil)

	if err.Error() != "OCSP validation indeterminate" {
		t.Errorf("OCSPValidationIndeterminateError.Error() = %v, want %v", err.Error(), "OCSP validation indeterminate")
	}
	if len(err.Failures) != 1 {
		t.Errorf("OCSPValidationIndeterminateError.Failures = %v, want 1 element", len(err.Failures))
	}
	if err.SuspectStale != nil {
		t.Error("OCSPValidationIndeterminateError.SuspectStale should be nil")
	}
}

func TestValidationError(t *testing.T) {
	err := NewValidationError("validation failed")
	if err.Error() != "validation failed" {
		t.Errorf("ValidationError.Error() = %v, want %v", err.Error(), "validation failed")
	}
	if err.FailureMsg != "validation failed" {
		t.Errorf("ValidationError.FailureMsg = %v, want %v", err.FailureMsg, "validation failed")
	}
}

func TestPathValidationError(t *testing.T) {
	err := NewPathValidationError("path validation failed", nil)
	if err.Error() != "path validation failed" {
		t.Errorf("PathValidationError.Error() = %v, want %v", err.Error(), "path validation failed")
	}
	if err.CurrentPath != nil {
		t.Error("PathValidationError.CurrentPath should be nil when procState is nil")
	}
}

func TestPathValidationErrorWithState(t *testing.T) {
	path := NewValidationPath(nil)
	stack := NewConsList(path)
	state, _ := NewValProcState(stack)

	err := NewPathValidationError("path validation failed", state)
	if err.CurrentPath != path {
		t.Error("PathValidationError.CurrentPath should match the path from state")
	}
	if err.OriginalPath != path {
		t.Error("PathValidationError.OriginalPath should match the path from state")
	}
}

func TestRevokedError(t *testing.T) {
	revocationTime := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC)
	err := NewRevokedError("certificate revoked", CRLReasonKeyCompromise, revocationTime, nil)

	if err.Reason != CRLReasonKeyCompromise {
		t.Errorf("RevokedError.Reason = %v, want %v", err.Reason, CRLReasonKeyCompromise)
	}
	if !err.RevocationDt.Equal(revocationTime) {
		t.Errorf("RevokedError.RevocationDt = %v, want %v", err.RevocationDt, revocationTime)
	}
}

func TestFormatRevokedError(t *testing.T) {
	revocationTime := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC)
	err := FormatRevokedError(CRLReasonKeyCompromise, revocationTime, "CRL", nil)

	expected := "CRL indicates the certificate was revoked at 14:30:00 on 2024-06-15, due to key compromise."
	if err.Error() != expected {
		t.Errorf("FormatRevokedError() = %v, want %v", err.Error(), expected)
	}
}

func TestInsufficientRevinfoError(t *testing.T) {
	err := NewInsufficientRevinfoError("insufficient revocation info", nil)
	if err.Error() != "insufficient revocation info" {
		t.Errorf("InsufficientRevinfoError.Error() = %v, want %v", err.Error(), "insufficient revocation info")
	}
}

func TestStaleRevinfoError(t *testing.T) {
	cutoff := time.Now().Add(-24 * time.Hour)
	err := NewStaleRevinfoError("stale revocation info", cutoff, nil)

	if err.Error() != "stale revocation info" {
		t.Errorf("StaleRevinfoError.Error() = %v, want %v", err.Error(), "stale revocation info")
	}
	if !err.TimeCutoff.Equal(cutoff) {
		t.Errorf("StaleRevinfoError.TimeCutoff = %v, want %v", err.TimeCutoff, cutoff)
	}
}

func TestInsufficientPOEError(t *testing.T) {
	err := NewInsufficientPOEError("insufficient proof of existence", nil)
	if err.Error() != "insufficient proof of existence" {
		t.Errorf("InsufficientPOEError.Error() = %v, want %v", err.Error(), "insufficient proof of existence")
	}
}

func TestExpiredError(t *testing.T) {
	expiredTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	err := NewExpiredError("certificate expired", expiredTime, nil)

	if !err.ExpiredDt.Equal(expiredTime) {
		t.Errorf("ExpiredError.ExpiredDt = %v, want %v", err.ExpiredDt, expiredTime)
	}
}

func TestFormatExpiredError(t *testing.T) {
	expiredTime := time.Date(2024, 1, 1, 12, 30, 45, 0, time.UTC)
	err := FormatExpiredError(expiredTime, nil)

	expected := "The path could not be validated because the certificate expired 2024-01-01 12:30:45Z"
	if err.Error() != expected {
		t.Errorf("FormatExpiredError() = %v, want %v", err.Error(), expected)
	}
}

func TestNotYetValidError(t *testing.T) {
	validFrom := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	err := NewNotYetValidError("certificate not yet valid", validFrom, nil)

	if !err.ValidFrom.Equal(validFrom) {
		t.Errorf("NotYetValidError.ValidFrom = %v, want %v", err.ValidFrom, validFrom)
	}
}

func TestFormatNotYetValidError(t *testing.T) {
	validFrom := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	err := FormatNotYetValidError(validFrom, nil)

	expected := "The path could not be validated because the certificate is not valid until 2025-12-01 00:00:00Z"
	if err.Error() != expected {
		t.Errorf("FormatNotYetValidError() = %v, want %v", err.Error(), expected)
	}
}

func TestInvalidCertificateError(t *testing.T) {
	err := NewInvalidCertificateError("invalid certificate")
	if err.Error() != "invalid certificate" {
		t.Errorf("InvalidCertificateError.Error() = %v, want %v", err.Error(), "invalid certificate")
	}
}

func TestDisallowedAlgorithmError(t *testing.T) {
	bannedSince := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	err := NewDisallowedAlgorithmError("SHA-1 not allowed", nil, &bannedSince)

	if err.Error() != "SHA-1 not allowed" {
		t.Errorf("DisallowedAlgorithmError.Error() = %v, want %v", err.Error(), "SHA-1 not allowed")
	}
	if err.BannedSince == nil || !err.BannedSince.Equal(bannedSince) {
		t.Errorf("DisallowedAlgorithmError.BannedSince = %v, want %v", err.BannedSince, bannedSince)
	}
}

func TestInvalidAttrCertificateError(t *testing.T) {
	err := NewInvalidAttrCertificateError("invalid attribute certificate")
	if err.Error() != "invalid attribute certificate" {
		t.Errorf("InvalidAttrCertificateError.Error() = %v, want %v", err.Error(), "invalid attribute certificate")
	}
}

func TestPSSParameterMismatch(t *testing.T) {
	err := NewPSSParameterMismatch("PSS parameters do not match")
	if err.Error() != "PSS parameters do not match" {
		t.Errorf("PSSParameterMismatch.Error() = %v, want %v", err.Error(), "PSS parameters do not match")
	}
}

func TestDSAParametersUnavailable(t *testing.T) {
	err := NewDSAParametersUnavailable("DSA parameters not available")
	if err.Error() != "DSA parameters not available" {
		t.Errorf("DSAParametersUnavailable.Error() = %v, want %v", err.Error(), "DSA parameters not available")
	}
}

func TestAlgorithmNotSupported(t *testing.T) {
	err := NewAlgorithmNotSupported("algorithm not supported")
	if err.Error() != "algorithm not supported" {
		t.Errorf("AlgorithmNotSupported.Error() = %v, want %v", err.Error(), "algorithm not supported")
	}
}

func TestNameConstraintError(t *testing.T) {
	err := NewNameConstraintError("name constraint violation")
	if err.Error() != "name constraint violation" {
		t.Errorf("NameConstraintError.Error() = %v, want %v", err.Error(), "name constraint violation")
	}
}

func TestUnsupportedNameTypeError(t *testing.T) {
	err := NewUnsupportedNameTypeError(99)
	expected := "unsupported general name type: 99"
	if err.Error() != expected {
		t.Errorf("UnsupportedNameTypeError.Error() = %v, want %v", err.Error(), expected)
	}
	if err.NameType != 99 {
		t.Errorf("UnsupportedNameTypeError.NameType = %v, want %v", err.NameType, 99)
	}
}

func TestErrors(t *testing.T) {
	errs := NewErrors()

	// Test empty state
	if errs.HasErrors() {
		t.Error("NewErrors should have no errors initially")
	}
	if errs.Count() != 0 {
		t.Errorf("NewErrors.Count() = %v, want 0", errs.Count())
	}
	if errs.First() != nil {
		t.Error("NewErrors.First() should be nil initially")
	}
	if errs.Combined() != nil {
		t.Error("NewErrors.Combined() should be nil initially")
	}

	// Add errors
	errs.Add(NewPathError("error 1"))
	errs.Add(nil) // Should be ignored
	errs.Add(NewPathError("error 2"))

	if !errs.HasErrors() {
		t.Error("Errors should have errors after Add")
	}
	if errs.Count() != 2 {
		t.Errorf("Errors.Count() = %v, want 2", errs.Count())
	}
	if errs.First().Error() != "error 1" {
		t.Errorf("Errors.First() = %v, want 'error 1'", errs.First().Error())
	}
	if len(errs.All()) != 2 {
		t.Errorf("Errors.All() = %v, want 2 elements", len(errs.All()))
	}

	// Test Combined
	combined := errs.Combined()
	if combined == nil {
		t.Error("Errors.Combined() should not be nil")
	}

	// Test Clear
	errs.Clear()
	if errs.HasErrors() {
		t.Error("Errors should have no errors after Clear")
	}
}

func TestErrorsSingleError(t *testing.T) {
	errs := NewErrors()
	errs.Add(NewPathError("single error"))

	combined := errs.Combined()
	if combined.Error() != "single error" {
		t.Errorf("Errors.Combined() with single error = %v, want 'single error'", combined.Error())
	}
}
