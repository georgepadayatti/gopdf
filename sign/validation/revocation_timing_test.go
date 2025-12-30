package validation

import (
	"testing"
	"time"
)

func TestRevocationTimingStatusConstants(t *testing.T) {
	tests := []struct {
		status   RevocationTimingStatus
		expected string
	}{
		{RevocationTimingNotRevoked, "not_revoked"},
		{RevocationTimingRevokedBefore, "revoked_before_signing"},
		{RevocationTimingRevokedAfter, "revoked_after_signing"},
		{RevocationTimingUnknown, "unknown"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("RevocationTimingStatus %v = %s, want %s", tt.status, string(tt.status), tt.expected)
		}
	}
}

func TestRevocationTimingStatusString(t *testing.T) {
	status := RevocationTimingRevokedBefore
	if status.String() != "revoked_before_signing" {
		t.Errorf("RevocationTimingStatus.String() = %s, want revoked_before_signing", status.String())
	}
}

func TestIsRevokedBeforeSigning_EmbeddedTimestamp(t *testing.T) {
	// With embedded timestamp, we can reliably determine timing
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	t.Run("RevokedBeforeTimestamp", func(t *testing.T) {
		// Certificate revoked BEFORE signing - should return true
		revocationTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
		result := IsRevokedBeforeSigning(revocationTime, signingTime, TimeSourceEmbeddedTimestamp)
		if !result {
			t.Error("Expected true when certificate was revoked before signing time")
		}
	})

	t.Run("RevokedAfterTimestamp", func(t *testing.T) {
		// Certificate revoked AFTER signing - should return false
		revocationTime := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)
		result := IsRevokedBeforeSigning(revocationTime, signingTime, TimeSourceEmbeddedTimestamp)
		if result {
			t.Error("Expected false when certificate was revoked after signing time")
		}
	})

	t.Run("RevokedAtSameTime", func(t *testing.T) {
		// Certificate revoked at exactly the same time - should return false (Before returns false for equal times)
		result := IsRevokedBeforeSigning(signingTime, signingTime, TimeSourceEmbeddedTimestamp)
		if result {
			t.Error("Expected false when revocation time equals signing time")
		}
	})
}

func TestIsRevokedBeforeSigning_SignatureTime(t *testing.T) {
	// With signature time (untrusted), we must be conservative
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	t.Run("AlwaysConservativeWithSignatureTime", func(t *testing.T) {
		// Even if revocation is after signing time, we can't trust the signature time
		revocationTime := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)
		result := IsRevokedBeforeSigning(revocationTime, signingTime, TimeSourceSignatureTime)
		if !result {
			t.Error("Expected true (conservative) when using untrusted signature time")
		}
	})

	t.Run("ConservativeEvenForOlderRevocation", func(t *testing.T) {
		revocationTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
		result := IsRevokedBeforeSigning(revocationTime, signingTime, TimeSourceSignatureTime)
		if !result {
			t.Error("Expected true when using untrusted signature time")
		}
	})
}

func TestIsRevokedBeforeSigning_CurrentTime(t *testing.T) {
	// With current time (fallback), we must be conservative
	signingTime := time.Now()

	t.Run("AlwaysConservativeWithCurrentTime", func(t *testing.T) {
		revocationTime := time.Now().Add(-24 * time.Hour)
		result := IsRevokedBeforeSigning(revocationTime, signingTime, TimeSourceCurrentTime)
		if !result {
			t.Error("Expected true (conservative) when using current time")
		}
	})
}

func TestIsRevokedBeforeSigning_ZeroSigningTime(t *testing.T) {
	// With zero signing time, we must be conservative
	revocationTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
	var zeroTime time.Time

	result := IsRevokedBeforeSigning(revocationTime, zeroTime, TimeSourceEmbeddedTimestamp)
	if !result {
		t.Error("Expected true (conservative) when signing time is zero")
	}
}

func TestAnalyzeRevocationTiming_NotRevoked(t *testing.T) {
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	result := AnalyzeRevocationTiming(
		false,            // isRevoked
		nil,              // revocationTime
		"",               // revocationReason
		"",               // revocationSource
		signingTime,      // signingTime
		TimeSourceEmbeddedTimestamp,
	)

	if result.Status != RevocationTimingNotRevoked {
		t.Errorf("Status = %s, want not_revoked", result.Status)
	}
	if result.IsRevoked {
		t.Error("IsRevoked should be false")
	}
	if result.RevokedBeforeSigning {
		t.Error("RevokedBeforeSigning should be false")
	}
	if !result.CanDetermineTiming {
		t.Error("CanDetermineTiming should be true for not revoked")
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Expected no warnings for not revoked, got: %v", result.Warnings)
	}
}

func TestAnalyzeRevocationTiming_RevokedBeforeWithTimestamp(t *testing.T) {
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	revocationTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)

	result := AnalyzeRevocationTiming(
		true,
		&revocationTime,
		"keyCompromise",
		"OCSP",
		signingTime,
		TimeSourceEmbeddedTimestamp,
	)

	if result.Status != RevocationTimingRevokedBefore {
		t.Errorf("Status = %s, want revoked_before_signing", result.Status)
	}
	if !result.IsRevoked {
		t.Error("IsRevoked should be true")
	}
	if !result.RevokedBeforeSigning {
		t.Error("RevokedBeforeSigning should be true")
	}
	if !result.CanDetermineTiming {
		t.Error("CanDetermineTiming should be true with embedded timestamp")
	}
	if result.RevocationSource != "OCSP" {
		t.Errorf("RevocationSource = %s, want OCSP", result.RevocationSource)
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected critical warning for revoked before signing")
	}
	// Check for CRITICAL warning
	found := false
	for _, w := range result.Warnings {
		if containsSubstring(w, "CRITICAL") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected CRITICAL warning, got: %v", result.Warnings)
	}
}

func TestAnalyzeRevocationTiming_RevokedAfterWithTimestamp(t *testing.T) {
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	revocationTime := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC)

	result := AnalyzeRevocationTiming(
		true,
		&revocationTime,
		"cessationOfOperation",
		"CRL",
		signingTime,
		TimeSourceEmbeddedTimestamp,
	)

	if result.Status != RevocationTimingRevokedAfter {
		t.Errorf("Status = %s, want revoked_after_signing", result.Status)
	}
	if !result.IsRevoked {
		t.Error("IsRevoked should be true")
	}
	if result.RevokedBeforeSigning {
		t.Error("RevokedBeforeSigning should be false")
	}
	if !result.CanDetermineTiming {
		t.Error("CanDetermineTiming should be true with embedded timestamp")
	}
	if result.RevocationSource != "CRL" {
		t.Errorf("RevocationSource = %s, want CRL", result.RevocationSource)
	}
	// Should have informational warning, not critical
	if len(result.Warnings) == 0 {
		t.Error("Expected warning for revoked after signing")
	}
	for _, w := range result.Warnings {
		if containsSubstring(w, "CRITICAL") {
			t.Errorf("Should not have CRITICAL warning for revoked after signing, got: %s", w)
		}
	}
}

func TestAnalyzeRevocationTiming_RevokedWithUntrustedTime(t *testing.T) {
	// When using signature time (untrusted), we can't determine timing
	signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	revocationTime := time.Date(2024, 1, 20, 12, 0, 0, 0, time.UTC) // After signing

	result := AnalyzeRevocationTiming(
		true,
		&revocationTime,
		"keyCompromise",
		"OCSP",
		signingTime,
		TimeSourceSignatureTime, // Untrusted
	)

	// Even though revocation is "after" signing, we treat it as before (conservative)
	if result.Status != RevocationTimingRevokedBefore {
		t.Errorf("Status = %s, want revoked_before_signing (conservative)", result.Status)
	}
	if !result.RevokedBeforeSigning {
		t.Error("RevokedBeforeSigning should be true (conservative)")
	}
	if result.CanDetermineTiming {
		t.Error("CanDetermineTiming should be false with untrusted time source")
	}
	// Should have warning about untrusted time
	if len(result.Warnings) == 0 {
		t.Error("Expected warning about untrusted timestamp")
	}
}

func TestAnalyzeRevocationTiming_RevokedWithCurrentTime(t *testing.T) {
	signingTime := time.Now()
	revocationTime := time.Now().Add(24 * time.Hour) // Future revocation

	result := AnalyzeRevocationTiming(
		true,
		&revocationTime,
		"superseded",
		"OCSP",
		signingTime,
		TimeSourceCurrentTime, // Current time fallback
	)

	// Conservative: treat as revoked before
	if result.Status != RevocationTimingRevokedBefore {
		t.Errorf("Status = %s, want revoked_before_signing (conservative)", result.Status)
	}
	if result.CanDetermineTiming {
		t.Error("CanDetermineTiming should be false with current time")
	}
}

func TestRevocationTimingResult_Fields(t *testing.T) {
	revTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
	result := &RevocationTimingResult{
		Status:               RevocationTimingRevokedBefore,
		IsRevoked:            true,
		RevocationTime:       &revTime,
		RevocationReason:     "keyCompromise",
		RevocationSource:     "OCSP",
		RevokedBeforeSigning: true,
		CanDetermineTiming:   true,
		Warnings:             []string{"test warning"},
	}

	if result.Status != RevocationTimingRevokedBefore {
		t.Error("Status field not set correctly")
	}
	if !result.IsRevoked {
		t.Error("IsRevoked field not set correctly")
	}
	if result.RevocationTime == nil || !result.RevocationTime.Equal(revTime) {
		t.Error("RevocationTime field not set correctly")
	}
	if result.RevocationReason != "keyCompromise" {
		t.Error("RevocationReason field not set correctly")
	}
	if result.RevocationSource != "OCSP" {
		t.Error("RevocationSource field not set correctly")
	}
	if !result.RevokedBeforeSigning {
		t.Error("RevokedBeforeSigning field not set correctly")
	}
	if !result.CanDetermineTiming {
		t.Error("CanDetermineTiming field not set correctly")
	}
	if len(result.Warnings) != 1 || result.Warnings[0] != "test warning" {
		t.Error("Warnings field not set correctly")
	}
}

func TestSignatureValidationResult_RevocationResult(t *testing.T) {
	// Test that RevocationResult can be set on SignatureValidationResult
	revTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
	revResult := &RevocationTimingResult{
		Status:               RevocationTimingRevokedBefore,
		IsRevoked:            true,
		RevocationTime:       &revTime,
		RevokedBeforeSigning: true,
	}

	sigResult := &SignatureValidationResult{
		Status:           StatusInvalid,
		RevocationResult: revResult,
	}

	if sigResult.RevocationResult == nil {
		t.Error("RevocationResult should not be nil")
	}
	if sigResult.RevocationResult.Status != RevocationTimingRevokedBefore {
		t.Error("RevocationResult.Status not set correctly")
	}
	if !sigResult.RevocationResult.RevokedBeforeSigning {
		t.Error("RevocationResult.RevokedBeforeSigning not set correctly")
	}
}

func TestEdgeCases(t *testing.T) {
	t.Run("NilRevocationTime", func(t *testing.T) {
		signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
		result := AnalyzeRevocationTiming(
			true,  // isRevoked (but no time)
			nil,   // revocationTime
			"",
			"",
			signingTime,
			TimeSourceEmbeddedTimestamp,
		)

		// Without revocation time, treat as not revoked
		if result.Status != RevocationTimingNotRevoked {
			t.Errorf("Status = %s, want not_revoked when revocation time is nil", result.Status)
		}
	})

	t.Run("IsRevokedFalseWithTime", func(t *testing.T) {
		signingTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
		revTime := time.Date(2024, 1, 10, 12, 0, 0, 0, time.UTC)
		result := AnalyzeRevocationTiming(
			false, // isRevoked = false, even with revocation time
			&revTime,
			"",
			"",
			signingTime,
			TimeSourceEmbeddedTimestamp,
		)

		// isRevoked is false, so status should be not_revoked
		if result.Status != RevocationTimingNotRevoked {
			t.Errorf("Status = %s, want not_revoked when isRevoked is false", result.Status)
		}
	})
}

// Helper function for string contains check
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
