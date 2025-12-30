package validation

import (
	"testing"
	"time"
)

func TestTimeSourceConstants(t *testing.T) {
	tests := []struct {
		ts       TimeSource
		expected string
	}{
		{TimeSourceEmbeddedTimestamp, "embedded_timestamp"},
		{TimeSourceSignatureTime, "signature_time"},
		{TimeSourceCurrentTime, "current_time"},
	}

	for _, tt := range tests {
		if string(tt.ts) != tt.expected {
			t.Errorf("TimeSource %v = %s, want %s", tt.ts, string(tt.ts), tt.expected)
		}
	}
}

func TestTimeSourceString(t *testing.T) {
	ts := TimeSourceEmbeddedTimestamp
	if ts.String() != "embedded_timestamp" {
		t.Errorf("TimeSource.String() = %s, want embedded_timestamp", ts.String())
	}
}

func TestTimeSourceIsTrusted(t *testing.T) {
	tests := []struct {
		ts       TimeSource
		expected bool
	}{
		{TimeSourceEmbeddedTimestamp, true},
		{TimeSourceSignatureTime, false},
		{TimeSourceCurrentTime, false},
	}

	for _, tt := range tests {
		if tt.ts.IsTrusted() != tt.expected {
			t.Errorf("TimeSource(%s).IsTrusted() = %v, want %v", tt.ts, tt.ts.IsTrusted(), tt.expected)
		}
	}
}

func TestTimestampStatusConstants(t *testing.T) {
	tests := []struct {
		ts       TimestampStatus
		expected string
	}{
		{TimestampStatusValid, "valid"},
		{TimestampStatusInvalid, "invalid"},
		{TimestampStatusMissing, "missing"},
	}

	for _, tt := range tests {
		if string(tt.ts) != tt.expected {
			t.Errorf("TimestampStatus %v = %s, want %s", tt.ts, string(tt.ts), tt.expected)
		}
	}
}

func TestTimestampStatusString(t *testing.T) {
	ts := TimestampStatusValid
	if ts.String() != "valid" {
		t.Errorf("TimestampStatus.String() = %s, want valid", ts.String())
	}
}

func TestDetermineVerificationTime_EmbeddedTimestamp(t *testing.T) {
	validator := NewSignatureValidator(DefaultValidatorSettings())

	timestampTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	signatureTime := time.Date(2024, 1, 15, 10, 29, 0, 0, time.UTC)

	timeResult := &TimeValidationResult{
		TimestampTime:   timestampTime,
		SignatureTime:   signatureTime,
		TimestampStatus: TimestampStatusValid,
	}

	result := validator.determineVerificationTime(timeResult)

	if result.TimeSource != TimeSourceEmbeddedTimestamp {
		t.Errorf("TimeSource = %s, want %s", result.TimeSource, TimeSourceEmbeddedTimestamp)
	}
	if !result.VerificationTime.Equal(timestampTime) {
		t.Errorf("VerificationTime = %v, want %v", result.VerificationTime, timestampTime)
	}
	if len(result.TimeWarnings) != 0 {
		t.Errorf("Expected no warnings for embedded timestamp, got: %v", result.TimeWarnings)
	}
}

func TestDetermineVerificationTime_SignatureTime_Trusted(t *testing.T) {
	settings := LenientValidatorSettings() // TrustSignatureTime = true
	validator := NewSignatureValidator(settings)

	signatureTime := time.Date(2024, 1, 15, 10, 29, 0, 0, time.UTC)

	timeResult := &TimeValidationResult{
		SignatureTime:   signatureTime,
		TimestampStatus: TimestampStatusMissing,
	}

	result := validator.determineVerificationTime(timeResult)

	if result.TimeSource != TimeSourceSignatureTime {
		t.Errorf("TimeSource = %s, want %s", result.TimeSource, TimeSourceSignatureTime)
	}
	if !result.VerificationTime.Equal(signatureTime) {
		t.Errorf("VerificationTime = %v, want %v", result.VerificationTime, signatureTime)
	}
	if len(result.TimeWarnings) == 0 {
		t.Error("Expected warning for signature time usage")
	}
}

func TestDetermineVerificationTime_SignatureTime_NotTrusted(t *testing.T) {
	settings := DefaultValidatorSettings() // TrustSignatureTime = false
	validator := NewSignatureValidator(settings)

	signatureTime := time.Date(2024, 1, 15, 10, 29, 0, 0, time.UTC)

	timeResult := &TimeValidationResult{
		SignatureTime:   signatureTime,
		TimestampStatus: TimestampStatusMissing,
	}

	result := validator.determineVerificationTime(timeResult)

	if result.TimeSource != TimeSourceCurrentTime {
		t.Errorf("TimeSource = %s, want %s", result.TimeSource, TimeSourceCurrentTime)
	}
	// Should use current time, not signature time
	if result.VerificationTime.Equal(signatureTime) {
		t.Error("Should not use signature time when TrustSignatureTime=false")
	}
	if len(result.TimeWarnings) == 0 {
		t.Error("Expected warning about signature time not being trusted")
	}
}

func TestDetermineVerificationTime_CurrentTime_Fallback(t *testing.T) {
	settings := DefaultValidatorSettings()
	validator := NewSignatureValidator(settings)

	timeResult := &TimeValidationResult{
		TimestampStatus: TimestampStatusMissing,
	}

	beforeTest := time.Now()
	result := validator.determineVerificationTime(timeResult)
	afterTest := time.Now()

	if result.TimeSource != TimeSourceCurrentTime {
		t.Errorf("TimeSource = %s, want %s", result.TimeSource, TimeSourceCurrentTime)
	}
	if result.VerificationTime.Before(beforeTest) || result.VerificationTime.After(afterTest) {
		t.Error("VerificationTime should be approximately now")
	}
	if len(result.TimeWarnings) == 0 {
		t.Error("Expected warning about using current time")
	}
}

func TestDetermineVerificationTime_ExplicitValidationTime(t *testing.T) {
	explicitTime := time.Date(2023, 6, 1, 12, 0, 0, 0, time.UTC)
	settings := DefaultValidatorSettings()
	settings.ValidationTime = explicitTime
	validator := NewSignatureValidator(settings)

	timestampTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	timeResult := &TimeValidationResult{
		TimestampTime:   timestampTime,
		TimestampStatus: TimestampStatusValid,
	}

	result := validator.determineVerificationTime(timeResult)

	// Explicit time should override even embedded timestamp
	if !result.VerificationTime.Equal(explicitTime) {
		t.Errorf("VerificationTime = %v, want %v (explicit)", result.VerificationTime, explicitTime)
	}
	if len(result.TimeWarnings) == 0 {
		t.Error("Expected warning about using explicit validation time")
	}
}

func TestTimeValidationResult_Initialization(t *testing.T) {
	result := &TimeValidationResult{
		TimeSource:      TimeSourceCurrentTime,
		TimestampStatus: TimestampStatusMissing,
	}

	if result.TimeSource != TimeSourceCurrentTime {
		t.Errorf("Initial TimeSource = %s, want current_time", result.TimeSource)
	}
	if result.TimestampStatus != TimestampStatusMissing {
		t.Errorf("Initial TimestampStatus = %s, want missing", result.TimestampStatus)
	}
	if result.TimestampTrusted {
		t.Error("Initial TimestampTrusted should be false")
	}
	if len(result.TimeWarnings) != 0 {
		t.Error("Initial TimeWarnings should be empty")
	}
}

func TestDefaultValidatorSettings_TimeSettings(t *testing.T) {
	settings := DefaultValidatorSettings()

	if settings.TrustSignatureTime {
		t.Error("Default TrustSignatureTime should be false (secure default)")
	}
	if !settings.ValidateTimestampCertificates {
		t.Error("Default ValidateTimestampCertificates should be true")
	}
}

func TestDefaultValidatorSettings_SecurityDefaults(t *testing.T) {
	settings := DefaultValidatorSettings()

	// Test all security-first defaults
	t.Run("TrustSignatureTime", func(t *testing.T) {
		if settings.TrustSignatureTime {
			t.Error("Default TrustSignatureTime should be false (secure: don't trust signatory-provided time)")
		}
	})

	t.Run("ValidateTimestampCertificates", func(t *testing.T) {
		if !settings.ValidateTimestampCertificates {
			t.Error("Default ValidateTimestampCertificates should be true (secure: validate timestamp certs)")
		}
	})

	t.Run("AllowExpiredCerts", func(t *testing.T) {
		if settings.AllowExpiredCerts {
			t.Error("Default AllowExpiredCerts should be false (secure: reject expired certificates)")
		}
	})

	t.Run("AllowEmbeddedRoots", func(t *testing.T) {
		if settings.AllowEmbeddedRoots {
			t.Error("Default AllowEmbeddedRoots should be false (secure: don't trust roots from PDFs)")
		}
	})

	t.Run("EnableExternalRevocationCheck", func(t *testing.T) {
		if settings.EnableExternalRevocationCheck {
			t.Error("Default EnableExternalRevocationCheck should be false (secure: no external network calls)")
		}
	})

	t.Run("HTTPTimeout", func(t *testing.T) {
		if settings.HTTPTimeout != 10*time.Second {
			t.Errorf("Default HTTPTimeout should be 10s, got %v", settings.HTTPTimeout)
		}
	})

	t.Run("KeyUsageConstraints", func(t *testing.T) {
		if settings.KeyUsageConstraints == nil {
			t.Error("Default KeyUsageConstraints should not be nil")
		}
	})
}

func TestLenientValidatorSettings_TimeSettings(t *testing.T) {
	settings := LenientValidatorSettings()

	if !settings.TrustSignatureTime {
		t.Error("Lenient TrustSignatureTime should be true")
	}
	if !settings.ValidateTimestampCertificates {
		t.Error("Lenient ValidateTimestampCertificates should be true")
	}
}

func TestLenientValidatorSettings_SecuritySettings(t *testing.T) {
	settings := LenientValidatorSettings()

	// Lenient relaxes signature time trust but keeps other security settings
	t.Run("TrustSignatureTime", func(t *testing.T) {
		if !settings.TrustSignatureTime {
			t.Error("Lenient TrustSignatureTime should be true (relaxed)")
		}
	})

	t.Run("AllowExpiredCerts", func(t *testing.T) {
		if settings.AllowExpiredCerts {
			t.Error("Lenient AllowExpiredCerts should still be false")
		}
	})

	t.Run("AllowEmbeddedRoots", func(t *testing.T) {
		if settings.AllowEmbeddedRoots {
			t.Error("Lenient AllowEmbeddedRoots should still be false")
		}
	})

	t.Run("EnableExternalRevocationCheck", func(t *testing.T) {
		if settings.EnableExternalRevocationCheck {
			t.Error("Lenient EnableExternalRevocationCheck should still be false")
		}
	})
}

func TestStrictValidatorSettings_TimeSettings(t *testing.T) {
	settings := StrictValidatorSettings()

	if settings.TrustSignatureTime {
		t.Error("Strict TrustSignatureTime should be false")
	}
	if !settings.ValidateTimestampCertificates {
		t.Error("Strict ValidateTimestampCertificates should be true")
	}
}

func TestStrictValidatorSettings_SecuritySettings(t *testing.T) {
	settings := StrictValidatorSettings()

	// Strict should have all security settings enabled
	t.Run("TrustSignatureTime", func(t *testing.T) {
		if settings.TrustSignatureTime {
			t.Error("Strict TrustSignatureTime should be false")
		}
	})

	t.Run("AllowExpiredCerts", func(t *testing.T) {
		if settings.AllowExpiredCerts {
			t.Error("Strict AllowExpiredCerts should be false")
		}
	})

	t.Run("AllowEmbeddedRoots", func(t *testing.T) {
		if settings.AllowEmbeddedRoots {
			t.Error("Strict AllowEmbeddedRoots should be false")
		}
	})

	t.Run("EnableExternalRevocationCheck", func(t *testing.T) {
		if settings.EnableExternalRevocationCheck {
			t.Error("Strict EnableExternalRevocationCheck should be false")
		}
	})

	t.Run("KeyUsageConstraints", func(t *testing.T) {
		if settings.KeyUsageConstraints == nil {
			t.Error("Strict KeyUsageConstraints should not be nil")
		}
		// Strict should require Document Signing EKU
		if !settings.KeyUsageConstraints.ExplicitExtdKeyUsageRequired {
			t.Error("Strict KeyUsageConstraints should require explicit EKU")
		}
	})
}

func TestOnlineValidatorSettings(t *testing.T) {
	settings := OnlineValidatorSettings()

	t.Run("EnableExternalRevocationCheck", func(t *testing.T) {
		if !settings.EnableExternalRevocationCheck {
			t.Error("Online EnableExternalRevocationCheck should be true")
		}
	})

	t.Run("HTTPTimeout", func(t *testing.T) {
		if settings.HTTPTimeout != 10*time.Second {
			t.Errorf("Online HTTPTimeout should be 10s, got %v", settings.HTTPTimeout)
		}
	})

	// Online should keep other security settings
	t.Run("TrustSignatureTime", func(t *testing.T) {
		if settings.TrustSignatureTime {
			t.Error("Online TrustSignatureTime should still be false")
		}
	})

	t.Run("AllowEmbeddedRoots", func(t *testing.T) {
		if settings.AllowEmbeddedRoots {
			t.Error("Online AllowEmbeddedRoots should still be false")
		}
	})

	t.Run("AllowExpiredCerts", func(t *testing.T) {
		if settings.AllowExpiredCerts {
			t.Error("Online AllowExpiredCerts should still be false")
		}
	})
}

func TestTimeSourcePriority(t *testing.T) {
	// Test that embedded timestamp takes priority over signature time
	t.Run("TimestampOverSignatureTime", func(t *testing.T) {
		settings := LenientValidatorSettings() // Trust both sources
		validator := NewSignatureValidator(settings)

		timestampTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
		signatureTime := time.Date(2024, 1, 15, 10, 29, 0, 0, time.UTC)

		timeResult := &TimeValidationResult{
			TimestampTime:   timestampTime,
			SignatureTime:   signatureTime,
			TimestampStatus: TimestampStatusValid,
		}

		result := validator.determineVerificationTime(timeResult)

		if result.TimeSource != TimeSourceEmbeddedTimestamp {
			t.Errorf("TimeSource = %s, want embedded_timestamp (should take priority)", result.TimeSource)
		}
		if !result.VerificationTime.Equal(timestampTime) {
			t.Errorf("VerificationTime = %v, want %v (timestamp should take priority)", result.VerificationTime, timestampTime)
		}
	})

	// Test that signature time is used when timestamp is invalid
	t.Run("SignatureTimeWhenTimestampInvalid", func(t *testing.T) {
		settings := LenientValidatorSettings()
		validator := NewSignatureValidator(settings)

		signatureTime := time.Date(2024, 1, 15, 10, 29, 0, 0, time.UTC)

		timeResult := &TimeValidationResult{
			SignatureTime:   signatureTime,
			TimestampStatus: TimestampStatusInvalid,
		}

		result := validator.determineVerificationTime(timeResult)

		if result.TimeSource != TimeSourceSignatureTime {
			t.Errorf("TimeSource = %s, want signature_time (timestamp is invalid)", result.TimeSource)
		}
	})
}

func TestTimeWarningsContent(t *testing.T) {
	t.Run("SignatureTimeWarning", func(t *testing.T) {
		settings := LenientValidatorSettings()
		validator := NewSignatureValidator(settings)

		signatureTime := time.Date(2024, 1, 15, 10, 29, 0, 0, time.UTC)

		timeResult := &TimeValidationResult{
			SignatureTime:   signatureTime,
			TimestampStatus: TimestampStatusMissing,
		}

		result := validator.determineVerificationTime(timeResult)

		found := false
		for _, w := range result.TimeWarnings {
			if contains(w, "untrusted") || contains(w, "signatory") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected warning about untrusted signature time, got: %v", result.TimeWarnings)
		}
	})

	t.Run("CurrentTimeWarning", func(t *testing.T) {
		settings := DefaultValidatorSettings()
		validator := NewSignatureValidator(settings)

		timeResult := &TimeValidationResult{
			TimestampStatus: TimestampStatusMissing,
		}

		result := validator.determineVerificationTime(timeResult)

		found := false
		for _, w := range result.TimeWarnings {
			if contains(w, "current time") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected warning about using current time, got: %v", result.TimeWarnings)
		}
	})
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
