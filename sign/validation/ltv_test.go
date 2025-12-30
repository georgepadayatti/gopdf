package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator"
)

// Helper to create a test certificate for LTV tests
func createTestCertificateForLTV(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// TestRevocationInfoValidationType tests the validation type enum.
func TestRevocationInfoValidationType(t *testing.T) {
	tests := []struct {
		valType  RevocationInfoValidationType
		expected string
	}{
		{RevocationInfoAdobeStyle, "adobe"},
		{RevocationInfoPAdESLT, "pades"},
		{RevocationInfoPAdESLTA, "pades-lta"},
		{RevocationInfoValidationType(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.valType.String(); got != tt.expected {
			t.Errorf("RevocationInfoValidationType(%d).String() = %s, want %s", tt.valType, got, tt.expected)
		}
	}
}

// TestParseRevocationInfoValidationType tests parsing validation types.
func TestParseRevocationInfoValidationType(t *testing.T) {
	tests := []struct {
		input    string
		expected RevocationInfoValidationType
		hasError bool
	}{
		{"adobe", RevocationInfoAdobeStyle, false},
		{"pades", RevocationInfoPAdESLT, false},
		{"pades-lta", RevocationInfoPAdESLTA, false},
		{"unknown", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseRevocationInfoValidationType(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("ParseRevocationInfoValidationType(%s) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseRevocationInfoValidationType(%s) error: %v", tt.input, err)
			}
			if got != tt.expected {
				t.Errorf("ParseRevocationInfoValidationType(%s) = %v, want %v", tt.input, got, tt.expected)
			}
		}
	}
}

// TestLTVRevocationPolicies tests the revocation policy creation.
func TestLTVRevocationPolicies(t *testing.T) {
	t.Run("DefaultLTVRevocationPolicy", func(t *testing.T) {
		policy := NewDefaultLTVRevocationPolicy(false)
		if policy == nil {
			t.Fatal("NewDefaultLTVRevocationPolicy returned nil")
		}
		if policy.RetroactiveRevInfo {
			t.Error("Expected RetroactiveRevInfo = false")
		}
	})

	t.Run("DefaultLTVRevocationPolicyRetroactive", func(t *testing.T) {
		policy := NewDefaultLTVRevocationPolicy(true)
		if !policy.RetroactiveRevInfo {
			t.Error("Expected RetroactiveRevInfo = true")
		}
	})

	t.Run("StrictLTVRevocationPolicy", func(t *testing.T) {
		policy := NewStrictLTVRevocationPolicy(false)
		if policy == nil {
			t.Fatal("NewStrictLTVRevocationPolicy returned nil")
		}
	})
}

// TestLTVValidationContext tests the LTV validation context.
func TestLTVValidationContext(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("NewLTVValidationContext", func(t *testing.T) {
		ctx := NewLTVValidationContext(tm)
		if ctx == nil {
			t.Fatal("NewLTVValidationContext returned nil")
		}
		if ctx.TrustManager != tm {
			t.Error("TrustManager not set correctly")
		}
		if !ctx.AllowFetching {
			t.Error("Expected AllowFetching = true by default")
		}
		if ctx.RevocationPolicy == nil {
			t.Error("RevocationPolicy should not be nil")
		}
	})

	t.Run("WithValidationTime", func(t *testing.T) {
		ctx := NewLTVValidationContext(tm)
		validationTime := time.Now().Add(-time.Hour)
		result := ctx.WithValidationTime(validationTime)

		if result != ctx {
			t.Error("WithValidationTime should return the same context")
		}
		if !ctx.ValidationTime.Equal(validationTime) {
			t.Error("ValidationTime not set correctly")
		}
	})

	t.Run("WithRevocationPolicy", func(t *testing.T) {
		ctx := NewLTVValidationContext(tm)
		policy := NewStrictLTVRevocationPolicy(true)
		result := ctx.WithRevocationPolicy(policy)

		if result != ctx {
			t.Error("WithRevocationPolicy should return the same context")
		}
		if ctx.RevocationPolicy != policy {
			t.Error("RevocationPolicy not set correctly")
		}
	})

	t.Run("WithDSSData", func(t *testing.T) {
		ctx := NewLTVValidationContext(tm)
		cert := createTestCertificateForLTV(t)
		dss := &DocumentSecurityStore{
			Certs: []*x509.Certificate{cert},
			CRLs:  [][]byte{[]byte("crl1")},
			OCSPs: [][]byte{[]byte("ocsp1")},
		}

		result := ctx.WithDSSData(dss)

		if result != ctx {
			t.Error("WithDSSData should return the same context")
		}
		if len(ctx.Certificates) != 1 {
			t.Errorf("Expected 1 cert, got %d", len(ctx.Certificates))
		}
		if len(ctx.CRLs) != 1 {
			t.Errorf("Expected 1 CRL, got %d", len(ctx.CRLs))
		}
		if len(ctx.OCSPs) != 1 {
			t.Errorf("Expected 1 OCSP, got %d", len(ctx.OCSPs))
		}
	})

	t.Run("WithDSSDataNil", func(t *testing.T) {
		ctx := NewLTVValidationContext(tm)
		ctx.WithDSSData(nil)
		// Should not panic
	})
}

// TestTimestampSignatureStatus tests the timestamp status.
func TestTimestampSignatureStatus(t *testing.T) {
	t.Run("SummaryValidTrusted", func(t *testing.T) {
		status := &TimestampSignatureStatus{
			Valid:     true,
			Trusted:   true,
			Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		}
		summary := status.Summary()
		if summary == "" {
			t.Error("Summary should not be empty")
		}
	})

	t.Run("SummaryValidUntrusted", func(t *testing.T) {
		status := &TimestampSignatureStatus{
			Valid:     true,
			Trusted:   false,
			Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		}
		summary := status.Summary()
		if summary == "" {
			t.Error("Summary should not be empty")
		}
	})

	t.Run("SummaryInvalid", func(t *testing.T) {
		status := &TimestampSignatureStatus{
			Valid: false,
		}
		summary := status.Summary()
		if summary != "invalid timestamp" {
			t.Errorf("Expected 'invalid timestamp', got '%s'", summary)
		}
	})
}

// TestLTVValidator tests the LTV validator.
func TestLTVValidator(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("NewLTVValidator", func(t *testing.T) {
		validator := NewLTVValidator(tm)
		if validator == nil {
			t.Fatal("NewLTVValidator returned nil")
		}
		if validator.TrustManager != tm {
			t.Error("TrustManager not set correctly")
		}
		if validator.DiffPolicy == nil {
			t.Error("DiffPolicy should not be nil")
		}
	})
}

// TestLTVProfiles tests the LTV profiles.
func TestLTVProfiles(t *testing.T) {
	t.Run("AdobeProfile", func(t *testing.T) {
		if LTVProfileAdobe.ValidationType != RevocationInfoAdobeStyle {
			t.Error("Adobe profile should use Adobe style")
		}
		if LTVProfileAdobe.RequireDSS {
			t.Error("Adobe profile should not require DSS")
		}
	})

	t.Run("PAdESLTProfile", func(t *testing.T) {
		if LTVProfilePAdESLT.ValidationType != RevocationInfoPAdESLT {
			t.Error("PAdES-LT profile should use PAdES-LT style")
		}
		if !LTVProfilePAdESLT.RequireDSS {
			t.Error("PAdES-LT profile should require DSS")
		}
	})

	t.Run("PAdESLTAProfile", func(t *testing.T) {
		if LTVProfilePAdESLTA.ValidationType != RevocationInfoPAdESLTA {
			t.Error("PAdES-LTA profile should use PAdES-LTA style")
		}
		if !LTVProfilePAdESLTA.RequireDSS {
			t.Error("PAdES-LTA profile should require DSS")
		}
		if !LTVProfilePAdESLTA.RequireChain {
			t.Error("PAdES-LTA profile should require chain")
		}
		if LTVProfilePAdESLTA.MinChainLength != 2 {
			t.Errorf("Expected MinChainLength = 2, got %d", LTVProfilePAdESLTA.MinChainLength)
		}
	})
}

// TestGetLTVProfile tests profile retrieval by name.
func TestGetLTVProfile(t *testing.T) {
	tests := []struct {
		name     string
		expected *LTVProfile
	}{
		{"adobe", LTVProfileAdobe},
		{"pades-lt", LTVProfilePAdESLT},
		{"pades", LTVProfilePAdESLT},
		{"pades-lta", LTVProfilePAdESLTA},
		{"unknown", nil},
	}

	for _, tt := range tests {
		got := GetLTVProfile(tt.name)
		if got != tt.expected {
			t.Errorf("GetLTVProfile(%s) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

// TestVerifyTimestampImprint tests the imprint verification.
func TestVerifyTimestampImprint(t *testing.T) {
	t.Run("MatchingImprint", func(t *testing.T) {
		tstInfo := &TSTInfo{
			MessageImprint: MessageImprint{
				HashedMessage: []byte{1, 2, 3, 4, 5},
			},
		}
		expectedDigest := []byte{1, 2, 3, 4, 5}

		err := verifyTimestampImprint(tstInfo, expectedDigest)
		if err != nil {
			t.Errorf("Expected no error for matching imprint, got: %v", err)
		}
	})

	t.Run("MismatchedImprint", func(t *testing.T) {
		tstInfo := &TSTInfo{
			MessageImprint: MessageImprint{
				HashedMessage: []byte{1, 2, 3, 4, 5},
			},
		}
		expectedDigest := []byte{5, 4, 3, 2, 1}

		err := verifyTimestampImprint(tstInfo, expectedDigest)
		if err == nil {
			t.Error("Expected error for mismatched imprint")
		}
	})

	t.Run("LengthMismatch", func(t *testing.T) {
		tstInfo := &TSTInfo{
			MessageImprint: MessageImprint{
				HashedMessage: []byte{1, 2, 3},
			},
		}
		expectedDigest := []byte{1, 2, 3, 4, 5}

		err := verifyTimestampImprint(tstInfo, expectedDigest)
		if err == nil {
			t.Error("Expected error for length mismatch")
		}
	})
}

// TestDefaultLTVRevocationCheckingPolicy tests the default policy.
func TestDefaultLTVRevocationCheckingPolicy(t *testing.T) {
	if DefaultLTVRevocationCheckingPolicy == nil {
		t.Fatal("DefaultLTVRevocationCheckingPolicy is nil")
	}
	if DefaultLTVRevocationCheckingPolicy.EECertificateRule != certvalidator.RevocationRuleCheckIfDeclared {
		t.Error("Expected EE rule to be CheckIfDeclared")
	}
	if DefaultLTVRevocationCheckingPolicy.IntermediateCACertRule != certvalidator.RevocationRuleCheckIfDeclared {
		t.Error("Expected CA rule to be CheckIfDeclared")
	}
}

// TestStrictLTVRevocationCheckingPolicy tests the strict policy.
func TestStrictLTVRevocationCheckingPolicy(t *testing.T) {
	if StrictLTVRevocationCheckingPolicy == nil {
		t.Fatal("StrictLTVRevocationCheckingPolicy is nil")
	}
	if StrictLTVRevocationCheckingPolicy.EECertificateRule != certvalidator.RevocationRuleCRLOrOCSPRequired {
		t.Error("Expected EE rule to be CRLOrOCSPRequired")
	}
	if StrictLTVRevocationCheckingPolicy.IntermediateCACertRule != certvalidator.RevocationRuleCRLOrOCSPRequired {
		t.Error("Expected CA rule to be CRLOrOCSPRequired")
	}
}

// TestTimestampTrustData tests the timestamp trust data struct.
func TestTimestampTrustData(t *testing.T) {
	data := &TimestampTrustData{
		ChainLength:    2,
		ValidationTime: time.Now(),
	}

	if data.ChainLength != 2 {
		t.Errorf("Expected ChainLength = 2, got %d", data.ChainLength)
	}
}

// TestLTVSignatureStatus tests the LTV signature status.
func TestLTVSignatureStatus(t *testing.T) {
	status := &LTVSignatureStatus{
		SignatureValidationResult: &SignatureValidationResult{
			Status: StatusValid,
		},
		ValidationType:       RevocationInfoPAdESLTA,
		TimestampChainLength: 2,
		DSSPresent:           true,
	}

	if status.ValidationType != RevocationInfoPAdESLTA {
		t.Error("ValidationType not set correctly")
	}
	if status.TimestampChainLength != 2 {
		t.Error("TimestampChainLength not set correctly")
	}
	if !status.DSSPresent {
		t.Error("DSSPresent should be true")
	}
}

// TestGetNameValue tests the name value extraction helper.
func TestGetNameValue(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{nil, ""},
		{"test", "test"},
		{"/DocTimeStamp", "/DocTimeStamp"},
	}

	for _, tt := range tests {
		got := getNameValue(tt.input)
		if got != tt.expected {
			t.Errorf("getNameValue(%v) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}
