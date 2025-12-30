package validation

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"
)

func TestAlgorithmUsageConstraint(t *testing.T) {
	t.Run("NewAllowedConstraint", func(t *testing.T) {
		c := NewAllowedConstraint()
		if !c.Allowed {
			t.Error("Expected Allowed = true")
		}
		if c.FailureReason != "" {
			t.Error("Expected empty FailureReason")
		}
	})

	t.Run("NewDisallowedConstraint", func(t *testing.T) {
		reason := "test reason"
		c := NewDisallowedConstraint(reason)
		if c.Allowed {
			t.Error("Expected Allowed = false")
		}
		if c.FailureReason != reason {
			t.Errorf("Expected FailureReason = %s, got %s", reason, c.FailureReason)
		}
	})
}

func TestDefaultWeakHashAlgorithms(t *testing.T) {
	if !DefaultWeakHashAlgorithms["sha1"] {
		t.Error("Expected sha1 to be weak")
	}
	if !DefaultWeakHashAlgorithms["md5"] {
		t.Error("Expected md5 to be weak")
	}
	if !DefaultWeakHashAlgorithms["md2"] {
		t.Error("Expected md2 to be weak")
	}
	if DefaultWeakHashAlgorithms["sha256"] {
		t.Error("Expected sha256 to not be weak")
	}
}

func TestDisallowWeakAlgorithmsPolicy(t *testing.T) {
	policy := NewDisallowWeakAlgorithmsPolicy(nil)
	moment := time.Now()

	t.Run("AllowsSHA256", func(t *testing.T) {
		c := policy.DigestAlgorithmAllowed(crypto.SHA256, moment)
		if !c.Allowed {
			t.Errorf("Expected SHA256 to be allowed: %s", c.FailureReason)
		}
	})

	t.Run("AllowsSHA384", func(t *testing.T) {
		c := policy.DigestAlgorithmAllowed(crypto.SHA384, moment)
		if !c.Allowed {
			t.Errorf("Expected SHA384 to be allowed: %s", c.FailureReason)
		}
	})

	t.Run("AllowsSHA512", func(t *testing.T) {
		c := policy.DigestAlgorithmAllowed(crypto.SHA512, moment)
		if !c.Allowed {
			t.Errorf("Expected SHA512 to be allowed: %s", c.FailureReason)
		}
	})

	t.Run("DisallowsSHA1", func(t *testing.T) {
		c := policy.DigestAlgorithmAllowed(crypto.SHA1, moment)
		if c.Allowed {
			t.Error("Expected SHA1 to be disallowed")
		}
	})

	t.Run("DisallowsMD5", func(t *testing.T) {
		c := policy.DigestAlgorithmAllowed(crypto.MD5, moment)
		if c.Allowed {
			t.Error("Expected MD5 to be disallowed")
		}
	})
}

func TestDisallowWeakAlgorithmsPolicySignature(t *testing.T) {
	policy := NewDisallowWeakAlgorithmsPolicy(nil)
	moment := time.Now()

	t.Run("AllowsSHA256WithRSA", func(t *testing.T) {
		c := policy.SignatureAlgorithmAllowed(x509.SHA256WithRSA, moment, nil)
		if !c.Allowed {
			t.Errorf("Expected SHA256WithRSA to be allowed: %s", c.FailureReason)
		}
	})

	t.Run("DisallowsSHA1WithRSA", func(t *testing.T) {
		c := policy.SignatureAlgorithmAllowed(x509.SHA1WithRSA, moment, nil)
		if c.Allowed {
			t.Error("Expected SHA1WithRSA to be disallowed")
		}
	})

	t.Run("DisallowsMD5WithRSA", func(t *testing.T) {
		c := policy.SignatureAlgorithmAllowed(x509.MD5WithRSA, moment, nil)
		if c.Allowed {
			t.Error("Expected MD5WithRSA to be disallowed")
		}
	})
}

func TestDefaultCMSAlgorithmUsagePolicy(t *testing.T) {
	policy := NewDefaultCMSAlgorithmUsagePolicy()
	moment := time.Now()

	t.Run("DigestCombinationAllowed_Matching", func(t *testing.T) {
		c := policy.DigestCombinationAllowed(x509.SHA256WithRSA, crypto.SHA256, moment)
		if !c.Allowed {
			t.Errorf("Expected matching combination to be allowed: %s", c.FailureReason)
		}
	})

	t.Run("DigestCombinationAllowed_Mismatching", func(t *testing.T) {
		c := policy.DigestCombinationAllowed(x509.SHA256WithRSA, crypto.SHA512, moment)
		if c.Allowed {
			t.Error("Expected mismatching combination to be disallowed")
		}
	})
}

func TestLiftToCMSPolicy(t *testing.T) {
	t.Run("AlreadyCMSPolicy", func(t *testing.T) {
		original := NewDefaultCMSAlgorithmUsagePolicy()
		lifted := LiftToCMSPolicy(original)
		if lifted != original {
			t.Error("Expected same policy to be returned")
		}
	})

	t.Run("BasePolicy", func(t *testing.T) {
		original := NewDisallowWeakAlgorithmsPolicy(nil)
		lifted := LiftToCMSPolicy(original)
		if lifted == nil {
			t.Error("Expected lifted policy to not be nil")
		}

		// Test that it implements CMSAlgorithmUsagePolicy
		moment := time.Now()
		c := lifted.DigestCombinationAllowed(x509.SHA256WithRSA, crypto.SHA256, moment)
		if !c.Allowed {
			t.Error("Expected digest combination to be allowed")
		}
	})
}

func TestEnsureDigestMatch(t *testing.T) {
	tests := []struct {
		name       string
		sigAlgo    x509.SignatureAlgorithm
		digestAlgo crypto.Hash
		allowed    bool
	}{
		{"SHA256_Match", x509.SHA256WithRSA, crypto.SHA256, true},
		{"SHA256_Mismatch", x509.SHA256WithRSA, crypto.SHA384, false},
		{"SHA384_Match", x509.SHA384WithRSA, crypto.SHA384, true},
		{"SHA384_Mismatch", x509.SHA384WithRSA, crypto.SHA256, false},
		{"SHA512_Match", x509.SHA512WithRSA, crypto.SHA512, true},
		{"ECDSA_SHA256_Match", x509.ECDSAWithSHA256, crypto.SHA256, true},
		{"ECDSA_SHA384_Match", x509.ECDSAWithSHA384, crypto.SHA384, true},
		{"Ed25519_NoDigest", x509.PureEd25519, crypto.SHA256, true}, // Ed25519 doesn't use separate hash
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := EnsureDigestMatch(tt.sigAlgo, tt.digestAlgo)
			if c.Allowed != tt.allowed {
				t.Errorf("Expected Allowed = %v, got %v (reason: %s)", tt.allowed, c.Allowed, c.FailureReason)
			}
		})
	}
}

func TestSignatureAlgorithmHash(t *testing.T) {
	tests := []struct {
		algo     x509.SignatureAlgorithm
		expected crypto.Hash
	}{
		{x509.MD5WithRSA, crypto.MD5},
		{x509.SHA1WithRSA, crypto.SHA1},
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.ECDSAWithSHA1, crypto.SHA1},
		{x509.ECDSAWithSHA256, crypto.SHA256},
		{x509.ECDSAWithSHA384, crypto.SHA384},
		{x509.ECDSAWithSHA512, crypto.SHA512},
		{x509.PureEd25519, 0}, // Ed25519 doesn't use a separate hash
		{x509.UnknownSignatureAlgorithm, 0},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			hash := SignatureAlgorithmHash(tt.algo)
			if hash != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, hash)
			}
		})
	}
}

func TestHashAlgorithmName(t *testing.T) {
	tests := []struct {
		algo     crypto.Hash
		expected string
	}{
		{crypto.MD5, "md5"},
		{crypto.SHA1, "sha1"},
		{crypto.SHA224, "sha224"},
		{crypto.SHA256, "sha256"},
		{crypto.SHA384, "sha384"},
		{crypto.SHA512, "sha512"},
		{crypto.SHA3_256, "sha3_256"},
		{crypto.SHA3_384, "sha3_384"},
		{crypto.SHA3_512, "sha3_512"},
		{crypto.Hash(0), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := HashAlgorithmName(tt.algo)
			if name != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, name)
			}
		})
	}
}

func TestHashAlgorithmFromName(t *testing.T) {
	tests := []struct {
		name     string
		expected crypto.Hash
	}{
		{"md5", crypto.MD5},
		{"sha1", crypto.SHA1},
		{"sha224", crypto.SHA224},
		{"sha256", crypto.SHA256},
		{"sha384", crypto.SHA384},
		{"sha512", crypto.SHA512},
		{"sha3_256", crypto.SHA3_256},
		{"sha3-256", crypto.SHA3_256},
		{"sha3_384", crypto.SHA3_384},
		{"sha3-384", crypto.SHA3_384},
		{"sha3_512", crypto.SHA3_512},
		{"sha3-512", crypto.SHA3_512},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo := HashAlgorithmFromName(tt.name)
			if algo != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, algo)
			}
		})
	}
}

func TestHashAlgorithmFromOID(t *testing.T) {
	tests := []struct {
		oid      asn1.ObjectIdentifier
		expected crypto.Hash
	}{
		{OIDDigestAlgorithmMD5, crypto.MD5},
		{OIDDigestAlgorithmSHA1, crypto.SHA1},
		{OIDDigestAlgorithmSHA224, crypto.SHA224},
		{OIDDigestAlgorithmSHA256, crypto.SHA256},
		{OIDDigestAlgorithmSHA384, crypto.SHA384},
		{OIDDigestAlgorithmSHA512, crypto.SHA512},
		{OIDDigestAlgorithmSHA3_256, crypto.SHA3_256},
		{OIDDigestAlgorithmSHA3_384, crypto.SHA3_384},
		{OIDDigestAlgorithmSHA3_512, crypto.SHA3_512},
		{asn1.ObjectIdentifier{1, 2, 3}, 0}, // Unknown OID
	}

	for _, tt := range tests {
		t.Run(tt.oid.String(), func(t *testing.T) {
			algo := HashAlgorithmFromOID(tt.oid)
			if algo != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, algo)
			}
		})
	}
}

func TestHashAlgorithmOID(t *testing.T) {
	tests := []struct {
		algo     crypto.Hash
		expected asn1.ObjectIdentifier
	}{
		{crypto.MD5, OIDDigestAlgorithmMD5},
		{crypto.SHA1, OIDDigestAlgorithmSHA1},
		{crypto.SHA224, OIDDigestAlgorithmSHA224},
		{crypto.SHA256, OIDDigestAlgorithmSHA256},
		{crypto.SHA384, OIDDigestAlgorithmSHA384},
		{crypto.SHA512, OIDDigestAlgorithmSHA512},
		{crypto.SHA3_256, OIDDigestAlgorithmSHA3_256},
		{crypto.SHA3_384, OIDDigestAlgorithmSHA3_384},
		{crypto.SHA3_512, OIDDigestAlgorithmSHA3_512},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			oid := HashAlgorithmOID(tt.algo)
			if !oid.Equal(tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, oid)
			}
		})
	}
}

func TestExtractMessageDigest(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "contentType", Value: "1.2.840.113549.1.7.1"},
			{Type: "messageDigest", Value: []byte{1, 2, 3, 4}},
		}

		digest, err := ExtractMessageDigest(attrs)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(digest) != 4 {
			t.Errorf("Expected 4 bytes, got %d", len(digest))
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "contentType", Value: "1.2.840.113549.1.7.1"},
		}

		_, err := ExtractMessageDigest(attrs)
		if err != ErrMessageDigestNotFound {
			t.Errorf("Expected ErrMessageDigestNotFound, got %v", err)
		}
	})

	t.Run("Multiple", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "messageDigest", Value: []byte{1, 2, 3}},
			{Type: "messageDigest", Value: []byte{4, 5, 6}},
		}

		_, err := ExtractMessageDigest(attrs)
		if err != ErrMultipleMessageDigests {
			t.Errorf("Expected ErrMultipleMessageDigests, got %v", err)
		}
	})

	t.Run("ByOID", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "1.2.840.113549.1.9.4", Value: []byte{1, 2, 3, 4}},
		}

		digest, err := ExtractMessageDigest(attrs)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if len(digest) != 4 {
			t.Errorf("Expected 4 bytes, got %d", len(digest))
		}
	})
}

func TestExtractSigningTime(t *testing.T) {
	now := time.Now()

	t.Run("Found", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "signingTime", Value: now},
		}

		sigTime, err := ExtractSigningTime(attrs)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !sigTime.Equal(now) {
			t.Error("Signing time mismatch")
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		attrs := []SignedAttribute{}

		_, err := ExtractSigningTime(attrs)
		if err == nil {
			t.Error("Expected error for missing signing time")
		}
	})

	t.Run("ByOID", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "1.2.840.113549.1.9.5", Value: now},
		}

		sigTime, err := ExtractSigningTime(attrs)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !sigTime.Equal(now) {
			t.Error("Signing time mismatch")
		}
	})
}

func TestExtractContentType(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "contentType", Value: "1.2.840.113549.1.7.1"},
		}

		ct, err := ExtractContentType(attrs)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if ct != "1.2.840.113549.1.7.1" {
			t.Errorf("Expected content type OID, got %s", ct)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		attrs := []SignedAttribute{}

		_, err := ExtractContentType(attrs)
		if err == nil {
			t.Error("Expected error for missing content type")
		}
	})
}

func TestValidateSignedAttributes(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "contentType", Value: "1.2.840.113549.1.7.1"},
			{Type: "messageDigest", Value: []byte{1, 2, 3, 4}},
		}

		err := ValidateSignedAttributes(attrs)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("MissingContentType", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "messageDigest", Value: []byte{1, 2, 3, 4}},
		}

		err := ValidateSignedAttributes(attrs)
		if err == nil {
			t.Error("Expected error for missing content type")
		}
	})

	t.Run("MissingMessageDigest", func(t *testing.T) {
		attrs := []SignedAttribute{
			{Type: "contentType", Value: "1.2.840.113549.1.7.1"},
		}

		err := ValidateSignedAttributes(attrs)
		if err == nil {
			t.Error("Expected error for missing message digest")
		}
	})
}

func TestCompareOIDs(t *testing.T) {
	tests := []struct {
		a        asn1.ObjectIdentifier
		b        asn1.ObjectIdentifier
		expected bool
	}{
		{asn1.ObjectIdentifier{1, 2, 3}, asn1.ObjectIdentifier{1, 2, 3}, true},
		{asn1.ObjectIdentifier{1, 2, 3}, asn1.ObjectIdentifier{1, 2, 4}, false},
		{asn1.ObjectIdentifier{1, 2, 3}, asn1.ObjectIdentifier{1, 2}, false},
		{asn1.ObjectIdentifier{1, 2}, asn1.ObjectIdentifier{1, 2, 3}, false},
	}

	for i, tt := range tests {
		result := CompareOIDs(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("Test %d: Expected %v, got %v", i, tt.expected, result)
		}
	}
}

func TestSignatureAlgorithmFromOID(t *testing.T) {
	tests := []struct {
		oid      asn1.ObjectIdentifier
		expected x509.SignatureAlgorithm
	}{
		{OIDSignatureRSAMD5, x509.MD5WithRSA},
		{OIDSignatureRSASHA1, x509.SHA1WithRSA},
		{OIDSignatureRSASHA256, x509.SHA256WithRSA},
		{OIDSignatureRSASHA384, x509.SHA384WithRSA},
		{OIDSignatureRSASHA512, x509.SHA512WithRSA},
		{OIDSignatureECDSASHA1, x509.ECDSAWithSHA1},
		{OIDSignatureECDSASHA256, x509.ECDSAWithSHA256},
		{OIDSignatureECDSASHA384, x509.ECDSAWithSHA384},
		{OIDSignatureECDSASHA512, x509.ECDSAWithSHA512},
		{OIDSignatureEd25519, x509.PureEd25519},
		{asn1.ObjectIdentifier{1, 2, 3}, x509.UnknownSignatureAlgorithm},
	}

	for _, tt := range tests {
		t.Run(tt.oid.String(), func(t *testing.T) {
			algo := SignatureAlgorithmFromOID(tt.oid)
			if algo != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, algo)
			}
		})
	}
}

func TestIsWeakAlgorithm(t *testing.T) {
	tests := []struct {
		algo   crypto.Hash
		isWeak bool
	}{
		{crypto.SHA1, true},
		{crypto.MD5, true},
		{crypto.SHA256, false},
		{crypto.SHA384, false},
		{crypto.SHA512, false},
	}

	for _, tt := range tests {
		t.Run(HashAlgorithmName(tt.algo), func(t *testing.T) {
			if IsWeakAlgorithm(tt.algo) != tt.isWeak {
				t.Errorf("Expected IsWeakAlgorithm = %v", tt.isWeak)
			}
		})
	}
}

func TestValidateAlgorithmStrength(t *testing.T) {
	policy := NewDefaultCMSAlgorithmUsagePolicy()
	moment := time.Now()

	t.Run("ValidAlgorithms", func(t *testing.T) {
		err := ValidateAlgorithmStrength(x509.SHA256WithRSA, crypto.SHA256, policy, moment)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("WeakSignatureAlgorithm", func(t *testing.T) {
		err := ValidateAlgorithmStrength(x509.SHA1WithRSA, crypto.SHA1, policy, moment)
		if err == nil {
			t.Error("Expected error for weak signature algorithm")
		}
	})

	t.Run("MismatchedAlgorithms", func(t *testing.T) {
		err := ValidateAlgorithmStrength(x509.SHA256WithRSA, crypto.SHA512, policy, moment)
		if err == nil {
			t.Error("Expected error for mismatched algorithms")
		}
	})
}

func TestDefaultAlgorithmUsagePolicy(t *testing.T) {
	if DefaultAlgorithmUsagePolicy == nil {
		t.Error("DefaultAlgorithmUsagePolicy is nil")
	}
}

func TestStrictAlgorithmUsagePolicy(t *testing.T) {
	if StrictAlgorithmUsagePolicy == nil {
		t.Error("StrictAlgorithmUsagePolicy is nil")
	}

	moment := time.Now()

	// Strict policy should also disallow SHA-224
	c := StrictAlgorithmUsagePolicy.DigestAlgorithmAllowed(crypto.SHA224, moment)
	if c.Allowed {
		t.Error("Expected strict policy to disallow SHA-224")
	}
}

func TestOIDConstants(t *testing.T) {
	// Test that OID constants are properly defined
	oids := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"OIDDigestAlgorithmMD5", OIDDigestAlgorithmMD5},
		{"OIDDigestAlgorithmSHA1", OIDDigestAlgorithmSHA1},
		{"OIDDigestAlgorithmSHA256", OIDDigestAlgorithmSHA256},
		{"OIDDigestAlgorithmSHA384", OIDDigestAlgorithmSHA384},
		{"OIDDigestAlgorithmSHA512", OIDDigestAlgorithmSHA512},
		{"OIDSignatureRSASHA256", OIDSignatureRSASHA256},
		{"OIDSignatureECDSASHA256", OIDSignatureECDSASHA256},
		{"OIDSignatureEd25519", OIDSignatureEd25519},
	}

	for _, tt := range oids {
		if len(tt.oid) == 0 {
			t.Errorf("%s is empty", tt.name)
		}
	}
}
