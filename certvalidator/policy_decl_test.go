package certvalidator

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestRevocationCheckingRuleString(t *testing.T) {
	tests := []struct {
		rule     RevocationCheckingRule
		expected string
	}{
		{RevocationRuleCRLRequired, "clrcheck"},
		{RevocationRuleOCSPRequired, "ocspcheck"},
		{RevocationRuleCRLAndOCSPRequired, "bothcheck"},
		{RevocationRuleCRLOrOCSPRequired, "eithercheck"},
		{RevocationRuleNoCheck, "nocheck"},
		{RevocationRuleCheckIfDeclared, "ifdeclaredcheck"},
		{RevocationRuleCheckIfDeclaredSoft, "ifdeclaredsoftcheck"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.rule.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRevocationCheckingRuleIsStrict(t *testing.T) {
	strictRules := []RevocationCheckingRule{
		RevocationRuleCRLRequired,
		RevocationRuleOCSPRequired,
		RevocationRuleCRLAndOCSPRequired,
		RevocationRuleCRLOrOCSPRequired,
	}
	nonStrictRules := []RevocationCheckingRule{
		RevocationRuleNoCheck,
		RevocationRuleCheckIfDeclared,
		RevocationRuleCheckIfDeclaredSoft,
	}

	for _, rule := range strictRules {
		if !rule.IsStrict() {
			t.Errorf("%v should be strict", rule)
		}
	}
	for _, rule := range nonStrictRules {
		if rule.IsStrict() {
			t.Errorf("%v should not be strict", rule)
		}
	}
}

func TestRevocationCheckingRuleIsTolerant(t *testing.T) {
	tolerantRules := []RevocationCheckingRule{
		RevocationRuleNoCheck,
		RevocationRuleCheckIfDeclaredSoft,
	}
	nonTolerantRules := []RevocationCheckingRule{
		RevocationRuleCRLRequired,
		RevocationRuleOCSPRequired,
		RevocationRuleCRLAndOCSPRequired,
		RevocationRuleCRLOrOCSPRequired,
		RevocationRuleCheckIfDeclared,
	}

	for _, rule := range tolerantRules {
		if !rule.IsTolerant() {
			t.Errorf("%v should be tolerant", rule)
		}
	}
	for _, rule := range nonTolerantRules {
		if rule.IsTolerant() {
			t.Errorf("%v should not be tolerant", rule)
		}
	}
}

func TestRevocationCheckingRuleCRLMandatory(t *testing.T) {
	crlMandatory := []RevocationCheckingRule{
		RevocationRuleCRLRequired,
		RevocationRuleCRLAndOCSPRequired,
	}
	crlNotMandatory := []RevocationCheckingRule{
		RevocationRuleOCSPRequired,
		RevocationRuleCRLOrOCSPRequired,
		RevocationRuleNoCheck,
	}

	for _, rule := range crlMandatory {
		if !rule.IsCRLMandatory() {
			t.Errorf("%v should have CRL mandatory", rule)
		}
	}
	for _, rule := range crlNotMandatory {
		if rule.IsCRLMandatory() {
			t.Errorf("%v should not have CRL mandatory", rule)
		}
	}
}

func TestRevocationCheckingRuleOCSPMandatory(t *testing.T) {
	ocspMandatory := []RevocationCheckingRule{
		RevocationRuleOCSPRequired,
		RevocationRuleCRLAndOCSPRequired,
	}
	ocspNotMandatory := []RevocationCheckingRule{
		RevocationRuleCRLRequired,
		RevocationRuleCRLOrOCSPRequired,
		RevocationRuleNoCheck,
	}

	for _, rule := range ocspMandatory {
		if !rule.IsOCSPMandatory() {
			t.Errorf("%v should have OCSP mandatory", rule)
		}
	}
	for _, rule := range ocspNotMandatory {
		if rule.IsOCSPMandatory() {
			t.Errorf("%v should not have OCSP mandatory", rule)
		}
	}
}

func TestRevocationCheckingPolicyFromLegacy(t *testing.T) {
	tests := []struct {
		name      string
		policy    string
		wantErr   bool
		eeRule    RevocationCheckingRule
		caRule    RevocationCheckingRule
	}{
		{"none", "none", false, RevocationRuleNoCheck, RevocationRuleNoCheck},
		{"soft-fail", "soft-fail", false, RevocationRuleCheckIfDeclaredSoft, RevocationRuleCheckIfDeclaredSoft},
		{"hard-fail", "hard-fail", false, RevocationRuleCheckIfDeclared, RevocationRuleCheckIfDeclared},
		{"require", "require", false, RevocationRuleCRLOrOCSPRequired, RevocationRuleCRLOrOCSPRequired},
		{"invalid", "invalid", true, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := RevocationPolicyFromLegacy(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if policy.EECertificateRule != tt.eeRule {
					t.Errorf("EECertificateRule = %v, want %v", policy.EECertificateRule, tt.eeRule)
				}
				if policy.IntermediateCACertRule != tt.caRule {
					t.Errorf("IntermediateCACertRule = %v, want %v", policy.IntermediateCACertRule, tt.caRule)
				}
			}
		})
	}
}

func TestRevocationCheckingPolicyIsEssential(t *testing.T) {
	if !RequireRevInfo.IsEssential() {
		t.Error("RequireRevInfo should be essential")
	}
	if NoRevocation.IsEssential() {
		t.Error("NoRevocation should not be essential")
	}
}

func TestFreshnessReqTypeString(t *testing.T) {
	tests := []struct {
		reqType  FreshnessReqType
		expected string
	}{
		{FreshnessDefault, "default"},
		{FreshnessMaxDiffRevocationValidation, "max_diff_revocation_validation"},
		{FreshnessTimeAfterSignature, "time_after_signature"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.reqType.String(); got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCertRevTrustPolicy(t *testing.T) {
	policy := NewCertRevTrustPolicy(RequireRevInfo)
	if policy.RevocationCheckingPolicy != RequireRevInfo {
		t.Error("policy should use RequireRevInfo")
	}
	if policy.FreshnessReqType != FreshnessDefault {
		t.Error("default freshness type should be FreshnessDefault")
	}
}

func TestIntersectPolicySets(t *testing.T) {
	tests := []struct {
		name     string
		aPols    map[string]bool
		bPols    map[string]bool
		expected map[string]bool
	}{
		{
			"both any",
			map[string]bool{AnyPolicy: true},
			map[string]bool{AnyPolicy: true},
			map[string]bool{AnyPolicy: true},
		},
		{
			"a any",
			map[string]bool{AnyPolicy: true},
			map[string]bool{"policy1": true, "policy2": true},
			map[string]bool{"policy1": true, "policy2": true},
		},
		{
			"b any",
			map[string]bool{"policy1": true, "policy2": true},
			map[string]bool{AnyPolicy: true},
			map[string]bool{"policy1": true, "policy2": true},
		},
		{
			"intersection",
			map[string]bool{"policy1": true, "policy2": true},
			map[string]bool{"policy2": true, "policy3": true},
			map[string]bool{"policy2": true},
		},
		{
			"no overlap",
			map[string]bool{"policy1": true},
			map[string]bool{"policy2": true},
			map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IntersectPolicySets(tt.aPols, tt.bPols)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d policies, got %d", len(tt.expected), len(result))
			}
			for k := range tt.expected {
				if !result[k] {
					t.Errorf("expected %s in result", k)
				}
			}
		})
	}
}

func TestPKIXValidationParams(t *testing.T) {
	t.Run("default params", func(t *testing.T) {
		params := DefaultPKIXValidationParams()
		if !params.UserInitialPolicySet[AnyPolicy] {
			t.Error("default should accept any policy")
		}
		if params.InitialPolicyMappingInhibit {
			t.Error("policy mapping should be permitted by default")
		}
		if params.InitialExplicitPolicy {
			t.Error("explicit policy should be false by default")
		}
		if params.InitialAnyPolicyInhibit {
			t.Error("any policy should be processed by default")
		}
	})

	t.Run("merge params", func(t *testing.T) {
		p1 := &PKIXValidationParams{
			UserInitialPolicySet:    map[string]bool{"policy1": true, "policy2": true},
			InitialAnyPolicyInhibit: true,
			InitialExplicitPolicy:   true,
		}
		p2 := &PKIXValidationParams{
			UserInitialPolicySet:    map[string]bool{"policy2": true, "policy3": true},
			InitialAnyPolicyInhibit: true,
			InitialExplicitPolicy:   false,
		}

		merged := p1.Merge(p2)

		if len(merged.UserInitialPolicySet) != 1 {
			t.Errorf("expected 1 policy in intersection, got %d", len(merged.UserInitialPolicySet))
		}
		if !merged.UserInitialPolicySet["policy2"] {
			t.Error("policy2 should be in merged set")
		}
		if !merged.InitialAnyPolicyInhibit {
			t.Error("any policy inhibit should be AND of both")
		}
		if merged.InitialExplicitPolicy {
			t.Error("explicit policy should be AND of both (false)")
		}
	})

	t.Run("merge with any policy", func(t *testing.T) {
		p1 := DefaultPKIXValidationParams() // has any_policy
		p2 := &PKIXValidationParams{
			UserInitialPolicySet: map[string]bool{"policy1": true},
		}

		merged := p1.Merge(p2)
		if !merged.UserInitialPolicySet["policy1"] {
			t.Error("merge with any_policy should use other set")
		}
	})
}

func TestAlgorithmUsageConstraint(t *testing.T) {
	t.Run("allowed constraint", func(t *testing.T) {
		c := NewAlgorithmUsageConstraint(true)
		if !c.IsAllowed() {
			t.Error("constraint should be allowed")
		}
	})

	t.Run("disallowed constraint", func(t *testing.T) {
		c := NewAlgorithmUsageConstraint(false)
		if c.IsAllowed() {
			t.Error("constraint should not be allowed")
		}
	})

	t.Run("constraint with reason", func(t *testing.T) {
		c := NewAlgorithmUsageConstraintWithReason(false, "weak algorithm")
		if c.IsAllowed() {
			t.Error("constraint should not be allowed")
		}
		if c.FailureReason != "weak algorithm" {
			t.Errorf("expected 'weak algorithm', got '%s'", c.FailureReason)
		}
	})

	t.Run("constraint with not allowed after", func(t *testing.T) {
		now := time.Now()
		c := &AlgorithmUsageConstraint{
			Allowed:         false,
			NotAllowedAfter: &now,
		}
		if c.NotAllowedAfter == nil {
			t.Error("NotAllowedAfter should be set")
		}
	})
}

func TestDisallowWeakAlgorithmsPolicy(t *testing.T) {
	policy := NewDisallowWeakAlgorithmsPolicy()

	t.Run("weak hash not allowed", func(t *testing.T) {
		constraint := policy.DigestAlgorithmAllowed(crypto.MD5, nil)
		if constraint.IsAllowed() {
			t.Error("MD5 should not be allowed")
		}

		constraint = policy.DigestAlgorithmAllowed(crypto.SHA1, nil)
		if constraint.IsAllowed() {
			t.Error("SHA1 should not be allowed")
		}
	})

	t.Run("strong hash allowed", func(t *testing.T) {
		constraint := policy.DigestAlgorithmAllowed(crypto.SHA256, nil)
		if !constraint.IsAllowed() {
			t.Error("SHA256 should be allowed")
		}

		constraint = policy.DigestAlgorithmAllowed(crypto.SHA384, nil)
		if !constraint.IsAllowed() {
			t.Error("SHA384 should be allowed")
		}

		constraint = policy.DigestAlgorithmAllowed(crypto.SHA512, nil)
		if !constraint.IsAllowed() {
			t.Error("SHA512 should be allowed")
		}
	})

	t.Run("signature algorithm with weak hash", func(t *testing.T) {
		constraint := policy.SignatureAlgorithmAllowed(x509.SHA1WithRSA, nil, nil)
		if constraint.IsAllowed() {
			t.Error("SHA1WithRSA should not be allowed due to weak hash")
		}
	})

	t.Run("signature algorithm with strong hash", func(t *testing.T) {
		constraint := policy.SignatureAlgorithmAllowed(x509.SHA256WithRSA, nil, nil)
		if !constraint.IsAllowed() {
			t.Error("SHA256WithRSA should be allowed")
		}
	})

	t.Run("small RSA key", func(t *testing.T) {
		// Create a mock small RSA key
		smallKey := &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(make([]byte, 128)), // 1024-bit
			E: 65537,
		}
		constraint := policy.SignatureAlgorithmAllowed(x509.SHA256WithRSA, nil, smallKey)
		if constraint.IsAllowed() {
			t.Error("small RSA key should not be allowed")
		}
	})
}

func TestAcceptAllAlgorithmsPolicy(t *testing.T) {
	policy := &AcceptAllAlgorithmsPolicy{}

	t.Run("all digests allowed", func(t *testing.T) {
		for _, hash := range []crypto.Hash{crypto.MD5, crypto.SHA1, crypto.SHA256} {
			constraint := policy.DigestAlgorithmAllowed(hash, nil)
			if !constraint.IsAllowed() {
				t.Errorf("%v should be allowed", hash)
			}
		}
	})

	t.Run("all signatures allowed", func(t *testing.T) {
		for _, algo := range []x509.SignatureAlgorithm{
			x509.SHA1WithRSA, x509.SHA256WithRSA, x509.ECDSAWithSHA256,
		} {
			constraint := policy.SignatureAlgorithmAllowed(algo, nil, nil)
			if !constraint.IsAllowed() {
				t.Errorf("%v should be allowed", algo)
			}
		}
	})
}

func TestNonRevokedStatusAssertion(t *testing.T) {
	now := time.Now()
	cert := []byte{0x01, 0x02, 0x03}

	assertion := NonRevokedStatusAssertion{
		CertSHA256: cert,
		At:         now,
	}

	if len(assertion.CertSHA256) != 3 {
		t.Errorf("expected 3 bytes, got %d", len(assertion.CertSHA256))
	}
	if assertion.At != now {
		t.Error("time should match")
	}
}

func TestDefaultWeakHashAlgos(t *testing.T) {
	if !DefaultWeakHashAlgos[crypto.MD5] {
		t.Error("MD5 should be in default weak algos")
	}
	if !DefaultWeakHashAlgos[crypto.SHA1] {
		t.Error("SHA1 should be in default weak algos")
	}
	if DefaultWeakHashAlgos[crypto.SHA256] {
		t.Error("SHA256 should not be in default weak algos")
	}
}

func TestFreshnessFallbackValidityDefault(t *testing.T) {
	expected := 30 * time.Minute
	if FreshnessFallbackValidityDefault != expected {
		t.Errorf("expected %v, got %v", expected, FreshnessFallbackValidityDefault)
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("isRSAAlgorithm", func(t *testing.T) {
		rsaAlgos := []x509.SignatureAlgorithm{
			x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
			x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		}
		for _, algo := range rsaAlgos {
			if !isRSAAlgorithm(algo) {
				t.Errorf("%v should be RSA", algo)
			}
		}

		nonRSA := []x509.SignatureAlgorithm{
			x509.ECDSAWithSHA256, x509.DSAWithSHA256,
		}
		for _, algo := range nonRSA {
			if isRSAAlgorithm(algo) {
				t.Errorf("%v should not be RSA", algo)
			}
		}
	})

	t.Run("isDSAAlgorithm", func(t *testing.T) {
		if !isDSAAlgorithm(x509.DSAWithSHA1) {
			t.Error("DSAWithSHA1 should be DSA")
		}
		if !isDSAAlgorithm(x509.DSAWithSHA256) {
			t.Error("DSAWithSHA256 should be DSA")
		}
		if isDSAAlgorithm(x509.SHA256WithRSA) {
			t.Error("SHA256WithRSA should not be DSA")
		}
	})

	t.Run("getHashFromSignatureAlgorithm", func(t *testing.T) {
		tests := []struct {
			algo     x509.SignatureAlgorithm
			expected crypto.Hash
		}{
			{x509.MD5WithRSA, crypto.MD5},
			{x509.SHA1WithRSA, crypto.SHA1},
			{x509.SHA256WithRSA, crypto.SHA256},
			{x509.SHA384WithRSA, crypto.SHA384},
			{x509.SHA512WithRSA, crypto.SHA512},
			{x509.ECDSAWithSHA256, crypto.SHA256},
			{x509.ECDSAWithSHA384, crypto.SHA384},
			{x509.ECDSAWithSHA512, crypto.SHA512},
		}

		for _, tt := range tests {
			hash := getHashFromSignatureAlgorithm(tt.algo)
			if hash != tt.expected {
				t.Errorf("getHashFromSignatureAlgorithm(%v) = %v, want %v", tt.algo, hash, tt.expected)
			}
		}
	})
}

func TestRevocationCheckingRuleRelevance(t *testing.T) {
	t.Run("CRL relevant", func(t *testing.T) {
		crlRelevant := []RevocationCheckingRule{
			RevocationRuleCRLRequired,
			RevocationRuleCRLAndOCSPRequired,
			RevocationRuleCRLOrOCSPRequired,
			RevocationRuleCheckIfDeclared,
			RevocationRuleCheckIfDeclaredSoft,
		}
		for _, rule := range crlRelevant {
			if !rule.IsCRLRelevant() {
				t.Errorf("%v should be CRL relevant", rule)
			}
		}

		crlNotRelevant := []RevocationCheckingRule{
			RevocationRuleNoCheck,
			RevocationRuleOCSPRequired,
		}
		for _, rule := range crlNotRelevant {
			if rule.IsCRLRelevant() {
				t.Errorf("%v should not be CRL relevant", rule)
			}
		}
	})

	t.Run("OCSP relevant", func(t *testing.T) {
		ocspRelevant := []RevocationCheckingRule{
			RevocationRuleOCSPRequired,
			RevocationRuleCRLAndOCSPRequired,
			RevocationRuleCRLOrOCSPRequired,
			RevocationRuleCheckIfDeclared,
			RevocationRuleCheckIfDeclaredSoft,
		}
		for _, rule := range ocspRelevant {
			if !rule.IsOCSPRelevant() {
				t.Errorf("%v should be OCSP relevant", rule)
			}
		}

		ocspNotRelevant := []RevocationCheckingRule{
			RevocationRuleNoCheck,
			RevocationRuleCRLRequired,
		}
		for _, rule := range ocspNotRelevant {
			if rule.IsOCSPRelevant() {
				t.Errorf("%v should not be OCSP relevant", rule)
			}
		}
	})
}
