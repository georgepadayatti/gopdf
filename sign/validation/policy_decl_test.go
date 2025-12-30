package validation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator"
)

// Helper to create a test certificate
func createTestCertificateForPolicy(t *testing.T) *x509.Certificate {
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

// TestRevinfoOnlineFetchingRule tests the online fetching rule enum.
func TestRevinfoOnlineFetchingRule(t *testing.T) {
	tests := []struct {
		rule     RevinfoOnlineFetchingRule
		expected string
	}{
		{RevinfoOnlineFetchNever, "never"},
		{RevinfoOnlineFetchIfConvenient, "if-convenient"},
		{RevinfoOnlineFetchAlways, "always"},
		{RevinfoOnlineFetchingRule(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.rule.String(); got != tt.expected {
			t.Errorf("RevinfoOnlineFetchingRule(%d).String() = %s, want %s", tt.rule, got, tt.expected)
		}
	}
}

// TestRevocationInfoGatheringSpec tests the RevocationInfoGatheringSpec.
func TestRevocationInfoGatheringSpec(t *testing.T) {
	t.Run("NewRevocationInfoGatheringSpec", func(t *testing.T) {
		spec := NewRevocationInfoGatheringSpec()
		if spec.OnlineFetching != RevinfoOnlineFetchIfConvenient {
			t.Errorf("Expected OnlineFetching = IfConvenient, got %v", spec.OnlineFetching)
		}
		if spec.HTTPTimeout != 30*time.Second {
			t.Errorf("Expected HTTPTimeout = 30s, got %v", spec.HTTPTimeout)
		}
		if !spec.UseAIA {
			t.Error("Expected UseAIA = true")
		}
	})

	t.Run("NewOfflineRevocationInfoGatheringSpec", func(t *testing.T) {
		spec := NewOfflineRevocationInfoGatheringSpec()
		if spec.OnlineFetching != RevinfoOnlineFetchNever {
			t.Errorf("Expected OnlineFetching = Never, got %v", spec.OnlineFetching)
		}
		if spec.UseAIA {
			t.Error("Expected UseAIA = false")
		}
	})
}

// TestLocalKnowledge tests the LocalKnowledge type.
func TestLocalKnowledge(t *testing.T) {
	t.Run("NewLocalKnowledge", func(t *testing.T) {
		lk := NewLocalKnowledge()
		if lk == nil {
			t.Fatal("NewLocalKnowledge returned nil")
		}
		if lk.OtherRevInfo == nil {
			t.Error("OtherRevInfo map not initialized")
		}
	})

	t.Run("IsEmpty", func(t *testing.T) {
		lk := NewLocalKnowledge()
		if !lk.IsEmpty() {
			t.Error("Expected new LocalKnowledge to be empty")
		}

		lk.Certs = []*x509.Certificate{createTestCertificateForPolicy(t)}
		if lk.IsEmpty() {
			t.Error("Expected LocalKnowledge with cert to not be empty")
		}
	})

	t.Run("AddAndGetOtherRevInfo", func(t *testing.T) {
		lk := NewLocalKnowledge()
		oid := asn1.ObjectIdentifier{1, 2, 3, 4}
		data := []byte("test data")

		lk.AddOtherRevInfo(oid, data)
		retrieved := lk.GetOtherRevInfo(oid)

		if len(retrieved) != 1 {
			t.Fatalf("Expected 1 item, got %d", len(retrieved))
		}
		if string(retrieved[0]) != string(data) {
			t.Errorf("Retrieved data mismatch")
		}
	})

	t.Run("Merge", func(t *testing.T) {
		lk1 := NewLocalKnowledge()
		lk1.Certs = []*x509.Certificate{createTestCertificateForPolicy(t)}
		lk1.CRLs = [][]byte{[]byte("crl1")}

		lk2 := NewLocalKnowledge()
		lk2.OCSPs = [][]byte{[]byte("ocsp1")}
		lk2.AddOtherRevInfo(asn1.ObjectIdentifier{1, 2, 3}, []byte("rev1"))

		merged := lk1.Merge(lk2)

		if len(merged.Certs) != 1 {
			t.Errorf("Expected 1 cert, got %d", len(merged.Certs))
		}
		if len(merged.CRLs) != 1 {
			t.Errorf("Expected 1 CRL, got %d", len(merged.CRLs))
		}
		if len(merged.OCSPs) != 1 {
			t.Errorf("Expected 1 OCSP, got %d", len(merged.OCSPs))
		}
		if len(merged.OtherRevInfo) != 1 {
			t.Errorf("Expected 1 OtherRevInfo entry, got %d", len(merged.OtherRevInfo))
		}
	})

	t.Run("MergeWithNil", func(t *testing.T) {
		lk := NewLocalKnowledge()
		lk.Certs = []*x509.Certificate{createTestCertificateForPolicy(t)}

		merged := lk.Merge(nil)
		if merged != lk {
			t.Error("Merge with nil should return the original")
		}
	})
}

// TestQualificationRequirements tests qualification requirements.
func TestQualificationRequirements(t *testing.T) {
	req := NewQualificationRequirements()
	if req == nil {
		t.Fatal("NewQualificationRequirements returned nil")
	}

	// Defaults should be false
	if req.RequireQualifiedSignature {
		t.Error("Expected RequireQualifiedSignature = false")
	}
	if req.RequireQualifiedTimestamp {
		t.Error("Expected RequireQualifiedTimestamp = false")
	}
	if req.RequireQSCD {
		t.Error("Expected RequireQSCD = false")
	}
}

// TestSignatureValidationSpec tests the SignatureValidationSpec type.
func TestSignatureValidationSpec(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("NewSignatureValidationSpec", func(t *testing.T) {
		spec := NewSignatureValidationSpec(tm)
		if spec == nil {
			t.Fatal("NewSignatureValidationSpec returned nil")
		}
		if spec.TrustManager != tm {
			t.Error("TrustManager not set correctly")
		}
		if spec.PKIXParams == nil {
			t.Error("PKIXParams should not be nil")
		}
		if spec.RevocationPolicy == nil {
			t.Error("RevocationPolicy should not be nil")
		}
		if spec.RevocationGathering == nil {
			t.Error("RevocationGathering should not be nil")
		}
		if spec.AlgorithmPolicy == nil {
			t.Error("AlgorithmPolicy should not be nil")
		}
		if spec.LocalKnowledge == nil {
			t.Error("LocalKnowledge should not be nil")
		}
	})

	t.Run("WithValidationTime", func(t *testing.T) {
		spec := NewSignatureValidationSpec(tm)
		validationTime := time.Now().Add(-time.Hour)
		result := spec.WithValidationTime(validationTime)

		if result != spec {
			t.Error("WithValidationTime should return the same spec")
		}
		if !spec.ValidationTime.Equal(validationTime) {
			t.Error("ValidationTime not set correctly")
		}
	})

	t.Run("WithRevocationPolicy", func(t *testing.T) {
		spec := NewSignatureValidationSpec(tm)
		policy := certvalidator.NewCertRevTrustPolicy(certvalidator.NoRevocation)
		result := spec.WithRevocationPolicy(policy)

		if result != spec {
			t.Error("WithRevocationPolicy should return the same spec")
		}
		if spec.RevocationPolicy != policy {
			t.Error("RevocationPolicy not set correctly")
		}
	})

	t.Run("WithAlgorithmPolicy", func(t *testing.T) {
		spec := NewSignatureValidationSpec(tm)
		policy := &certvalidator.AcceptAllAlgorithmsPolicy{}
		result := spec.WithAlgorithmPolicy(policy)

		if result != spec {
			t.Error("WithAlgorithmPolicy should return the same spec")
		}
		if spec.AlgorithmPolicy != policy {
			t.Error("AlgorithmPolicy not set correctly")
		}
	})

	t.Run("WithLocalKnowledge", func(t *testing.T) {
		spec := NewSignatureValidationSpec(tm)
		lk := NewLocalKnowledge()
		lk.Certs = []*x509.Certificate{createTestCertificateForPolicy(t)}
		result := spec.WithLocalKnowledge(lk)

		if result != spec {
			t.Error("WithLocalKnowledge should return the same spec")
		}
		if spec.LocalKnowledge != lk {
			t.Error("LocalKnowledge not set correctly")
		}
	})
}

// TestSignatureType tests the SignatureType enum.
func TestSignatureType(t *testing.T) {
	tests := []struct {
		sigType  SignatureType
		expected string
	}{
		{SignatureTypeUnknown, "unknown"},
		{SignatureTypeApproval, "approval"},
		{SignatureTypeCertification, "certification"},
		{SignatureTypeDocTimestamp, "doc_timestamp"},
		{SignatureTypeUsageRights, "usage_rights"},
	}

	for _, tt := range tests {
		if got := tt.sigType.String(); got != tt.expected {
			t.Errorf("SignatureType(%d).String() = %s, want %s", tt.sigType, got, tt.expected)
		}
	}
}

// TestDocMDPLevel tests the DocMDPLevel enum.
func TestDocMDPLevel(t *testing.T) {
	tests := []struct {
		level    DocMDPLevel
		expected string
	}{
		{DocMDPNone, "none"},
		{DocMDPNoChanges, "no_changes"},
		{DocMDPFormFilling, "form_filling"},
		{DocMDPAnnotations, "annotations"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("DocMDPLevel(%d).String() = %s, want %s", tt.level, got, tt.expected)
		}
	}
}

// TestDiffPolicy tests the DiffPolicy type.
func TestDiffPolicy(t *testing.T) {
	policy := NewDiffPolicy()
	if policy == nil {
		t.Fatal("NewDiffPolicy returned nil")
	}

	if policy.GlobalPolicy != ModificationPolicyForbid {
		t.Errorf("Expected GlobalPolicy = Forbid, got %v", policy.GlobalPolicy)
	}
	if policy.FormFillingPolicy != ModificationPolicyAllow {
		t.Errorf("Expected FormFillingPolicy = Allow, got %v", policy.FormFillingPolicy)
	}
	if policy.AnnotationPolicy != ModificationPolicyWarn {
		t.Errorf("Expected AnnotationPolicy = Warn, got %v", policy.AnnotationPolicy)
	}
}

// TestPdfSignatureValidationSpec tests the PdfSignatureValidationSpec type.
func TestPdfSignatureValidationSpec(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("NewPdfSignatureValidationSpec", func(t *testing.T) {
		spec := NewPdfSignatureValidationSpec(tm)
		if spec == nil {
			t.Fatal("NewPdfSignatureValidationSpec returned nil")
		}
		if spec.SignatureValidationSpec == nil {
			t.Error("SignatureValidationSpec should not be nil")
		}
		if spec.DiffPolicy == nil {
			t.Error("DiffPolicy should not be nil")
		}
		if !spec.AllowMultipleSignatures {
			t.Error("Expected AllowMultipleSignatures = true")
		}
		if !spec.RequireContiguous {
			t.Error("Expected RequireContiguous = true")
		}
	})

	t.Run("WithExpectedSignatureType", func(t *testing.T) {
		spec := NewPdfSignatureValidationSpec(tm)
		result := spec.WithExpectedSignatureType(SignatureTypeCertification)

		if result != spec {
			t.Error("WithExpectedSignatureType should return the same spec")
		}
		if spec.ExpectedSignatureType != SignatureTypeCertification {
			t.Error("ExpectedSignatureType not set correctly")
		}
	})

	t.Run("WithDocMDPRequirement", func(t *testing.T) {
		spec := NewPdfSignatureValidationSpec(tm)
		result := spec.WithDocMDPRequirement(DocMDPFormFilling)

		if result != spec {
			t.Error("WithDocMDPRequirement should return the same spec")
		}
		if spec.RequireDocMDP != DocMDPFormFilling {
			t.Error("RequireDocMDP not set correctly")
		}
	})

	t.Run("WithLTVRequired", func(t *testing.T) {
		spec := NewPdfSignatureValidationSpec(tm)
		result := spec.WithLTVRequired(true)

		if result != spec {
			t.Error("WithLTVRequired should return the same spec")
		}
		if !spec.LTVRequired {
			t.Error("LTVRequired not set correctly")
		}
	})
}

// TestValidationDataHandlers tests the validation data handlers.
func TestValidationDataHandlers(t *testing.T) {
	t.Run("NewValidationDataHandlers", func(t *testing.T) {
		handlers := NewValidationDataHandlers()
		if handlers == nil {
			t.Fatal("NewValidationDataHandlers returned nil")
		}
	})

	t.Run("RegisterAndGet", func(t *testing.T) {
		handlers := NewValidationDataHandlers()
		dssHandler := &DSSValidationDataHandler{}

		handlers.Register("dss", dssHandler)
		retrieved, ok := handlers.Get("dss")

		if !ok {
			t.Fatal("Handler not found")
		}
		if retrieved != dssHandler {
			t.Error("Retrieved handler mismatch")
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		handlers := NewValidationDataHandlers()
		_, ok := handlers.Get("nonexistent")
		if ok {
			t.Error("Expected handler not found")
		}
	})

	t.Run("BootstrapValidationDataHandlers", func(t *testing.T) {
		handlers := BootstrapValidationDataHandlers()
		if handlers == nil {
			t.Fatal("BootstrapValidationDataHandlers returned nil")
		}

		if _, ok := handlers.Get("dss"); !ok {
			t.Error("DSS handler not registered")
		}
		if _, ok := handlers.Get("cms"); !ok {
			t.Error("CMS handler not registered")
		}
	})
}

// TestDSSValidationDataHandler tests the DSS handler.
func TestDSSValidationDataHandler(t *testing.T) {
	handler := &DSSValidationDataHandler{}

	t.Run("CollectCertificates", func(t *testing.T) {
		cert := createTestCertificateForPolicy(t)
		dss := &DocumentSecurityStore{
			Certs: []*x509.Certificate{cert},
		}

		certs, err := handler.CollectCertificates(dss)
		if err != nil {
			t.Fatalf("CollectCertificates error: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("Expected 1 cert, got %d", len(certs))
		}
	})

	t.Run("CollectCertificatesInvalidSource", func(t *testing.T) {
		certs, err := handler.CollectCertificates("invalid")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if certs != nil {
			t.Error("Expected nil for invalid source")
		}
	})

	t.Run("CollectCRLs", func(t *testing.T) {
		dss := &DocumentSecurityStore{
			CRLs: [][]byte{[]byte("crl1"), []byte("crl2")},
		}

		crls, err := handler.CollectCRLs(dss)
		if err != nil {
			t.Fatalf("CollectCRLs error: %v", err)
		}
		if len(crls) != 2 {
			t.Errorf("Expected 2 CRLs, got %d", len(crls))
		}
	})

	t.Run("CollectOCSPs", func(t *testing.T) {
		dss := &DocumentSecurityStore{
			OCSPs: [][]byte{[]byte("ocsp1")},
		}

		ocsps, err := handler.CollectOCSPs(dss)
		if err != nil {
			t.Fatalf("CollectOCSPs error: %v", err)
		}
		if len(ocsps) != 1 {
			t.Errorf("Expected 1 OCSP, got %d", len(ocsps))
		}
	})
}

// TestCMSValidationDataHandler tests the CMS handler.
func TestCMSValidationDataHandler(t *testing.T) {
	handler := &CMSValidationDataHandler{}

	// CMS handler returns nil for unimplemented methods
	certs, err := handler.CollectCertificates(nil)
	if err != nil || certs != nil {
		t.Error("Expected nil, nil for CollectCertificates")
	}

	crls, err := handler.CollectCRLs(nil)
	if err != nil || crls != nil {
		t.Error("Expected nil, nil for CollectCRLs")
	}

	ocsps, err := handler.CollectOCSPs(nil)
	if err != nil || ocsps != nil {
		t.Error("Expected nil, nil for CollectOCSPs")
	}
}

// TestValidationSpecPresets tests the preset validation specs.
func TestValidationSpecPresets(t *testing.T) {
	tm := certvalidator.NewSimpleTrustManager()

	t.Run("StrictPreset", func(t *testing.T) {
		spec := GetValidationSpecPreset("strict", tm)
		if spec == nil {
			t.Fatal("Strict preset returned nil")
		}
		if !spec.LTVRequired {
			t.Error("Expected LTVRequired = true for strict")
		}
		if !spec.DSSRequired {
			t.Error("Expected DSSRequired = true for strict")
		}
		if !spec.RequireExactByteRanges {
			t.Error("Expected RequireExactByteRanges = true for strict")
		}
	})

	t.Run("RelaxedPreset", func(t *testing.T) {
		spec := GetValidationSpecPreset("relaxed", tm)
		if spec == nil {
			t.Fatal("Relaxed preset returned nil")
		}
		if !spec.AllowExpiredCerts {
			t.Error("Expected AllowExpiredCerts = true for relaxed")
		}
		if spec.DiffPolicy.GlobalPolicy != ModificationPolicyWarn {
			t.Error("Expected GlobalPolicy = Warn for relaxed")
		}
	})

	t.Run("OfflinePreset", func(t *testing.T) {
		spec := GetValidationSpecPreset("offline", tm)
		if spec == nil {
			t.Fatal("Offline preset returned nil")
		}
		if spec.RevocationGathering.OnlineFetching != RevinfoOnlineFetchNever {
			t.Error("Expected OnlineFetching = Never for offline")
		}
	})

	t.Run("UnknownPreset", func(t *testing.T) {
		spec := GetValidationSpecPreset("unknown", tm)
		if spec == nil {
			t.Fatal("Unknown preset should return default spec")
		}
		// Should be the default spec
		if spec.TrustManager != tm {
			t.Error("Expected default spec with provided trust manager")
		}
	})
}

// TestModificationPolicy tests the modification policy constants.
func TestModificationPolicy(t *testing.T) {
	if ModificationPolicyAllow != 0 {
		t.Error("ModificationPolicyAllow should be 0")
	}
	if ModificationPolicyWarn != 1 {
		t.Error("ModificationPolicyWarn should be 1")
	}
	if ModificationPolicyForbid != 2 {
		t.Error("ModificationPolicyForbid should be 2")
	}
}
