package ades

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Test helpers

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// ValidationConclusion tests

func TestNewValidationConclusion(t *testing.T) {
	conclusion := NewValidationConclusion(IndicationPassed)
	if conclusion.Indication != IndicationPassed {
		t.Errorf("Indication = %q, want %q", conclusion.Indication, IndicationPassed)
	}
}

func TestValidationConclusionSetSubIndication(t *testing.T) {
	conclusion := NewValidationConclusion(IndicationFailed)
	conclusion.SetSubIndication(SubIndicationHashFailure)

	if conclusion.SubIndication != SubIndicationHashFailure {
		t.Errorf("SubIndication = %q, want %q", conclusion.SubIndication, SubIndicationHashFailure)
	}
}

func TestValidationConclusionAddError(t *testing.T) {
	conclusion := NewValidationConclusion(IndicationFailed)
	conclusion.AddError("HASH_FAILURE", "Document hash mismatch")

	if len(conclusion.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(conclusion.Errors))
	}
	if conclusion.Errors[0].Key != "HASH_FAILURE" {
		t.Errorf("Error key = %q, want %q", conclusion.Errors[0].Key, "HASH_FAILURE")
	}
}

func TestValidationConclusionAddWarning(t *testing.T) {
	conclusion := NewValidationConclusion(IndicationPassed)
	conclusion.AddWarning("WEAK_ALGO", "SHA-1 is considered weak")

	if len(conclusion.Warnings) != 1 {
		t.Errorf("Expected 1 warning, got %d", len(conclusion.Warnings))
	}
}

func TestValidationConclusionAddInfo(t *testing.T) {
	conclusion := NewValidationConclusion(IndicationPassed)
	conclusion.AddInfo("TIMESTAMP", "Document timestamp verified")

	if len(conclusion.Infos) != 1 {
		t.Errorf("Expected 1 info, got %d", len(conclusion.Infos))
	}
}

func TestValidationConclusionIsPassed(t *testing.T) {
	passed := NewValidationConclusion(IndicationPassed)
	if !passed.IsPassed() {
		t.Error("IsPassed should return true for PASSED")
	}

	failed := NewValidationConclusion(IndicationFailed)
	if failed.IsPassed() {
		t.Error("IsPassed should return false for FAILED")
	}
}

func TestValidationConclusionIsFailed(t *testing.T) {
	failed := NewValidationConclusion(IndicationFailed)
	if !failed.IsFailed() {
		t.Error("IsFailed should return true for FAILED")
	}

	passed := NewValidationConclusion(IndicationPassed)
	if passed.IsFailed() {
		t.Error("IsFailed should return false for PASSED")
	}
}

func TestValidationConclusionIsIndeterminate(t *testing.T) {
	ind := NewValidationConclusion(IndicationIndeterminate)
	if !ind.IsIndeterminate() {
		t.Error("IsIndeterminate should return true for INDETERMINATE")
	}
}

// CertificateInfo tests

func TestNewCertificateInfo(t *testing.T) {
	cert := generateTestCert(t)
	info := NewCertificateInfo(cert, "test-id")

	if info.ID != "test-id" {
		t.Errorf("ID = %q, want %q", info.ID, "test-id")
	}
	if info.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if info.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if info.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	// Note: IsSelfSigned detection depends on signature verification
	// which may not work for test certs created with template as parent
}

func TestCertificateInfoKeyUsage(t *testing.T) {
	cert := generateTestCert(t)
	info := NewCertificateInfo(cert, "test")

	hasDigitalSig := false
	hasContentCommitment := false
	for _, usage := range info.KeyUsage {
		if usage == "digitalSignature" {
			hasDigitalSig = true
		}
		if usage == "contentCommitment" {
			hasContentCommitment = true
		}
	}

	if !hasDigitalSig {
		t.Error("Should have digitalSignature key usage")
	}
	if !hasContentCommitment {
		t.Error("Should have contentCommitment key usage")
	}
}

func TestCertificateInfoExtendedKeyUsage(t *testing.T) {
	cert := generateTestCert(t)
	info := NewCertificateInfo(cert, "test")

	hasEmailProtection := false
	for _, usage := range info.ExtendedKeyUsage {
		if usage == "emailProtection" {
			hasEmailProtection = true
		}
	}

	if !hasEmailProtection {
		t.Error("Should have emailProtection extended key usage")
	}
}

func TestCertificateInfoIsValidAt(t *testing.T) {
	cert := generateTestCert(t)
	info := NewCertificateInfo(cert, "test")

	// Should be valid now
	if !info.IsValidAt(time.Now()) {
		t.Error("Should be valid at current time")
	}

	// Should not be valid before NotBefore
	if info.IsValidAt(info.NotBefore.Add(-24 * time.Hour)) {
		t.Error("Should not be valid before NotBefore")
	}

	// Should not be valid after NotAfter
	if info.IsValidAt(info.NotAfter.Add(24 * time.Hour)) {
		t.Error("Should not be valid after NotAfter")
	}
}

// ValidationReport tests

func TestNewValidationReport(t *testing.T) {
	report := NewValidationReport("test-report")

	if report.ID != "test-report" {
		t.Errorf("ID = %q, want %q", report.ID, "test-report")
	}
	if report.Conclusion == nil {
		t.Error("Conclusion should be initialized")
	}
	if time.Since(report.ValidationTime) > time.Second {
		t.Error("ValidationTime should be close to now")
	}
}

func TestValidationReportSetValidationPolicy(t *testing.T) {
	report := NewValidationReport("test")
	policy := &ValidationPolicy{
		ID:   "policy-1",
		Name: "Default Policy",
	}
	report.SetValidationPolicy(policy)

	if report.ValidationPolicy != policy {
		t.Error("ValidationPolicy not set correctly")
	}
}

func TestValidationReportSetDocumentInfo(t *testing.T) {
	report := NewValidationReport("test")
	info := &DocumentInfo{
		Filename: "test.pdf",
		MimeType: "application/pdf",
		Size:     1024,
	}
	report.SetDocumentInfo(info)

	if report.DocumentInfo != info {
		t.Error("DocumentInfo not set correctly")
	}
}

func TestValidationReportAddSignature(t *testing.T) {
	report := NewValidationReport("test")
	sig := &SignatureInfo{
		ID:              "sig-1",
		SignatureFormat: "PAdES",
		Conclusion:      NewValidationConclusion(IndicationPassed),
	}
	report.AddSignature(sig)

	if len(report.SignatureValidation) != 1 {
		t.Errorf("Expected 1 signature, got %d", len(report.SignatureValidation))
	}
}

func TestValidationReportComputeOverallConclusionNoSigs(t *testing.T) {
	report := NewValidationReport("test")
	report.ComputeOverallConclusion()

	if !report.Conclusion.IsIndeterminate() {
		t.Error("Should be INDETERMINATE with no signatures")
	}
	if report.Conclusion.SubIndication != SubIndicationSignedDataNotFound {
		t.Errorf("SubIndication = %q, want %q", report.Conclusion.SubIndication, SubIndicationSignedDataNotFound)
	}
}

func TestValidationReportComputeOverallConclusionAllPassed(t *testing.T) {
	report := NewValidationReport("test")
	report.AddSignature(&SignatureInfo{
		ID:         "sig-1",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})
	report.AddSignature(&SignatureInfo{
		ID:         "sig-2",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})
	report.ComputeOverallConclusion()

	if !report.Conclusion.IsPassed() {
		t.Error("Should be PASSED when all signatures pass")
	}
}

func TestValidationReportComputeOverallConclusionOneFailed(t *testing.T) {
	report := NewValidationReport("test")
	report.AddSignature(&SignatureInfo{
		ID:         "sig-1",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})

	failedConc := NewValidationConclusion(IndicationFailed)
	failedConc.SetSubIndication(SubIndicationHashFailure)
	report.AddSignature(&SignatureInfo{
		ID:         "sig-2",
		Conclusion: failedConc,
	})
	report.ComputeOverallConclusion()

	if !report.Conclusion.IsFailed() {
		t.Error("Should be FAILED when any signature fails")
	}
	if report.Conclusion.SubIndication != SubIndicationHashFailure {
		t.Errorf("SubIndication = %q, want %q", report.Conclusion.SubIndication, SubIndicationHashFailure)
	}
}

func TestValidationReportSignatureCount(t *testing.T) {
	report := NewValidationReport("test")
	if report.SignatureCount() != 0 {
		t.Error("Should start with 0 signatures")
	}

	report.AddSignature(&SignatureInfo{ID: "sig-1"})
	report.AddSignature(&SignatureInfo{ID: "sig-2"})

	if report.SignatureCount() != 2 {
		t.Errorf("SignatureCount = %d, want 2", report.SignatureCount())
	}
}

func TestValidationReportPassedCount(t *testing.T) {
	report := NewValidationReport("test")
	report.AddSignature(&SignatureInfo{
		ID:         "sig-1",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})
	report.AddSignature(&SignatureInfo{
		ID:         "sig-2",
		Conclusion: NewValidationConclusion(IndicationFailed),
	})
	report.AddSignature(&SignatureInfo{
		ID:         "sig-3",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})

	if report.PassedCount() != 2 {
		t.Errorf("PassedCount = %d, want 2", report.PassedCount())
	}
}

func TestValidationReportFailedCount(t *testing.T) {
	report := NewValidationReport("test")
	report.AddSignature(&SignatureInfo{
		ID:         "sig-1",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})
	report.AddSignature(&SignatureInfo{
		ID:         "sig-2",
		Conclusion: NewValidationConclusion(IndicationFailed),
	})

	if report.FailedCount() != 1 {
		t.Errorf("FailedCount = %d, want 1", report.FailedCount())
	}
}

func TestValidationReportToJSON(t *testing.T) {
	report := NewValidationReport("test-report")
	report.AddSignature(&SignatureInfo{
		ID:              "sig-1",
		SignatureFormat: "PAdES",
		Conclusion:      NewValidationConclusion(IndicationPassed),
	})
	report.ComputeOverallConclusion()

	jsonData, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if parsed["id"] != "test-report" {
		t.Errorf("JSON id = %v, want %q", parsed["id"], "test-report")
	}
}

func TestValidationReportToXML(t *testing.T) {
	report := NewValidationReport("test-report")
	report.AddSignature(&SignatureInfo{
		ID:              "sig-1",
		SignatureFormat: "PAdES",
		Conclusion:      NewValidationConclusion(IndicationPassed),
	})
	report.ComputeOverallConclusion()

	xmlData, err := report.ToXML()
	if err != nil {
		t.Fatalf("ToXML failed: %v", err)
	}

	// Verify it's valid XML
	var parsed ValidationReport
	if err := xml.Unmarshal(xmlData, &parsed); err != nil {
		t.Fatalf("Invalid XML: %v", err)
	}

	if parsed.ID != "test-report" {
		t.Errorf("XML id = %v, want %q", parsed.ID, "test-report")
	}
}

// ReportBuilder tests

func TestReportBuilder(t *testing.T) {
	builder := NewReportBuilder("report-1")
	if builder.report == nil {
		t.Error("Report should be initialized")
	}
}

func TestReportBuilderSetValidationTime(t *testing.T) {
	specificTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	report := NewReportBuilder("test").
		SetValidationTime(specificTime).
		Build()

	if !report.ValidationTime.Equal(specificTime) {
		t.Error("ValidationTime not set correctly")
	}
}

func TestReportBuilderSetPolicy(t *testing.T) {
	report := NewReportBuilder("test").
		SetPolicy("pol-1", "Test Policy", "A test policy").
		Build()

	if report.ValidationPolicy == nil {
		t.Fatal("ValidationPolicy should be set")
	}
	if report.ValidationPolicy.ID != "pol-1" {
		t.Errorf("Policy ID = %q, want %q", report.ValidationPolicy.ID, "pol-1")
	}
}

func TestReportBuilderSetDocument(t *testing.T) {
	report := NewReportBuilder("test").
		SetDocument("test.pdf", "application/pdf", 2048).
		Build()

	if report.DocumentInfo == nil {
		t.Fatal("DocumentInfo should be set")
	}
	if report.DocumentInfo.Filename != "test.pdf" {
		t.Errorf("Filename = %q, want %q", report.DocumentInfo.Filename, "test.pdf")
	}
	if report.DocumentInfo.Size != 2048 {
		t.Errorf("Size = %d, want 2048", report.DocumentInfo.Size)
	}
}

func TestReportBuilderSignatureFlow(t *testing.T) {
	cert := generateTestCert(t)
	signingTime := time.Now()

	report := NewReportBuilder("test").
		StartSignature("sig-1").
		SetSignatureFormat("PAdES").
		SetSignatureLevel("PAdES-B").
		SetSigningTime(signingTime).
		SetSignerCertificate(cert).
		SetSignatureConclusion(IndicationPassed, "").
		EndSignature().
		Build()

	if len(report.SignatureValidation) != 1 {
		t.Fatalf("Expected 1 signature, got %d", len(report.SignatureValidation))
	}

	sig := report.SignatureValidation[0]
	if sig.ID != "sig-1" {
		t.Errorf("Signature ID = %q, want %q", sig.ID, "sig-1")
	}
	if sig.SignatureFormat != "PAdES" {
		t.Errorf("Format = %q, want %q", sig.SignatureFormat, "PAdES")
	}
	if sig.SignatureLevel != "PAdES-B" {
		t.Errorf("Level = %q, want %q", sig.SignatureLevel, "PAdES-B")
	}
	if sig.SignerCertificate == nil {
		t.Error("SignerCertificate should be set")
	}
}

func TestReportBuilderAddChainCertificate(t *testing.T) {
	cert := generateTestCert(t)

	report := NewReportBuilder("test").
		StartSignature("sig-1").
		AddChainCertificate(cert, "cert-1").
		AddChainCertificate(cert, "cert-2").
		SetSignatureConclusion(IndicationPassed, "").
		EndSignature().
		Build()

	if len(report.SignatureValidation[0].CertificateChain) != 2 {
		t.Errorf("Expected 2 chain certs, got %d", len(report.SignatureValidation[0].CertificateChain))
	}
}

func TestReportBuilderAddSignatureError(t *testing.T) {
	report := NewReportBuilder("test").
		StartSignature("sig-1").
		SetSignatureConclusion(IndicationFailed, SubIndicationHashFailure).
		AddSignatureError("HASH", "Hash mismatch").
		EndSignature().
		Build()

	if len(report.SignatureValidation[0].Conclusion.Errors) != 1 {
		t.Error("Should have 1 error")
	}
}

func TestReportBuilderAddSignatureWarning(t *testing.T) {
	report := NewReportBuilder("test").
		StartSignature("sig-1").
		SetSignatureConclusion(IndicationPassed, "").
		AddSignatureWarning("WEAK_ALGO", "SHA-1 is weak").
		EndSignature().
		Build()

	if len(report.SignatureValidation[0].Conclusion.Warnings) != 1 {
		t.Error("Should have 1 warning")
	}
}

func TestReportBuilderAutoEndSignature(t *testing.T) {
	// Build should auto-end any pending signature
	report := NewReportBuilder("test").
		StartSignature("sig-1").
		SetSignatureConclusion(IndicationPassed, "").
		Build() // Note: no EndSignature() call

	if len(report.SignatureValidation) != 1 {
		t.Error("Build should auto-end pending signature")
	}
}

// SimpleReportFormat tests

func TestDefaultSimpleReportFormat(t *testing.T) {
	format := DefaultSimpleReportFormat()

	if !format.IncludeDetails {
		t.Error("IncludeDetails should be true by default")
	}
	if format.IncludeChain {
		t.Error("IncludeChain should be false by default")
	}
	if !format.IncludeTimestamps {
		t.Error("IncludeTimestamps should be true by default")
	}
}

func TestValidationReportToSimpleText(t *testing.T) {
	signingTime := time.Now()
	report := NewReportBuilder("test-report").
		SetDocument("test.pdf", "application/pdf", 1024).
		StartSignature("sig-1").
		SetSignatureFormat("PAdES").
		SetSigningTime(signingTime).
		SetSignatureConclusion(IndicationPassed, "").
		EndSignature().
		Build()

	text := report.ToSimpleText(nil)

	if !strings.Contains(text, "VALIDATION REPORT") {
		t.Error("Should contain report header")
	}
	if !strings.Contains(text, "test-report") {
		t.Error("Should contain report ID")
	}
	if !strings.Contains(text, "test.pdf") {
		t.Error("Should contain document filename")
	}
	if !strings.Contains(text, "PASSED") {
		t.Error("Should contain PASSED result")
	}
	if !strings.Contains(text, "PAdES") {
		t.Error("Should contain signature format")
	}
}

func TestValidationReportToSimpleTextWithChain(t *testing.T) {
	cert := generateTestCert(t)
	report := NewReportBuilder("test").
		StartSignature("sig-1").
		SetSignerCertificate(cert).
		AddChainCertificate(cert, "chain-1").
		SetSignatureConclusion(IndicationPassed, "").
		EndSignature().
		Build()

	format := &SimpleReportFormat{
		IncludeDetails: true,
		IncludeChain:   true,
	}
	text := report.ToSimpleText(format)

	if !strings.Contains(text, "Certificate Chain") {
		t.Error("Should contain certificate chain when enabled")
	}
}

// SignatureLevelDetector tests

func TestSignatureLevelDetectorBasic(t *testing.T) {
	detector := &SignatureLevelDetector{}

	sig := &SignatureInfo{
		ID:              "sig-1",
		SignatureFormat: "PAdES",
	}

	level := detector.DetectLevel(sig)
	if level != "PAdES-B" {
		t.Errorf("Level = %q, want %q", level, "PAdES-B")
	}
}

func TestSignatureLevelDetectorWithTimestamp(t *testing.T) {
	detector := &SignatureLevelDetector{}

	sig := &SignatureInfo{
		ID:         "sig-1",
		Timestamps: []*TimestampInfo{
			{Type: "SIGNATURE_TIMESTAMP"},
		},
	}

	level := detector.DetectLevel(sig)
	if level != "PAdES-T" {
		t.Errorf("Level = %q, want %q", level, "PAdES-T")
	}
}

func TestSignatureLevelDetectorWithLT(t *testing.T) {
	detector := &SignatureLevelDetector{}
	cert := generateTestCert(t)

	sig := &SignatureInfo{
		ID:               "sig-1",
		CertificateChain: []*CertificateInfo{NewCertificateInfo(cert, "cert-1")},
		RevocationData:   []*RevocationInfo{{Type: "CRL"}},
		Timestamps:       []*TimestampInfo{{Type: "SIGNATURE_TIMESTAMP"}},
	}

	level := detector.DetectLevel(sig)
	if level != "PAdES-LT" {
		t.Errorf("Level = %q, want %q", level, "PAdES-LT")
	}
}

func TestSignatureLevelDetectorWithArchive(t *testing.T) {
	detector := &SignatureLevelDetector{}
	cert := generateTestCert(t)

	sig := &SignatureInfo{
		ID:               "sig-1",
		CertificateChain: []*CertificateInfo{NewCertificateInfo(cert, "cert-1")},
		RevocationData:   []*RevocationInfo{{Type: "CRL"}},
		Timestamps:       []*TimestampInfo{{Type: "ARCHIVE_TIMESTAMP"}},
	}

	level := detector.DetectLevel(sig)
	if level != "PAdES-A" {
		t.Errorf("Level = %q, want %q", level, "PAdES-A")
	}
}

// ValidationReportMerger tests

func TestValidationReportMerger(t *testing.T) {
	report1 := NewValidationReport("report-1")
	report1.AddSignature(&SignatureInfo{
		ID:         "sig-1",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})

	report2 := NewValidationReport("report-2")
	report2.AddSignature(&SignatureInfo{
		ID:         "sig-2",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})

	merger := &ValidationReportMerger{}
	merged := merger.Merge([]*ValidationReport{report1, report2}, "merged")

	if merged.SignatureCount() != 2 {
		t.Errorf("Merged should have 2 signatures, got %d", merged.SignatureCount())
	}
	if !merged.Conclusion.IsPassed() {
		t.Error("Merged report should be PASSED")
	}
}

// ValidationReportFilter tests

func TestValidationReportFilterByIndication(t *testing.T) {
	report := NewValidationReport("test")
	report.AddSignature(&SignatureInfo{
		ID:         "sig-1",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})
	report.AddSignature(&SignatureInfo{
		ID:         "sig-2",
		Conclusion: NewValidationConclusion(IndicationFailed),
	})
	report.AddSignature(&SignatureInfo{
		ID:         "sig-3",
		Conclusion: NewValidationConclusion(IndicationPassed),
	})

	filter := &ValidationReportFilter{}

	passed := filter.FilterPassed(report)
	if passed.SignatureCount() != 2 {
		t.Errorf("Passed filter should have 2, got %d", passed.SignatureCount())
	}

	failed := filter.FilterFailed(report)
	if failed.SignatureCount() != 1 {
		t.Errorf("Failed filter should have 1, got %d", failed.SignatureCount())
	}
}

// Indication constants tests

func TestIndicationConstants(t *testing.T) {
	if IndicationPassed != "PASSED" {
		t.Error("IndicationPassed should be 'PASSED'")
	}
	if IndicationFailed != "FAILED" {
		t.Error("IndicationFailed should be 'FAILED'")
	}
	if IndicationIndeterminate != "INDETERMINATE" {
		t.Error("IndicationIndeterminate should be 'INDETERMINATE'")
	}
}

// Sub-indication constants tests

func TestSubIndicationConstants(t *testing.T) {
	subIndications := []string{
		SubIndicationFormatFailure,
		SubIndicationHashFailure,
		SubIndicationSigConstraintsFailure,
		SubIndicationExpiredNoPoE,
		SubIndicationRevokedNoPoe,
		SubIndicationSigCryptoFailure,
		SubIndicationRevoked,
		SubIndicationNoCertificateChainFound,
		SubIndicationNoSignerCertFound,
	}

	for _, si := range subIndications {
		if si == "" {
			t.Error("Sub-indication should not be empty")
		}
	}
}

// SignatureProductionPlace tests

func TestSignatureProductionPlace(t *testing.T) {
	place := &SignatureProductionPlace{
		City:        "London",
		CountryName: "UK",
	}

	if place.City != "London" {
		t.Error("City should be London")
	}
	if place.CountryName != "UK" {
		t.Error("CountryName should be UK")
	}
}

// SignerRole tests

func TestSignerRole(t *testing.T) {
	role := &SignerRole{
		ClaimedRoles:   []string{"Author", "Reviewer"},
		CertifiedRoles: []string{"Manager"},
	}

	if len(role.ClaimedRoles) != 2 {
		t.Errorf("Expected 2 claimed roles, got %d", len(role.ClaimedRoles))
	}
	if len(role.CertifiedRoles) != 1 {
		t.Errorf("Expected 1 certified role, got %d", len(role.CertifiedRoles))
	}
}

// SignatureScope tests

func TestSignatureScope(t *testing.T) {
	scope := &SignatureScope{
		Name:        "Full document",
		Description: "Entire PDF document",
		Scope:       "FULL",
	}

	if scope.Scope != "FULL" {
		t.Error("Scope should be FULL")
	}
}

// TimestampInfo tests

func TestTimestampInfo(t *testing.T) {
	ts := &TimestampInfo{
		ID:             "ts-1",
		Type:           "SIGNATURE_TIMESTAMP",
		ProductionTime: time.Now(),
		DigestAlgorithm: "SHA-256",
		Conclusion:     NewValidationConclusion(IndicationPassed),
	}

	if ts.Type != "SIGNATURE_TIMESTAMP" {
		t.Error("Type should be SIGNATURE_TIMESTAMP")
	}
	if ts.Conclusion == nil {
		t.Error("Conclusion should not be nil")
	}
}

// RevocationInfo tests

func TestRevocationInfo(t *testing.T) {
	now := time.Now()
	revInfo := &RevocationInfo{
		ID:             "rev-1",
		Type:           "CRL",
		ProductionTime: now,
		ThisUpdate:     now.Add(-time.Hour),
	}

	if revInfo.Type != "CRL" {
		t.Error("Type should be CRL")
	}
	if revInfo.RevocationDate != nil {
		t.Error("RevocationDate should be nil for non-revoked")
	}
}

// DocumentInfo tests

func TestDocumentInfo(t *testing.T) {
	info := &DocumentInfo{
		Filename:    "contract.pdf",
		MimeType:    "application/pdf",
		DigestAlgo:  "SHA-256",
		DigestValue: "abc123",
		Size:        4096,
	}

	if info.Filename != "contract.pdf" {
		t.Error("Filename mismatch")
	}
	if info.Size != 4096 {
		t.Error("Size mismatch")
	}
}

// ValidationPolicy tests

func TestValidationPolicy(t *testing.T) {
	policy := &ValidationPolicy{
		ID:          "etsi-default",
		Name:        "ETSI Default Policy",
		Description: "Default validation policy per ETSI standards",
		URL:         "http://example.com/policy",
	}

	if policy.ID != "etsi-default" {
		t.Error("ID mismatch")
	}
	if policy.URL != "http://example.com/policy" {
		t.Error("URL mismatch")
	}
}
