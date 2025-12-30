package certvalidator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func generateTestCertForContext(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestValidationTimingInfo(t *testing.T) {
	now := time.Now()
	sigTime := now.Add(-time.Hour)

	info := NewValidationTimingInfo(now, sigTime, true)

	if !info.ValidationTime.Equal(now) {
		t.Errorf("ValidationTime = %v, want %v", info.ValidationTime, now)
	}
	if !info.BestSignatureTime.Equal(sigTime) {
		t.Errorf("BestSignatureTime = %v, want %v", info.BestSignatureTime, sigTime)
	}
	if !info.PointInTimeValidation {
		t.Error("PointInTimeValidation should be true")
	}
}

func TestValidationTimingParams(t *testing.T) {
	now := time.Now()
	info := NewValidationTimingInfo(now, now, false)
	params := NewValidationTimingParams(info, time.Second)

	if params.TimeTolerance != time.Second {
		t.Errorf("TimeTolerance = %v, want %v", params.TimeTolerance, time.Second)
	}
	if !params.ValidationTime().Equal(now) {
		t.Errorf("ValidationTime() = %v, want %v", params.ValidationTime(), now)
	}
}

func TestValidationTimingParamsNegativeTolerance(t *testing.T) {
	params := NewValidationTimingParams(nil, -5*time.Second)

	if params.TimeTolerance != 5*time.Second {
		t.Errorf("TimeTolerance = %v, want %v (absolute value)", params.TimeTolerance, 5*time.Second)
	}
}

func TestNewEnhancedValidationContext(t *testing.T) {
	ctx, err := NewEnhancedValidationContext()
	if err != nil {
		t.Fatalf("NewEnhancedValidationContext() error = %v", err)
	}

	if ctx.CertificateRegistry == nil {
		t.Error("CertificateRegistry should not be nil")
	}
	if ctx.TrustManager == nil {
		t.Error("TrustManager should not be nil")
	}
	if ctx.POEManager == nil {
		t.Error("POEManager should not be nil")
	}
	if ctx.AlgorithmPolicy == nil {
		t.Error("AlgorithmPolicy should not be nil")
	}
	if ctx.SigValidator == nil {
		t.Error("SigValidator should not be nil")
	}
}

func TestEnhancedValidationContextWithOptions(t *testing.T) {
	rootCert := generateTestCertForContext(t, "Root CA")
	otherCert := generateTestCertForContext(t, "Other Cert")
	moment := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	ctx, err := NewEnhancedValidationContext(
		WithTrustRoots([]*x509.Certificate{rootCert}),
		WithOtherCerts([]*x509.Certificate{otherCert}),
		WithMoment(moment),
		WithTimeTolerance(5*time.Second),
		WithRevocationMode(ContextRevocationModeHardFail),
		WithAllowFetching(true),
	)
	if err != nil {
		t.Fatalf("NewEnhancedValidationContext() error = %v", err)
	}

	if !ctx.Moment().Equal(moment) {
		t.Errorf("Moment() = %v, want %v", ctx.Moment(), moment)
	}
	if ctx.TimeTolerance() != 5*time.Second {
		t.Errorf("TimeTolerance() = %v, want %v", ctx.TimeTolerance(), 5*time.Second)
	}
	if !ctx.FetchingAllowed {
		t.Error("FetchingAllowed should be true")
	}
}

func TestEnhancedValidationContextWhitelisting(t *testing.T) {
	cert := generateTestCertForContext(t, "Test Cert")
	fingerprint := hex.EncodeToString(hashCertSHA1(cert.Raw))

	ctx, _ := NewEnhancedValidationContext(
		WithWhitelistedCerts([]string{fingerprint}),
	)

	if !ctx.IsWhitelisted(cert) {
		t.Error("IsWhitelisted() should return true for whitelisted cert")
	}

	otherCert := generateTestCertForContext(t, "Other Cert")
	if ctx.IsWhitelisted(otherCert) {
		t.Error("IsWhitelisted() should return false for non-whitelisted cert")
	}
}

func TestEnhancedValidationContextAddWhitelistedCert(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()
	cert := generateTestCertForContext(t, "Test Cert")

	fingerprint := hex.EncodeToString(hashCertSHA1(cert.Raw))
	ctx.AddWhitelistedCert(fingerprint)

	if !ctx.IsWhitelisted(cert) {
		t.Error("IsWhitelisted() should return true after adding to whitelist")
	}
}

func TestEnhancedValidationContextWhitelistFormats(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()
	cert := generateTestCertForContext(t, "Test Cert")

	fingerprint := hex.EncodeToString(hashCertSHA1(cert.Raw))

	// Test with colons
	fpWithColons := ""
	for i, c := range fingerprint {
		fpWithColons += string(c)
		if i%2 == 1 && i < len(fingerprint)-1 {
			fpWithColons += ":"
		}
	}
	ctx.AddWhitelistedCert(fpWithColons)

	if !ctx.IsWhitelisted(cert) {
		t.Error("IsWhitelisted() should work with colon-separated fingerprint")
	}
}

func hashCertSHA1(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func TestEnhancedValidationContextRecordValidation(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()
	cert := generateTestCertForContext(t, "Test Cert")
	path := NewValidationPath(nil)

	// Initially no validation recorded
	if ctx.CheckValidation(cert) != nil {
		t.Error("CheckValidation() should return nil before recording")
	}

	// Record validation
	ctx.RecordValidation(cert, path)

	// Check validation
	recorded := ctx.CheckValidation(cert)
	if recorded == nil {
		t.Error("CheckValidation() should return path after recording")
	}

	// Clear validation
	ctx.ClearValidation(cert)

	if ctx.CheckValidation(cert) != nil {
		t.Error("CheckValidation() should return nil after clearing")
	}
}

func TestEnhancedValidationContextSoftFailExceptions(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()

	err1 := NewPathError("soft fail 1")
	err2 := NewPathError("soft fail 2")

	ctx.ReportSoftFail(err1)
	ctx.ReportSoftFail(err2)

	exceptions := ctx.SoftFailExceptions()
	if len(exceptions) != 2 {
		t.Errorf("SoftFailExceptions() = %d, want 2", len(exceptions))
	}

	ctx.ClearSoftFailExceptions()

	exceptions = ctx.SoftFailExceptions()
	if len(exceptions) != 0 {
		t.Errorf("SoftFailExceptions() after clear = %d, want 0", len(exceptions))
	}
}

func TestValidationDataHandlers(t *testing.T) {
	handlers := BootstrapValidationDataHandlers(nil, nil, nil)

	if handlers.RevInfoManager == nil {
		t.Error("RevInfoManager should not be nil")
	}
	if handlers.POEManager == nil {
		t.Error("POEManager should not be nil")
	}
	if handlers.CertRegistry == nil {
		t.Error("CertRegistry should not be nil")
	}
}

func TestValidationDataHandlersWithCerts(t *testing.T) {
	certs := []*x509.Certificate{
		generateTestCertForContext(t, "Cert 1"),
		generateTestCertForContext(t, "Cert 2"),
	}

	handlers := BootstrapValidationDataHandlers(nil, certs, nil)

	if handlers.CertRegistry.Count() != 2 {
		t.Errorf("CertRegistry.Count() = %d, want 2", handlers.CertRegistry.Count())
	}
}

func TestCertValidationPolicySpec(t *testing.T) {
	tm := NewSimpleTrustManager()
	spec := NewCertValidationPolicySpec(tm)

	if spec.TrustManager != tm {
		t.Error("TrustManager not set correctly")
	}
	if spec.TimeTolerance != time.Second {
		t.Errorf("TimeTolerance = %v, want %v", spec.TimeTolerance, time.Second)
	}
	if spec.AlgorithmUsagePolicy == nil {
		t.Error("AlgorithmUsagePolicy should not be nil")
	}
	if spec.SignatureValidator == nil {
		t.Error("SignatureValidator should not be nil")
	}
}

func TestCertValidationPolicySpecBuildContext(t *testing.T) {
	tm := NewSimpleTrustManager()
	spec := NewCertValidationPolicySpec(tm)

	timingInfo := NewValidationTimingInfo(time.Now(), time.Now(), false)
	handlers := BootstrapValidationDataHandlers(nil, nil, nil)

	ctx, err := spec.BuildValidationContext(timingInfo, handlers)
	if err != nil {
		t.Fatalf("BuildValidationContext() error = %v", err)
	}

	if ctx.TrustManager != tm {
		t.Error("TrustManager not set correctly in context")
	}
}

func TestContextRevocationMode(t *testing.T) {
	tests := []struct {
		mode     ContextRevocationMode
		expected string
	}{
		{ContextRevocationModeSoftFail, "soft-fail"},
		{ContextRevocationModeHardFail, "hard-fail"},
		{ContextRevocationModeRequire, "require"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.expected {
			t.Errorf("ContextRevocationMode %v = %s, want %s", tt.mode, tt.mode, tt.expected)
		}
	}
}

func TestContextGeneralNameTypes(t *testing.T) {
	// Test Email
	email := NewContextGeneralNameFromEmail("test@example.com")
	if email.Type != GeneralNameRFC822Name {
		t.Errorf("Email GeneralName Type = %v, want %v", email.Type, GeneralNameRFC822Name)
	}
	if email.Value != "test@example.com" {
		t.Errorf("Email GeneralName Value = %v, want test@example.com", email.Value)
	}

	// Test DNS
	dns := NewContextGeneralNameFromDNS("example.com")
	if dns.Type != GeneralNameDNSName {
		t.Errorf("DNS GeneralName Type = %v, want %v", dns.Type, GeneralNameDNSName)
	}

	// Test URI
	uri := NewContextGeneralNameFromURI("https://example.com")
	if uri.Type != GeneralNameURI {
		t.Errorf("URI GeneralName Type = %v, want %v", uri.Type, GeneralNameURI)
	}

	// Test IP
	ip := NewContextGeneralNameFromIP("192.168.1.1")
	if ip.Type != GeneralNameIPAddress {
		t.Errorf("IP GeneralName Type = %v, want %v", ip.Type, GeneralNameIPAddress)
	}

	// Test Directory
	name := pkix.Name{CommonName: "Test"}
	dir := NewContextGeneralNameFromDirectory(name)
	if dir.Type != GeneralNameDirectoryName {
		t.Errorf("Directory GeneralName Type = %v, want %v", dir.Type, GeneralNameDirectoryName)
	}
}

func TestEnhancedValidationContextDefaultTiming(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()

	// Moment should be close to now
	now := time.Now()
	diff := ctx.Moment().Sub(now)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Moment() = %v, should be close to now (%v)", ctx.Moment(), now)
	}

	// BestSignatureTime should equal Moment by default
	if ctx.BestSignatureTime() != ctx.Moment() {
		t.Error("BestSignatureTime() should equal Moment() by default")
	}
}

func TestEnhancedValidationContextConcurrency(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext()

	// Test concurrent operations
	done := make(chan bool)

	// Concurrent whitelist operations
	go func() {
		for i := 0; i < 100; i++ {
			ctx.AddWhitelistedCert("abc123")
		}
		done <- true
	}()

	// Concurrent validation recording
	go func() {
		cert := generateTestCertForContext(t, "Test")
		for i := 0; i < 100; i++ {
			ctx.RecordValidation(cert, nil)
			ctx.CheckValidation(cert)
		}
		done <- true
	}()

	// Concurrent soft fail reporting
	go func() {
		for i := 0; i < 100; i++ {
			ctx.ReportSoftFail(NewPathError("test"))
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}
}

func TestEnhancedValidationContextWithBestSignatureTime(t *testing.T) {
	moment := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	sigTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)

	ctx, _ := NewEnhancedValidationContext(
		WithMoment(moment),
		WithBestSignatureTime(sigTime),
	)

	if !ctx.BestSignatureTime().Equal(sigTime) {
		t.Errorf("BestSignatureTime() = %v, want %v", ctx.BestSignatureTime(), sigTime)
	}
}

func TestEnhancedValidationContextWithWeakHashAlgos(t *testing.T) {
	ctx, _ := NewEnhancedValidationContext(
		WithWeakHashAlgos([]string{"md5", "sha1"}),
	)

	if ctx.AlgorithmPolicy == nil {
		t.Error("AlgorithmPolicy should not be nil")
	}
}

func TestEnhancedValidationContextWithACTargets(t *testing.T) {
	targets := &ACTargetDescription{}

	ctx, _ := NewEnhancedValidationContext(
		WithAcceptableACTargets(targets),
	)

	if ctx.AcceptableACTargets != targets {
		t.Error("AcceptableACTargets not set correctly")
	}
}
