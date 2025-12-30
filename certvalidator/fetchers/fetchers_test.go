package fetchers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", config.Timeout)
	}
	if config.MaxResponseSize != 10*1024*1024 {
		t.Errorf("Expected max size 10MB, got %d", config.MaxResponseSize)
	}
	if config.UserAgent == "" {
		t.Error("UserAgent should not be empty")
	}
	if !config.UseCache {
		t.Error("UseCache should be true by default")
	}
	if config.MaxRetries != 3 {
		t.Errorf("Expected 3 retries, got %d", config.MaxRetries)
	}
}

func TestNewFetcher(t *testing.T) {
	fetcher := NewFetcher(nil)
	if fetcher == nil {
		t.Fatal("NewFetcher returned nil")
	}
	if fetcher.config == nil {
		t.Error("config should not be nil")
	}
	if fetcher.client == nil {
		t.Error("client should not be nil")
	}
	if fetcher.cache == nil {
		t.Error("cache should not be nil")
	}
}

func TestNewFetcherWithConfig(t *testing.T) {
	config := &FetcherConfig{
		Timeout:   10 * time.Second,
		UserAgent: "test-agent",
	}

	fetcher := NewFetcher(config)
	if fetcher.config.UserAgent != "test-agent" {
		t.Errorf("Expected user agent 'test-agent', got '%s'", fetcher.config.UserAgent)
	}
}

func TestResponseCache(t *testing.T) {
	cache := newResponseCache(1 * time.Hour)

	// Set and get
	cache.set("key1", []byte("value1"))
	data, ok := cache.get("key1")
	if !ok {
		t.Error("Expected to get cached value")
	}
	if string(data) != "value1" {
		t.Errorf("Expected 'value1', got '%s'", string(data))
	}

	// Non-existent key
	_, ok = cache.get("nonexistent")
	if ok {
		t.Error("Should not find non-existent key")
	}
}

func TestResponseCacheExpiration(t *testing.T) {
	cache := newResponseCache(1 * time.Millisecond)

	cache.set("key1", []byte("value1"))
	time.Sleep(5 * time.Millisecond)

	_, ok := cache.get("key1")
	if ok {
		t.Error("Cache entry should have expired")
	}
}

func TestFetcherFetch(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	fetcher := NewFetcher(DefaultConfig())
	ctx := context.Background()

	data, err := fetcher.Fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if string(data) != "test response" {
		t.Errorf("Expected 'test response', got '%s'", string(data))
	}
}

func TestFetcherFetchCaching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte("response"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.UseCache = true
	fetcher := NewFetcher(config)
	ctx := context.Background()

	// First fetch
	fetcher.Fetch(ctx, server.URL)
	// Second fetch (should use cache)
	fetcher.Fetch(ctx, server.URL)

	if callCount != 1 {
		t.Errorf("Expected 1 server call (cached), got %d", callCount)
	}
}

func TestFetcherFetchNoCaching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write([]byte("response"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.UseCache = false
	fetcher := NewFetcher(config)
	ctx := context.Background()

	fetcher.Fetch(ctx, server.URL)
	fetcher.Fetch(ctx, server.URL)

	if callCount != 2 {
		t.Errorf("Expected 2 server calls (no cache), got %d", callCount)
	}
}

func TestFetcherFetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.MaxRetries = 0 // No retries
	fetcher := NewFetcher(config)
	ctx := context.Background()

	_, err := fetcher.Fetch(ctx, server.URL)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}

func TestFetcherFetchInvalidURL(t *testing.T) {
	fetcher := NewFetcher(DefaultConfig())
	ctx := context.Background()

	_, err := fetcher.Fetch(ctx, "not a valid url")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestFetcherFetchUnsupportedScheme(t *testing.T) {
	fetcher := NewFetcher(DefaultConfig())
	ctx := context.Background()

	_, err := fetcher.Fetch(ctx, "ftp://example.com/file")
	if err == nil {
		t.Error("Expected error for unsupported scheme")
	}
}

func TestFetcherClearCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response"))
	}))
	defer server.Close()

	fetcher := NewFetcher(DefaultConfig())
	ctx := context.Background()

	fetcher.Fetch(ctx, server.URL)
	fetcher.ClearCache()

	// Check cache is empty
	_, ok := fetcher.cache.get(server.URL)
	if ok {
		t.Error("Cache should be cleared")
	}
}

func TestNewCRLFetcher(t *testing.T) {
	fetcher := NewCRLFetcher(nil)
	if fetcher == nil {
		t.Fatal("NewCRLFetcher returned nil")
	}
}

func TestNewOCSPFetcher(t *testing.T) {
	fetcher := NewOCSPFetcher(nil)
	if fetcher == nil {
		t.Fatal("NewOCSPFetcher returned nil")
	}
}

func TestNewCertFetcher(t *testing.T) {
	fetcher := NewCertFetcher(nil)
	if fetcher == nil {
		t.Fatal("NewCertFetcher returned nil")
	}
}

func TestRevocationStatusString(t *testing.T) {
	tests := []struct {
		status   RevocationStatus
		expected string
	}{
		{RevocationStatusGood, "good"},
		{RevocationStatusRevoked, "revoked"},
		{RevocationStatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		result := tt.status.String()
		if result != tt.expected {
			t.Errorf("RevocationStatus.String() = %s, want %s", result, tt.expected)
		}
	}
}

func TestNewRevocationChecker(t *testing.T) {
	checker := NewRevocationChecker(nil, true)
	if checker == nil {
		t.Fatal("NewRevocationChecker returned nil")
	}
	if !checker.preferOCSP {
		t.Error("preferOCSP should be true")
	}

	checker2 := NewRevocationChecker(nil, false)
	if checker2.preferOCSP {
		t.Error("preferOCSP should be false")
	}
}

func TestNewAIAFetcher(t *testing.T) {
	fetcher := NewAIAFetcher(nil)
	if fetcher == nil {
		t.Fatal("NewAIAFetcher returned nil")
	}
}

func TestParseCertificatePEM(t *testing.T) {
	// Create a test certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	// Encode as PEM
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	certs, err := parseCertificatePEM(buf.Bytes())
	if err != nil {
		t.Fatalf("parseCertificatePEM failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}
}

func TestParseCertificatePEMMultiple(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	certs, err := parseCertificatePEM(buf.Bytes())
	if err != nil {
		t.Fatalf("parseCertificatePEM failed: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}
}

func TestParseCertificatePEMNotPEM(t *testing.T) {
	_, err := parseCertificatePEM([]byte("not pem data"))
	if err == nil {
		t.Error("Expected error for non-PEM data")
	}
}

func TestCertFetcherFetchCertificate(t *testing.T) {
	// Create a test certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	// Serve DER certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(certDER)
	}))
	defer server.Close()

	fetcher := NewCertFetcher(DefaultConfig())
	ctx := context.Background()

	cert, err := fetcher.FetchCertificate(ctx, server.URL)
	if err != nil {
		t.Fatalf("FetchCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != "Test Cert" {
		t.Errorf("Expected CN 'Test Cert', got '%s'", cert.Subject.CommonName)
	}
}

func TestCertFetcherFetchCertificatePEM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "PEM Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	var pemBuf bytes.Buffer
	pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pemBuf.Bytes())
	}))
	defer server.Close()

	fetcher := NewCertFetcher(DefaultConfig())
	ctx := context.Background()

	cert, err := fetcher.FetchCertificate(ctx, server.URL)
	if err != nil {
		t.Fatalf("FetchCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != "PEM Test Cert" {
		t.Errorf("Expected CN 'PEM Test Cert', got '%s'", cert.Subject.CommonName)
	}
}

func TestCertFetcherFetchCertificates(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(certDER)
	}))
	defer server.Close()

	fetcher := NewCertFetcher(DefaultConfig())
	ctx := context.Background()

	certs, err := fetcher.FetchCertificates(ctx, server.URL)
	if err != nil {
		t.Fatalf("FetchCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}
}

func TestCRLFetcherFetchCRLsForCertNoDistPoints(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		// No CRLDistributionPoints
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	fetcher := NewCRLFetcher(DefaultConfig())
	ctx := context.Background()

	_, err := fetcher.FetchCRLsForCert(ctx, cert)
	if err != ErrNoDistributionPoints {
		t.Errorf("Expected ErrNoDistributionPoints, got %v", err)
	}
}

func TestOCSPFetcherNoServers(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		// No OCSPServer
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	fetcher := NewOCSPFetcher(DefaultConfig())
	ctx := context.Background()

	req := &OCSPRequest{
		Certificate: cert,
		Issuer:      cert,
	}

	_, err := fetcher.FetchOCSP(ctx, req)
	if err != ErrNoOCSPServers {
		t.Errorf("Expected ErrNoOCSPServers, got %v", err)
	}
}

func TestCertFetcherFetchIssuingCertificate(t *testing.T) {
	// Create issuer certificate
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Issuer CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)

	// Serve issuer certificate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(issuerDER)
	}))
	defer server.Close()

	// Create leaf certificate with AIA
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IssuingCertificateURL: []string{server.URL},
	}

	issuerCert, _ := x509.ParseCertificate(issuerDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	fetcher := NewCertFetcher(DefaultConfig())
	ctx := context.Background()

	issuer, err := fetcher.FetchIssuingCertificate(ctx, leafCert)
	if err != nil {
		t.Fatalf("FetchIssuingCertificate failed: %v", err)
	}

	if issuer.Subject.CommonName != "Issuer CA" {
		t.Errorf("Expected CN 'Issuer CA', got '%s'", issuer.Subject.CommonName)
	}
}

func TestRevocationCheckerCheckRevocation(t *testing.T) {
	// Create test certificates (no OCSP/CRL endpoints)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	checker := NewRevocationChecker(nil, true)
	ctx := context.Background()

	result := checker.CheckRevocation(ctx, cert, cert)

	// Should return unknown since no endpoints available
	if result.Status != RevocationStatusUnknown {
		t.Errorf("Expected Unknown status, got %v", result.Status)
	}
}

func TestAIAFetcherFetchIssuers(t *testing.T) {
	// Create issuer certificate
	issuerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(issuerDER)
	}))
	defer server.Close()

	// Create leaf with AIA
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IssuingCertificateURL: []string{server.URL},
	}

	issuerCert, _ := x509.ParseCertificate(issuerDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	fetcher := NewAIAFetcher(DefaultConfig())
	ctx := context.Background()

	issuers, err := fetcher.FetchIssuers(ctx, leafCert)
	if err != nil {
		t.Fatalf("FetchIssuers failed: %v", err)
	}

	if len(issuers) != 1 {
		t.Errorf("Expected 1 issuer, got %d", len(issuers))
	}
}

func TestBase64Encoding(t *testing.T) {
	data := []byte("test data")
	encoded := base64.StdEncoding.EncodeToString(data)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if !bytes.Equal(data, decoded) {
		t.Error("Data mismatch after encode/decode")
	}
}

func TestFetcherWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("response"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.MaxRetries = 0
	fetcher := NewFetcher(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := fetcher.Fetch(ctx, server.URL)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestFetcherRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("success"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.MaxRetries = 3
	config.RetryDelay = 1 * time.Millisecond
	fetcher := NewFetcher(config)
	ctx := context.Background()

	data, err := fetcher.Fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("Fetch failed after retries: %v", err)
	}

	if string(data) != "success" {
		t.Errorf("Expected 'success', got '%s'", string(data))
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}
