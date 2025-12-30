// Package timestamps provides tests for the dummy timestamper.
package timestamps

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// createTestCert creates a test certificate and key for timestamping tests.
func createTestCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TSA",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func TestNewDummyTimeStamper(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	ts := NewDummyTimeStamper(cert, key)

	if ts == nil {
		t.Fatal("expected non-nil timestamper")
	}
	if ts.TSACert != cert {
		t.Error("TSACert not set correctly")
	}
	if ts.TSAKey != key {
		t.Error("TSAKey not set correctly")
	}
	if !ts.IncludeNonce {
		t.Error("IncludeNonce should default to true")
	}
	if len(ts.Policy) == 0 {
		t.Error("Policy should have a default value")
	}
}

func TestDummyTimeStamperWithCertsToEmbed(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	// Create another certificate to embed
	extraCert, _, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create extra cert: %v", err)
	}

	ts := NewDummyTimeStamper(cert, key).
		WithCertsToEmbed([]*x509.Certificate{extraCert})

	if len(ts.CertsToEmbed) != 1 {
		t.Errorf("expected 1 cert to embed, got %d", len(ts.CertsToEmbed))
	}
	if ts.CertsToEmbed[0] != extraCert {
		t.Error("wrong certificate embedded")
	}
}

func TestDummyTimeStamperWithFixedTime(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	ts := NewDummyTimeStamper(cert, key).
		WithFixedTime(fixedTime)

	if ts.FixedTime == nil {
		t.Fatal("expected FixedTime to be set")
	}
	if !ts.FixedTime.Equal(fixedTime) {
		t.Errorf("expected %v, got %v", fixedTime, *ts.FixedTime)
	}
}

func TestDummyTimeStamperWithoutNonce(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	ts := NewDummyTimeStamper(cert, key).
		WithoutNonce()

	if ts.IncludeNonce {
		t.Error("IncludeNonce should be false")
	}
}

func TestDummyTimeStamperWithPolicy(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	customPolicy := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	ts := NewDummyTimeStamper(cert, key).
		WithPolicy(customPolicy)

	if !ts.Policy.Equal(customPolicy) {
		t.Errorf("expected policy %v, got %v", customPolicy, ts.Policy)
	}
}

func TestDummyTimeStamperTimestamp(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	ts := NewDummyTimeStamper(cert, key)
	data := []byte("test data to timestamp")

	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	if len(token) == 0 {
		t.Fatal("expected non-empty token")
	}

	// Verify the token is valid CMS structure
	tstInfo, err := ExtractTSTInfo(token)
	if err != nil {
		t.Fatalf("failed to extract TSTInfo: %v", err)
	}

	if tstInfo.Version != 1 {
		t.Errorf("expected version 1, got %d", tstInfo.Version)
	}
}

func TestDummyTimeStamperTimestampWithOptions(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	ts := NewDummyTimeStamper(cert, key)
	data := []byte("test data to timestamp with options")

	opts := &TimestampRequestOptions{
		HashAlgorithm: crypto.SHA256,
		IncludeNonce:  true,
		RequestCerts:  true,
	}

	token, err := ts.TimestampWithOptions(data, opts)
	if err != nil {
		t.Fatalf("TimestampWithOptions failed: %v", err)
	}

	if len(token) == 0 {
		t.Fatal("expected non-empty token")
	}

	// Verify the token
	tstInfo, err := ExtractTSTInfo(token)
	if err != nil {
		t.Fatalf("failed to extract TSTInfo: %v", err)
	}

	// Verify message imprint matches
	if err := VerifyTimestamp(token, data); err != nil {
		t.Errorf("timestamp verification failed: %v", err)
	}

	// Check that policy is set
	if len(tstInfo.Policy) == 0 {
		t.Error("expected policy to be set")
	}
}

func TestDummyTimeStamperWithFixedTimeInToken(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	fixedTime := time.Date(2024, 6, 15, 14, 30, 45, 0, time.UTC)
	ts := NewDummyTimeStamper(cert, key).
		WithFixedTime(fixedTime)

	data := []byte("test data")
	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	genTime, err := GetGenTime(token)
	if err != nil {
		t.Fatalf("GetGenTime failed: %v", err)
	}

	// Compare with some tolerance due to time zone handling
	if !genTime.Equal(fixedTime) {
		t.Errorf("expected gen time %v, got %v", fixedTime, genTime)
	}
}

func TestDummyTimeStamperNoNonceInToken(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	ts := NewDummyTimeStamper(cert, key).
		WithoutNonce()

	data := []byte("test data")
	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	tstInfo, err := ExtractTSTInfo(token)
	if err != nil {
		t.Fatalf("failed to extract TSTInfo: %v", err)
	}

	if tstInfo.Nonce != nil {
		t.Error("expected nonce to be nil when WithoutNonce is used")
	}
}

func TestCreateTestTimestamper(t *testing.T) {
	ts, err := CreateTestTimestamper()
	if err != nil {
		t.Fatalf("CreateTestTimestamper failed: %v", err)
	}

	if ts == nil {
		t.Fatal("expected non-nil timestamper")
	}

	if ts.TSACert == nil {
		t.Error("expected TSACert to be set")
	}
	if ts.TSAKey == nil {
		t.Error("expected TSAKey to be set")
	}

	// Verify it can create timestamps
	data := []byte("test data for test timestamper")
	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	if err := VerifyTimestamp(token, data); err != nil {
		t.Errorf("verification failed: %v", err)
	}
}

func TestNewDummyTimestamperFromConfig(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	customPolicy := asn1.ObjectIdentifier{1, 2, 3, 4}

	cfg := &DummyTimestamperConfig{
		Certificate:  cert,
		PrivateKey:   key,
		FixedTime:    &fixedTime,
		IncludeNonce: false,
		Policy:       customPolicy,
	}

	ts, err := NewDummyTimestamperFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewDummyTimestamperFromConfig failed: %v", err)
	}

	if ts.TSACert != cert {
		t.Error("certificate not set correctly")
	}
	if ts.TSAKey != key {
		t.Error("private key not set correctly")
	}
	if ts.FixedTime == nil || !ts.FixedTime.Equal(fixedTime) {
		t.Error("fixed time not set correctly")
	}
	if ts.IncludeNonce {
		t.Error("include nonce should be false")
	}
	if !ts.Policy.Equal(customPolicy) {
		t.Error("policy not set correctly")
	}
}

func TestNewDummyTimestamperFromConfigErrors(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	// Test missing certificate
	cfg := &DummyTimestamperConfig{
		PrivateKey: key,
	}
	_, err = NewDummyTimestamperFromConfig(cfg)
	if err == nil {
		t.Error("expected error for missing certificate")
	}

	// Test missing private key
	cfg = &DummyTimestamperConfig{
		Certificate: cert,
	}
	_, err = NewDummyTimestamperFromConfig(cfg)
	if err == nil {
		t.Error("expected error for missing private key")
	}
}

func TestDummyTimeStamperWithAdditionalCerts(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	// Create additional certificates
	extraCert1, _, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create extra cert 1: %v", err)
	}
	extraCert2, _, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create extra cert 2: %v", err)
	}

	cfg := &DummyTimestamperConfig{
		Certificate:     cert,
		PrivateKey:      key,
		AdditionalCerts: []*x509.Certificate{extraCert1, extraCert2},
		IncludeNonce:    true,
	}

	ts, err := NewDummyTimestamperFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewDummyTimestamperFromConfig failed: %v", err)
	}

	data := []byte("test data")
	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	// Parse the token to verify certificates are embedded
	parsedToken, err := ParseTimestampToken(token)
	if err != nil {
		t.Fatalf("ParseTimestampToken failed: %v", err)
	}

	// Should have at least 3 certificates (TSA + 2 additional)
	if len(parsedToken.Certificates) < 3 {
		t.Errorf("expected at least 3 certificates, got %d", len(parsedToken.Certificates))
	}
}

func TestDummyTimeStamperTimestampInterface(t *testing.T) {
	ts, err := CreateTestTimestamper()
	if err != nil {
		t.Fatalf("CreateTestTimestamper failed: %v", err)
	}

	// Verify DummyTimeStamper implements Timestamper interface
	var _ Timestamper = ts

	data := []byte("interface test data")
	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	if len(token) == 0 {
		t.Error("expected non-empty token")
	}
}

func TestDummyTimeStamperChainedMethods(t *testing.T) {
	cert, key, err := createTestCert()
	if err != nil {
		t.Fatalf("failed to create test cert: %v", err)
	}

	extraCert, _, _ := createTestCert()
	fixedTime := time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC)
	customPolicy := asn1.ObjectIdentifier{1, 2, 840, 10065, 2, 1}

	ts := NewDummyTimeStamper(cert, key).
		WithCertsToEmbed([]*x509.Certificate{extraCert}).
		WithFixedTime(fixedTime).
		WithoutNonce().
		WithPolicy(customPolicy)

	// Verify all settings
	if len(ts.CertsToEmbed) != 1 {
		t.Error("CertsToEmbed not set correctly")
	}
	if ts.FixedTime == nil || !ts.FixedTime.Equal(fixedTime) {
		t.Error("FixedTime not set correctly")
	}
	if ts.IncludeNonce {
		t.Error("IncludeNonce should be false")
	}
	if !ts.Policy.Equal(customPolicy) {
		t.Error("Policy not set correctly")
	}

	// Create a timestamp and verify
	data := []byte("chained test data")
	token, err := ts.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	tstInfo, err := ExtractTSTInfo(token)
	if err != nil {
		t.Fatalf("ExtractTSTInfo failed: %v", err)
	}

	if !tstInfo.GenTime.Equal(fixedTime) {
		t.Errorf("GenTime mismatch: expected %v, got %v", fixedTime, tstInfo.GenTime)
	}
	if !tstInfo.Policy.Equal(customPolicy) {
		t.Errorf("Policy mismatch: expected %v, got %v", customPolicy, tstInfo.Policy)
	}
}

func TestDummyTimeStamperMultipleTimestamps(t *testing.T) {
	ts, err := CreateTestTimestamper()
	if err != nil {
		t.Fatalf("CreateTestTimestamper failed: %v", err)
	}

	// Create multiple timestamps and verify each has unique serial number
	data1 := []byte("data 1")
	data2 := []byte("data 2")
	data3 := []byte("data 3")

	token1, err := ts.Timestamp(data1)
	if err != nil {
		t.Fatalf("Timestamp 1 failed: %v", err)
	}

	token2, err := ts.Timestamp(data2)
	if err != nil {
		t.Fatalf("Timestamp 2 failed: %v", err)
	}

	token3, err := ts.Timestamp(data3)
	if err != nil {
		t.Fatalf("Timestamp 3 failed: %v", err)
	}

	// Verify each timestamp
	if err := VerifyTimestamp(token1, data1); err != nil {
		t.Errorf("token1 verification failed: %v", err)
	}
	if err := VerifyTimestamp(token2, data2); err != nil {
		t.Errorf("token2 verification failed: %v", err)
	}
	if err := VerifyTimestamp(token3, data3); err != nil {
		t.Errorf("token3 verification failed: %v", err)
	}

	// Verify serial numbers are different
	tstInfo1, _ := ExtractTSTInfo(token1)
	tstInfo2, _ := ExtractTSTInfo(token2)
	tstInfo3, _ := ExtractTSTInfo(token3)

	if tstInfo1.SerialNumber.Cmp(tstInfo2.SerialNumber) == 0 {
		t.Error("serial numbers should be unique")
	}
	if tstInfo2.SerialNumber.Cmp(tstInfo3.SerialNumber) == 0 {
		t.Error("serial numbers should be unique")
	}
}
