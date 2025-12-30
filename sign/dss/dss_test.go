package dss

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Cert",
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
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

func TestNewDSS(t *testing.T) {
	dss := NewDSS()

	if dss == nil {
		t.Fatal("NewDSS returned nil")
	}
	if len(dss.Certs) != 0 {
		t.Error("Certs should be empty")
	}
	if len(dss.OCSPs) != 0 {
		t.Error("OCSPs should be empty")
	}
	if len(dss.CRLs) != 0 {
		t.Error("CRLs should be empty")
	}
	if len(dss.VRI) != 0 {
		t.Error("VRI should be empty")
	}
}

func TestDSSAddCertificate(t *testing.T) {
	dss := NewDSS()
	cert := generateTestCert(t)

	dss.AddCertificate(cert)
	if len(dss.Certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(dss.Certs))
	}

	// Adding same cert again should not duplicate
	dss.AddCertificate(cert)
	if len(dss.Certs) != 1 {
		t.Errorf("Duplicate cert should not be added, got %d", len(dss.Certs))
	}
}

func TestDSSAddCertificates(t *testing.T) {
	dss := NewDSS()
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	dss.AddCertificates([]*x509.Certificate{cert1, cert2})
	if len(dss.Certs) != 2 {
		t.Errorf("Expected 2 certs, got %d", len(dss.Certs))
	}
}

func TestDSSAddOCSPResponse(t *testing.T) {
	dss := NewDSS()
	ocsp := []byte("test ocsp response")

	dss.AddOCSPResponse(ocsp)
	if len(dss.OCSPs) != 1 {
		t.Errorf("Expected 1 OCSP, got %d", len(dss.OCSPs))
	}

	// Adding same OCSP again should not duplicate
	dss.AddOCSPResponse(ocsp)
	if len(dss.OCSPs) != 1 {
		t.Errorf("Duplicate OCSP should not be added, got %d", len(dss.OCSPs))
	}
}

func TestDSSAddCRL(t *testing.T) {
	dss := NewDSS()
	crl := []byte("test crl")

	dss.AddCRL(crl)
	if len(dss.CRLs) != 1 {
		t.Errorf("Expected 1 CRL, got %d", len(dss.CRLs))
	}

	// Adding same CRL again should not duplicate
	dss.AddCRL(crl)
	if len(dss.CRLs) != 1 {
		t.Errorf("Duplicate CRL should not be added, got %d", len(dss.CRLs))
	}
}

func TestDSSGetVRI(t *testing.T) {
	dss := NewDSS()

	vri := dss.GetVRI("abc123")
	if vri == nil {
		t.Fatal("GetVRI returned nil")
	}
	if vri.SignatureHash != "abc123" {
		t.Errorf("Expected hash 'abc123', got '%s'", vri.SignatureHash)
	}

	// Getting same VRI should return same instance
	vri2 := dss.GetVRI("abc123")
	if vri2 != vri {
		t.Error("GetVRI should return same instance for same hash")
	}

	if len(dss.VRI) != 1 {
		t.Errorf("Expected 1 VRI entry, got %d", len(dss.VRI))
	}
}

func TestDSSAddVRICert(t *testing.T) {
	dss := NewDSS()
	cert := generateTestCert(t)

	dss.AddVRICert("sig123", cert)

	// Should be added to VRI
	vri := dss.VRI["sig123"]
	if vri == nil {
		t.Fatal("VRI entry should exist")
	}
	if len(vri.Certs) != 1 {
		t.Errorf("Expected 1 cert in VRI, got %d", len(vri.Certs))
	}

	// Should also be added to main certs
	if len(dss.Certs) != 1 {
		t.Errorf("Expected 1 cert in DSS, got %d", len(dss.Certs))
	}
}

func TestDSSAddVRIOCSP(t *testing.T) {
	dss := NewDSS()
	ocsp := []byte("test ocsp")

	dss.AddVRIOCSP("sig123", ocsp)

	vri := dss.VRI["sig123"]
	if len(vri.OCSPs) != 1 {
		t.Errorf("Expected 1 OCSP in VRI, got %d", len(vri.OCSPs))
	}
	if len(dss.OCSPs) != 1 {
		t.Errorf("Expected 1 OCSP in DSS, got %d", len(dss.OCSPs))
	}
}

func TestDSSAddVRICRL(t *testing.T) {
	dss := NewDSS()
	crl := []byte("test crl")

	dss.AddVRICRL("sig123", crl)

	vri := dss.VRI["sig123"]
	if len(vri.CRLs) != 1 {
		t.Errorf("Expected 1 CRL in VRI, got %d", len(vri.CRLs))
	}
	if len(dss.CRLs) != 1 {
		t.Errorf("Expected 1 CRL in DSS, got %d", len(dss.CRLs))
	}
}

func TestComputeSignatureHash(t *testing.T) {
	sig := []byte("test signature")
	hash := ComputeSignatureHash(sig)

	if hash == "" {
		t.Error("Hash should not be empty")
	}
	if len(hash) != 64 { // SHA256 hex = 64 chars
		t.Errorf("Expected 64 char hash, got %d", len(hash))
	}

	// Same signature should produce same hash
	hash2 := ComputeSignatureHash(sig)
	if hash != hash2 {
		t.Error("Same signature should produce same hash")
	}
}

func TestDSSToPdfObject(t *testing.T) {
	dss := NewDSS()
	cert := generateTestCert(t)
	dss.AddCertificate(cert)
	dss.AddOCSPResponse([]byte("ocsp"))
	dss.AddCRL([]byte("crl"))

	dict := dss.ToPdfObject()

	if dict.Get("Type") == nil {
		t.Error("Should have Type")
	}
	if dict.Get("Certs") == nil {
		t.Error("Should have Certs")
	}
	if dict.Get("OCSPs") == nil {
		t.Error("Should have OCSPs")
	}
	if dict.Get("CRLs") == nil {
		t.Error("Should have CRLs")
	}
}

func TestDSSToPdfObjectWithVRI(t *testing.T) {
	dss := NewDSS()
	dss.AddVRICert("sig123", generateTestCert(t))

	dict := dss.ToPdfObject()

	if dict.Get("VRI") == nil {
		t.Error("Should have VRI")
	}
}

func TestVRIEntryToPdfObject(t *testing.T) {
	vri := &VRIEntry{
		SignatureHash: "hash123",
		Certs:         []*x509.Certificate{},
		OCSPs:         [][]byte{[]byte("ocsp")},
		CRLs:          [][]byte{[]byte("crl")},
	}

	dict := vri.ToPdfObject()

	if dict.Get("OCSP") == nil {
		t.Error("Should have OCSP")
	}
	if dict.Get("CRL") == nil {
		t.Error("Should have CRL")
	}
}

func TestVRIEntryWithTimestamp(t *testing.T) {
	now := time.Now()
	vri := &VRIEntry{
		SignatureHash: "hash123",
		Timestamp:     &now,
	}

	dict := vri.ToPdfObject()

	if dict.Get("TU") == nil {
		t.Error("Should have TU (timestamp)")
	}
}

func TestDSSFindCertBySubject(t *testing.T) {
	dss := NewDSS()
	cert := generateTestCert(t)
	dss.AddCertificate(cert)

	// Find by CommonName
	found := dss.FindCertBySubject("Test Cert")
	if found == nil {
		t.Error("Should find cert by CommonName")
	}

	// Not found
	found = dss.FindCertBySubject("NonExistent")
	if found != nil {
		t.Error("Should not find non-existent cert")
	}
}

func TestDSSMerge(t *testing.T) {
	dss1 := NewDSS()
	dss1.AddCertificate(generateTestCert(t))
	dss1.AddOCSPResponse([]byte("ocsp1"))

	dss2 := NewDSS()
	dss2.AddCertificate(generateTestCert(t))
	dss2.AddCRL([]byte("crl1"))

	dss1.Merge(dss2)

	if len(dss1.Certs) != 2 {
		t.Errorf("Expected 2 certs after merge, got %d", len(dss1.Certs))
	}
	if len(dss1.OCSPs) != 1 {
		t.Error("Should still have 1 OCSP")
	}
	if len(dss1.CRLs) != 1 {
		t.Error("Should have 1 CRL from merge")
	}
}

func TestDSSIsEmpty(t *testing.T) {
	dss := NewDSS()
	if !dss.IsEmpty() {
		t.Error("New DSS should be empty")
	}

	dss.AddCertificate(generateTestCert(t))
	if dss.IsEmpty() {
		t.Error("DSS with cert should not be empty")
	}
}

func TestDSSSummary(t *testing.T) {
	dss := NewDSS()
	summary := dss.Summary()
	if summary == "" {
		t.Error("Summary should not be empty")
	}
	if !containsString(summary, "0 certs") {
		t.Error("Summary should mention 0 certs")
	}

	dss.AddCertificate(generateTestCert(t))
	summary = dss.Summary()
	if !containsString(summary, "1 certs") {
		t.Error("Summary should mention 1 certs")
	}
}

func TestBytesEqual(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	c := []byte{1, 2, 4}
	d := []byte{1, 2}

	if !bytesEqual(a, b) {
		t.Error("a and b should be equal")
	}
	if bytesEqual(a, c) {
		t.Error("a and c should not be equal")
	}
	if bytesEqual(a, d) {
		t.Error("a and d should not be equal (different length)")
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
