// Package certvalidator provides X.509 certificate path validation.
// This file contains tests that load and verify certificate fixtures.
package certvalidator

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadPEMCert loads a PEM-encoded certificate from file.
func loadPEMCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		// Try DER format
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			t.Fatalf("Failed to parse certificate %s: %v", path, err)
		}
		return cert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate %s: %v", path, err)
	}
	return cert
}

// loadDERCert loads a DER-encoded certificate from file.
func loadDERCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", path, err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatalf("Failed to parse certificate %s: %v", path, err)
	}
	return cert
}

// TestOpenSSL_OCSP_Fixtures tests loading OpenSSL OCSP test fixtures.
func TestOpenSSL_OCSP_Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "openssl-ocsp")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("Failed to read openssl-ocsp directory: %v", err)
	}

	var loaded, skipped int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(fixtureDir, name)

		if strings.HasSuffix(name, ".pem") {
			// Certificate file
			data, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("Failed to read %s: %v", name, err)
				continue
			}

			block, _ := pem.Decode(data)
			if block == nil {
				t.Errorf("Failed to decode PEM %s", name)
				continue
			}

			_, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("Failed to parse cert %s: %v", name, err)
				continue
			}
			loaded++
		} else if strings.HasSuffix(name, ".ors") {
			// OCSP response file - base64 encoded
			skipped++
		} else if strings.HasSuffix(name, ".der") {
			// DER encoded OCSP response
			skipped++
		}
	}

	t.Logf("Loaded %d certificates, %d OCSP responses skipped", loaded, skipped)
	if loaded < 20 {
		t.Errorf("Expected at least 20 certificates, got %d", loaded)
	}
}

// TestFreshness_Fixtures tests loading freshness test fixtures.
func TestFreshness_Fixtures(t *testing.T) {
	certsDir := filepath.Join("fixtures", "freshness", "certs")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("Failed to read freshness/certs directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}

		path := filepath.Join(certsDir, entry.Name())
		cert := loadDERCert(t, path)
		t.Logf("Loaded freshness cert: %s (CN=%s)", entry.Name(), cert.Subject.CommonName)
		loaded++
	}

	t.Logf("Loaded %d freshness certificates", loaded)
	if loaded < 3 {
		t.Errorf("Expected at least 3 freshness certificates, got %d", loaded)
	}
}

// TestFreshness_CRLs tests loading freshness CRL fixtures.
func TestFreshness_CRLs(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "freshness")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("Failed to read freshness directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crl") {
			continue
		}

		path := filepath.Join(fixtureDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read CRL %s: %v", entry.Name(), err)
			continue
		}

		crl, err := x509.ParseCRL(data)
		if err != nil {
			t.Errorf("Failed to parse CRL %s: %v", entry.Name(), err)
			continue
		}

		t.Logf("Loaded CRL: %s (issuer=%s)", entry.Name(), crl.TBSCertList.Issuer)
		loaded++
	}

	t.Logf("Loaded %d freshness CRLs", loaded)
	if loaded < 3 {
		t.Errorf("Expected at least 3 freshness CRLs, got %d", loaded)
	}
}

// TestTestingAIA_Fixtures tests loading AIA test fixtures.
func TestTestingAIA_Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "testing-aia")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("Failed to read testing-aia directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(fixtureDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", entry.Name(), err)
			continue
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		var cert *x509.Certificate
		if block != nil {
			cert, err = x509.ParseCertificate(block.Bytes)
		} else {
			// Try DER
			cert, err = x509.ParseCertificate(data)
		}

		if err != nil {
			t.Errorf("Failed to parse %s: %v", entry.Name(), err)
			continue
		}

		t.Logf("Loaded AIA cert: %s (CN=%s, AIA=%v)", entry.Name(), cert.Subject.CommonName, cert.IssuingCertificateURL)
		loaded++
	}

	t.Logf("Loaded %d AIA test certificates", loaded)
	if loaded < 10 {
		t.Errorf("Expected at least 10 AIA certificates, got %d", loaded)
	}
}

// TestTestingCA_Ed25519_Fixtures tests loading Ed25519 CA fixtures.
func TestTestingCA_Ed25519_Fixtures(t *testing.T) {
	certsDir := filepath.Join("fixtures", "testing-ca-ed25519")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("Failed to read testing-ca-ed25519 directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		path := filepath.Join(certsDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", name, err)
			continue
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		var cert *x509.Certificate
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
		} else {
			// Try DER
			cert, err = x509.ParseCertificate(data)
		}

		if err != nil {
			// Keys are expected to fail parsing as certs
			if strings.Contains(name, "key") {
				continue
			}
			t.Errorf("Failed to parse %s: %v", name, err)
			continue
		}

		t.Logf("Loaded Ed25519 cert: %s (CN=%s, SigAlg=%s)", name, cert.Subject.CommonName, cert.SignatureAlgorithm)
		loaded++
	}

	t.Logf("Loaded %d Ed25519 certificates", loaded)
}

// TestTestingCA_Ed448_Fixtures tests loading Ed448 CA fixtures.
func TestTestingCA_Ed448_Fixtures(t *testing.T) {
	certsDir := filepath.Join("fixtures", "testing-ca-ed448")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("Failed to read testing-ca-ed448 directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		path := filepath.Join(certsDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", name, err)
			continue
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		var cert *x509.Certificate
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
		} else {
			// Try DER
			cert, err = x509.ParseCertificate(data)
		}

		if err != nil {
			// Keys are expected to fail parsing as certs
			if strings.Contains(name, "key") {
				continue
			}
			t.Errorf("Failed to parse %s: %v", name, err)
			continue
		}

		t.Logf("Loaded Ed448 cert: %s (CN=%s, SigAlg=%s)", name, cert.Subject.CommonName, cert.SignatureAlgorithm)
		loaded++
	}

	t.Logf("Loaded %d Ed448 certificates", loaded)
}

// TestTestingCA_PSS_Fixtures tests loading RSASSA-PSS CA fixtures.
func TestTestingCA_PSS_Fixtures(t *testing.T) {
	certsDir := filepath.Join("fixtures", "testing-ca-pss")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("Failed to read testing-ca-pss directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		path := filepath.Join(certsDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", name, err)
			continue
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		var cert *x509.Certificate
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
		} else {
			// Try DER
			cert, err = x509.ParseCertificate(data)
		}

		if err != nil {
			// Keys are expected to fail parsing as certs
			if strings.Contains(name, "key") {
				continue
			}
			t.Errorf("Failed to parse %s: %v", name, err)
			continue
		}

		t.Logf("Loaded PSS cert: %s (CN=%s, SigAlg=%s)", name, cert.Subject.CommonName, cert.SignatureAlgorithm)
		loaded++
	}

	t.Logf("Loaded %d PSS certificates", loaded)
}

// TestDigiCert_Fixtures tests loading DigiCert certificate chain fixtures.
func TestDigiCert_Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("fixtures")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("Failed to read fixtures directory: %v", err)
	}

	var loaded, failed int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, "digicert") {
			continue
		}

		path := filepath.Join(fixtureDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", name, err)
			failed++
			continue
		}

		cert, err := x509.ParseCertificate(data)
		if err != nil {
			t.Logf("Cannot parse %s (may be incomplete chain file): %v", name, err)
			failed++
			continue
		}

		t.Logf("Loaded DigiCert cert: %s (CN=%s)", name, cert.Subject.CommonName)
		loaded++
	}

	t.Logf("Loaded %d DigiCert certificates, %d failed", loaded, failed)
	if loaded < 1 {
		t.Errorf("Expected at least 1 DigiCert certificate, got %d", loaded)
	}
}

// TestAttributeCerts_Fixtures tests loading attribute certificate fixtures.
func TestAttributeCerts_Fixtures(t *testing.T) {
	baseDir := filepath.Join("fixtures", "attribute-certs")

	// Check basic-aa subdirectory
	basicAADir := filepath.Join(baseDir, "basic-aa")
	entries, err := os.ReadDir(basicAADir)
	if err != nil {
		t.Fatalf("Failed to read basic-aa directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		path := filepath.Join(basicAADir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", name, err)
			continue
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		var cert *x509.Certificate
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err = x509.ParseCertificate(block.Bytes)
		} else if block == nil {
			// Try DER
			cert, err = x509.ParseCertificate(data)
		} else {
			// Skip non-certificate PEM blocks (like ATTRIBUTE CERTIFICATE)
			continue
		}

		if err != nil {
			// Some may be attribute certificates, not X.509 certs
			continue
		}

		t.Logf("Loaded AC fixture: %s (CN=%s)", name, cert.Subject.CommonName)
		loaded++
	}

	t.Logf("Loaded %d attribute certificate fixtures", loaded)
}

// TestCertsToUnpack_Fixtures tests loading PKCS#7 unpack fixtures.
func TestCertsToUnpack_Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "certs_to_unpack")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("Failed to read certs_to_unpack directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(fixtureDir, name)

		if strings.HasSuffix(name, ".p7b") {
			// PKCS#7 file - would need PKCS#7 parsing
			data, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("Failed to read %s: %v", name, err)
				continue
			}
			t.Logf("Found PKCS#7 file: %s (%d bytes)", name, len(data))
			loaded++
		}
	}

	t.Logf("Found %d PKCS#7 files", loaded)
}

// TestMiscCerts_Fixtures tests loading miscellaneous certificate fixtures.
func TestMiscCerts_Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("fixtures")

	miscCerts := []string{
		"mozilla.org.crt",
		"PostaSrbijeCA1.der",
		"PostaSrbijeCA1.pem",
		"self-signed-with-policy.crt",
	}

	for _, name := range miscCerts {
		path := filepath.Join(fixtureDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Logf("Skipping missing fixture: %s", name)
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Failed to read %s: %v", name, err)
			continue
		}

		// Try PEM first
		block, _ := pem.Decode(data)
		var cert *x509.Certificate
		if block != nil {
			cert, err = x509.ParseCertificate(block.Bytes)
		} else {
			cert, err = x509.ParseCertificate(data)
		}

		if err != nil {
			t.Errorf("Failed to parse %s: %v", name, err)
			continue
		}

		t.Logf("Loaded misc cert: %s (CN=%s, Issuer=%s)", name, cert.Subject.CommonName, cert.Issuer.CommonName)
	}
}

// TestADeS_TimeSlide_Fixtures tests loading AdES time-slide fixtures.
func TestADeS_TimeSlide_Fixtures(t *testing.T) {
	certsDir := filepath.Join("fixtures", "ades", "time-slide", "certs")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		t.Fatalf("Failed to read ades/time-slide/certs directory: %v", err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") {
			continue
		}

		path := filepath.Join(certsDir, name)
		cert := loadDERCert(t, path)
		t.Logf("Loaded ADeS time-slide cert: %s (CN=%s)", name, cert.Subject.CommonName)
		loaded++
	}

	t.Logf("Loaded %d ADeS time-slide certificates", loaded)
}

// TestMultitaskingOCSP_Fixtures tests loading multitasking OCSP fixtures.
func TestMultitaskingOCSP_Fixtures(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "multitasking-ocsp")
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatalf("Failed to read multitasking-ocsp directory: %v", err)
	}

	var certs, ocspResponses int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(fixtureDir, name)

		if strings.HasSuffix(name, ".crt") {
			cert := loadDERCert(t, path)
			t.Logf("Loaded multitasking-ocsp cert: %s (CN=%s)", name, cert.Subject.CommonName)
			certs++
		} else if strings.HasSuffix(name, ".der") {
			// OCSP response
			data, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("Failed to read OCSP response %s: %v", name, err)
				continue
			}
			t.Logf("Found OCSP response: %s (%d bytes)", name, len(data))
			ocspResponses++
		}
	}

	t.Logf("Loaded %d certificates, %d OCSP responses", certs, ocspResponses)
}

// TestFixtureCount provides a summary of all fixtures.
func TestFixtureCount(t *testing.T) {
	baseDir := filepath.Join("fixtures")

	var totalFiles int
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalFiles++
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk fixtures directory: %v", err)
	}

	t.Logf("Total fixture files: %d", totalFiles)
}
