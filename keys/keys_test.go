package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsPEM(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"PEM data", []byte("-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----"), true},
		{"DER data", []byte{0x30, 0x82, 0x01, 0x22}, false},
		{"Empty", []byte{}, false},
		{"Short data", []byte("----"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPEM(tt.data)
			if result != tt.expected {
				t.Errorf("isPEM() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLoadCertsFromPemDerData_PEM(t *testing.T) {
	// Generate a test certificate
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

	// Encode as PEM
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	certs, err := LoadCertsFromPemDerData(pemData)
	if err != nil {
		t.Fatalf("LoadCertsFromPemDerData failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(certs))
	}

	if certs[0].Subject.CommonName != "Test Cert" {
		t.Errorf("Expected CommonName 'Test Cert', got '%s'", certs[0].Subject.CommonName)
	}
}

func TestLoadCertsFromPemDerData_DER(t *testing.T) {
	// Generate a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "DER Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certs, err := LoadCertsFromPemDerData(certDER)
	if err != nil {
		t.Fatalf("LoadCertsFromPemDerData failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(certs))
	}

	if certs[0].Subject.CommonName != "DER Test Cert" {
		t.Errorf("Expected CommonName 'DER Test Cert', got '%s'", certs[0].Subject.CommonName)
	}
}

func TestLoadCertsFromPemDerData_MultipleCerts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	var pemData []byte
	for i := 0; i < 3; i++ {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				CommonName: "Cert " + string(rune('A'+i)),
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
		pemData = append(pemData, pemBlock...)
	}

	certs, err := LoadCertsFromPemDerData(pemData)
	if err != nil {
		t.Fatalf("LoadCertsFromPemDerData failed: %v", err)
	}

	if len(certs) != 3 {
		t.Errorf("Expected 3 certs, got %d", len(certs))
	}
}

func TestLoadCertsFromPemDerData_NoCert(t *testing.T) {
	// Empty data
	_, err := LoadCertsFromPemDerData([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func TestLoadCertsFromPemDer_File(t *testing.T) {
	// Generate a test certificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "File Test Cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Write to temp file
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test.crt")
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certFile, pemData, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	certs, err := LoadCertsFromPemDer(certFile)
	if err != nil {
		t.Fatalf("LoadCertsFromPemDer failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("Expected 1 cert, got %d", len(certs))
	}
}

func TestLoadCertFromPemDer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Single Cert Test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "single.crt")
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certFile, pemData, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	cert, err := LoadCertFromPemDer(certFile)
	if err != nil {
		t.Fatalf("LoadCertFromPemDer failed: %v", err)
	}

	if cert.Subject.CommonName != "Single Cert Test" {
		t.Errorf("Expected CommonName 'Single Cert Test', got '%s'", cert.Subject.CommonName)
	}
}

func TestLoadCertFromPemDer_MultipleCertsError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	var pemData []byte
	for i := 0; i < 2; i++ {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}

		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		pemData = append(pemData, pemBlock...)
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "multiple.crt")
	if err := os.WriteFile(certFile, pemData, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	_, err = LoadCertFromPemDer(certFile)
	if err == nil {
		t.Error("Expected error for multiple certs")
	}
}

func TestLoadPrivateKeyFromPemDerData_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// PKCS#1 format
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	loadedKey, err := LoadPrivateKeyFromPemDerData(pemData, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPemDerData failed: %v", err)
	}

	if _, ok := loadedKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestLoadPrivateKeyFromPemDerData_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal EC key: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	loadedKey, err := LoadPrivateKeyFromPemDerData(pemData, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPemDerData failed: %v", err)
	}

	if _, ok := loadedKey.(*ecdsa.PrivateKey); !ok {
		t.Error("Expected EC private key")
	}
}

func TestLoadPrivateKeyFromPemDerData_PKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS#8 key: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	loadedKey, err := LoadPrivateKeyFromPemDerData(pemData, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPemDerData failed: %v", err)
	}

	if _, ok := loadedKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestLoadPrivateKeyFromPemDerData_DER(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS#8 key: %v", err)
	}

	loadedKey, err := LoadPrivateKeyFromPemDerData(keyDER, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPemDerData failed: %v", err)
	}

	if _, ok := loadedKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestLoadPrivateKeyFromPemDer_File(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, pemData, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	loadedKey, err := LoadPrivateKeyFromPemDer(keyFile, nil)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPemDer failed: %v", err)
	}

	if _, ok := loadedKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestGetKeyInfo_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	info := GetKeyInfo(key)
	if info.Algorithm != "RSA" {
		t.Errorf("Expected Algorithm 'RSA', got '%s'", info.Algorithm)
	}
	if info.BitSize != 2048 {
		t.Errorf("Expected BitSize 2048, got %d", info.BitSize)
	}
}

func TestGetKeyInfo_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate EC key: %v", err)
	}

	info := GetKeyInfo(key)
	if info.Algorithm != "ECDSA" {
		t.Errorf("Expected Algorithm 'ECDSA', got '%s'", info.Algorithm)
	}
	if info.Curve != "P-256" {
		t.Errorf("Expected Curve 'P-256', got '%s'", info.Curve)
	}
}

func TestGetKeyInfo_Ed25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	info := GetKeyInfo(key)
	if info.Algorithm != "Ed25519" {
		t.Errorf("Expected Algorithm 'Ed25519', got '%s'", info.Algorithm)
	}
}

func TestIsSelfSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Self Signed",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, _ := x509.ParseCertificate(certDER)
	if !isSelfSigned(cert) {
		t.Error("Expected certificate to be self-signed")
	}
}

func TestLoadCertificateChain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create root cert
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	rootCert, _ := x509.ParseCertificate(rootDER)

	// Create leaf cert
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &key.PublicKey, key)

	tmpDir := t.TempDir()

	// Write leaf cert
	leafFile := filepath.Join(tmpDir, "leaf.crt")
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	os.WriteFile(leafFile, leafPEM, 0644)

	// Write root cert
	rootFile := filepath.Join(tmpDir, "root.crt")
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	os.WriteFile(rootFile, rootPEM, 0644)

	chain, err := LoadCertificateChain([]string{leafFile, rootFile})
	if err != nil {
		t.Fatalf("LoadCertificateChain failed: %v", err)
	}

	if chain.EndEntity.Subject.CommonName != "Leaf Cert" {
		t.Error("Expected end entity to be leaf cert")
	}

	if chain.Root == nil || chain.Root.Subject.CommonName != "Root CA" {
		t.Error("Expected root cert")
	}
}

func TestLoadCertAndKeyFromPemDer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	tmpDir := t.TempDir()

	certFile := filepath.Join(tmpDir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	os.WriteFile(certFile, certPEM, 0644)

	keyFile := filepath.Join(tmpDir, "key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	os.WriteFile(keyFile, keyPEM, 0600)

	cert, loadedKey, err := LoadCertAndKeyFromPemDer(certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("LoadCertAndKeyFromPemDer failed: %v", err)
	}

	if cert.Subject.CommonName != "Test Cert" {
		t.Error("Certificate not loaded correctly")
	}

	if _, ok := loadedKey.(*rsa.PrivateKey); !ok {
		t.Error("Expected RSA private key")
	}
}

func TestLoadCertsFromPemDerFiles(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tmpDir := t.TempDir()
	var files []string

	for i := 0; i < 3; i++ {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "Cert " + string(rune('A'+i))},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}

		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		filename := filepath.Join(tmpDir, "cert"+string(rune('A'+i))+".pem")
		pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		os.WriteFile(filename, pemData, 0644)
		files = append(files, filename)
	}

	certs, err := LoadCertsFromPemDerFiles(files)
	if err != nil {
		t.Fatalf("LoadCertsFromPemDerFiles failed: %v", err)
	}

	if len(certs) != 3 {
		t.Errorf("Expected 3 certs, got %d", len(certs))
	}
}

func TestLoadPrivateKeyFromPemDerData_InvalidPEM(t *testing.T) {
	_, err := LoadPrivateKeyFromPemDerData([]byte("not a valid key"), nil)
	if err == nil {
		t.Error("Expected error for invalid key data")
	}
}

func TestLoadCertsFromPemDer_FileNotFound(t *testing.T) {
	_, err := LoadCertsFromPemDer("/nonexistent/file.pem")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestLoadPrivateKeyFromPemDer_FileNotFound(t *testing.T) {
	_, err := LoadPrivateKeyFromPemDer("/nonexistent/file.pem", nil)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestToPrivateKey_Unknown(t *testing.T) {
	_, err := toPrivateKey("not a key")
	if err == nil {
		t.Error("Expected error for unknown key type")
	}
}

func TestLoadCertificateChain_Empty(t *testing.T) {
	_, err := LoadCertificateChain([]string{})
	if err == nil {
		t.Error("Expected error for empty file list")
	}
}
