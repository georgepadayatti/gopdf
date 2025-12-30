package signers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/sign/cms"
)

// Helper to generate test certificate and key
func generateTestCertAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, key
}

func TestNewSimpleSigner(t *testing.T) {
	cert, key := generateTestCertAndKey(t)

	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)
	if signer == nil {
		t.Fatal("NewSimpleSigner returned nil")
	}

	if signer.Certificate != cert {
		t.Error("Certificate mismatch")
	}

	if signer.PrivateKey != key {
		t.Error("PrivateKey mismatch")
	}
}

func TestSimpleSignerSign(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)

	data := []byte("Test data to sign")
	signature, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestSimpleSignerGetCertificate(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)

	if signer.GetCertificate() != cert {
		t.Error("GetCertificate returned wrong certificate")
	}
}

func TestSimpleSignerGetCertificateChain(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)

	// Initially empty
	chain := signer.GetCertificateChain()
	if len(chain) != 0 {
		t.Error("Chain should be empty initially")
	}

	// Set chain
	signer.SetCertificateChain([]*x509.Certificate{cert})
	chain = signer.GetCertificateChain()
	if len(chain) != 1 {
		t.Error("Chain should have 1 certificate")
	}
}

func TestSimpleSignerGetSignatureSize(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)

	size := signer.GetSignatureSize()
	if size < len(cert.Raw)+8192 {
		t.Error("Signature size seems too small")
	}
}

func TestSignatureMetadata(t *testing.T) {
	metadata := NewSignatureMetadata("Signature1")

	if metadata.FieldName != "Signature1" {
		t.Errorf("Expected FieldName 'Signature1', got '%s'", metadata.FieldName)
	}

	if metadata.SubFilter != "adbe.pkcs7.detached" {
		t.Errorf("Expected SubFilter 'adbe.pkcs7.detached', got '%s'", metadata.SubFilter)
	}

	// Set optional fields
	metadata.Reason = "Testing"
	metadata.Location = "Test Location"
	metadata.ContactInfo = "test@example.com"
	metadata.Name = "Test Name"

	if metadata.Reason != "Testing" {
		t.Error("Reason not set correctly")
	}
}

func TestNewPdfSigner(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)
	metadata := NewSignatureMetadata("Sig1")

	pdfSigner := NewPdfSigner(signer, metadata)
	if pdfSigner == nil {
		t.Fatal("NewPdfSigner returned nil")
	}

	if pdfSigner.Signer != signer {
		t.Error("Signer mismatch")
	}

	if pdfSigner.Metadata != metadata {
		t.Error("Metadata mismatch")
	}

	if pdfSigner.PageNumber != 0 {
		t.Error("Default page number should be 0")
	}
}

func TestPdfSignerSetSignatureAppearance(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	signer := NewSimpleSigner(cert, key, cms.SHA256WithRSA)
	metadata := NewSignatureMetadata("Sig1")
	pdfSigner := NewPdfSigner(signer, metadata)

	// Set appearance on page 1
	rect := &generic.Rectangle{LLX: 100, LLY: 100, URX: 200, URY: 150}
	pdfSigner.SetSignatureAppearance(1, rect)

	if pdfSigner.PageNumber != 1 {
		t.Errorf("Expected page 1, got %d", pdfSigner.PageNumber)
	}

	if pdfSigner.SignatureFieldBox != rect {
		t.Error("SignatureFieldBox not set correctly")
	}
}

func TestExternalSigner(t *testing.T) {
	cert, key := generateTestCertAndKey(t)

	// Create external signer with a signing function
	signFunc := func(digest []byte) ([]byte, error) {
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	}

	signer := NewExternalSigner(cert, signFunc, cms.SHA256WithRSA)
	if signer == nil {
		t.Fatal("NewExternalSigner returned nil")
	}

	if signer.GetCertificate() != cert {
		t.Error("GetCertificate returned wrong certificate")
	}

	size := signer.GetSignatureSize()
	if size == 0 {
		t.Error("GetSignatureSize should not return 0")
	}
}
