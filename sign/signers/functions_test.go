package signers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/embed"
	"github.com/georgepadayatti/gopdf/sign/cms"
)

func TestSigningError(t *testing.T) {
	t.Run("ErrorWithCause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := NewSigningError("signing failed", cause)

		if err.Error() != "signing failed: underlying error" {
			t.Errorf("Error() = %q, want %q", err.Error(), "signing failed: underlying error")
		}

		if !errors.Is(err, cause) {
			t.Error("Unwrap() should return the cause")
		}
	})

	t.Run("ErrorWithoutCause", func(t *testing.T) {
		err := NewSigningError("signing failed", nil)

		if err.Error() != "signing failed" {
			t.Errorf("Error() = %q, want %q", err.Error(), "signing failed")
		}
	})
}

func TestDefaultSignPdfOptions(t *testing.T) {
	opts := DefaultSignPdfOptions()

	if opts.ExistingFieldsOnly {
		t.Error("ExistingFieldsOnly should be false by default")
	}

	if opts.BytesReserved != 0 {
		t.Errorf("BytesReserved = %d, want 0", opts.BytesReserved)
	}

	if opts.InPlace {
		t.Error("InPlace should be false by default")
	}

	if opts.Timestamper != nil {
		t.Error("Timestamper should be nil by default")
	}

	if opts.Output != nil {
		t.Error("Output should be nil by default")
	}
}

func TestSignPdfValidation(t *testing.T) {
	// Create a test signer
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createTestCertificate(t, privateKey)
	signer := NewSimpleSigner(cert, privateKey, cms.SHA256WithRSA)
	metadata := NewSignatureMetadata("Signature1")

	// Use SignPdfFromReader to test validation since SignPdfBytes parses first
	t.Run("NilSigner", func(t *testing.T) {
		_, err := SignPdfFromReader(nil, metadata, nil, nil)
		if err != ErrSignerRequired {
			t.Errorf("Expected ErrSignerRequired, got %v", err)
		}
	})

	t.Run("NilMetadata", func(t *testing.T) {
		_, err := SignPdfFromReader(nil, nil, signer, nil)
		if err != ErrMetadataRequired {
			t.Errorf("Expected ErrMetadataRequired, got %v", err)
		}
	})

	t.Run("NilReader", func(t *testing.T) {
		_, err := SignPdfFromReader(nil, metadata, signer, nil)
		if err == nil {
			t.Error("Expected error for nil reader")
		}
	})
}

func TestQuickSign(t *testing.T) {
	// Create test signer
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := createTestCertificate(t, privateKey)
	signer := NewSimpleSigner(cert, privateKey, cms.SHA256WithRSA)

	t.Run("NewQuickSign", func(t *testing.T) {
		qs := NewQuickSign(signer, "Signature1")

		if qs.Signer != signer {
			t.Error("Signer not set correctly")
		}
		if qs.Metadata.FieldName != "Signature1" {
			t.Errorf("FieldName = %q, want %q", qs.Metadata.FieldName, "Signature1")
		}
	})

	t.Run("WithReason", func(t *testing.T) {
		qs := NewQuickSign(signer, "Sig1").WithReason("Test reason")
		if qs.Metadata.Reason != "Test reason" {
			t.Errorf("Reason = %q, want %q", qs.Metadata.Reason, "Test reason")
		}
	})

	t.Run("WithLocation", func(t *testing.T) {
		qs := NewQuickSign(signer, "Sig1").WithLocation("Test location")
		if qs.Metadata.Location != "Test location" {
			t.Errorf("Location = %q, want %q", qs.Metadata.Location, "Test location")
		}
	})

	t.Run("ChainedMethods", func(t *testing.T) {
		qs := NewQuickSign(signer, "Sig1").
			WithReason("My reason").
			WithLocation("My location")

		if qs.Metadata.Reason != "My reason" {
			t.Errorf("Reason = %q, want %q", qs.Metadata.Reason, "My reason")
		}
		if qs.Metadata.Location != "My location" {
			t.Errorf("Location = %q, want %q", qs.Metadata.Location, "My location")
		}
	})
}

func TestReplaceExtension(t *testing.T) {
	testCases := []struct {
		path     string
		newExt   string
		expected string
	}{
		{"document.pdf", ".sig", "document.sig"},
		{"path/to/file.txt", ".p7s", "path/to/file.p7s"},
		{"file", ".sig", "file.sig"},
		{"file.tar.gz", ".sig", "file.tar.sig"},
		{"path/to/file", ".sig", "path/to/file.sig"},
	}

	for _, tc := range testCases {
		result := replaceExtension(tc.path, tc.newExt)
		if result != tc.expected {
			t.Errorf("replaceExtension(%q, %q) = %q, want %q", tc.path, tc.newExt, result, tc.expected)
		}
	}
}

func TestDefaultEmbedPayloadWithCMSOptions(t *testing.T) {
	opts := DefaultEmbedPayloadWithCMSOptions()

	if opts.Extension != ".sig" {
		t.Errorf("Extension = %q, want %q", opts.Extension, ".sig")
	}

	if opts.FileName != "" {
		t.Error("FileName should be empty by default")
	}

	if opts.AFRelationship != "" {
		t.Error("AFRelationship should be empty by default")
	}
}

func TestEmbedPayloadWithCMSValidation(t *testing.T) {
	t.Run("NilWriter", func(t *testing.T) {
		payload := embed.NewEmbeddedFileFromData([]byte("test"), false, nil, "")
		err := EmbedPayloadWithCMS(nil, "test.pdf", payload, []byte("cms"), nil)
		if err == nil || err.Error() != "PDF writer is required" {
			t.Errorf("Expected 'PDF writer is required' error, got %v", err)
		}
	})

	t.Run("NilPayload", func(t *testing.T) {
		// Would need a real writer to test this
	})

	t.Run("EmptyCMSData", func(t *testing.T) {
		// Would need a real writer to test this
	})
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
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

	return cert
}
