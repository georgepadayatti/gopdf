package w3c

import (
	"encoding/xml"
	"testing"
)

func TestNamespace(t *testing.T) {
	expected := "http://www.w3.org/2000/09/xmldsig#"
	if Namespace != expected {
		t.Errorf("Namespace = %q, want %q", Namespace, expected)
	}
}

func TestAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		// Canonicalization
		{"C14N", AlgC14N, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
		{"C14NWithComments", AlgC14NWithComments, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"},
		{"ExcC14N", AlgExcC14N, "http://www.w3.org/2001/10/xml-exc-c14n#"},

		// Digest
		{"SHA1", AlgSHA1, "http://www.w3.org/2000/09/xmldsig#sha1"},
		{"SHA256", AlgSHA256, "http://www.w3.org/2001/04/xmlenc#sha256"},
		{"SHA384", AlgSHA384, "http://www.w3.org/2001/04/xmldsig-more#sha384"},
		{"SHA512", AlgSHA512, "http://www.w3.org/2001/04/xmlenc#sha512"},

		// Signature
		{"RSAWithSHA256", AlgRSAWithSHA256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
		{"ECDSAWithSHA256", AlgECDSAWithSHA256, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"},

		// Transform
		{"EnvelopedSignature", AlgEnvelopedSignature, "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
		{"Base64", AlgBase64, "http://www.w3.org/2000/09/xmldsig#base64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.constant != tc.expected {
				t.Errorf("got %q, want %q", tc.constant, tc.expected)
			}
		})
	}
}

func TestNewSignature(t *testing.T) {
	sig := NewSignature()
	if sig == nil {
		t.Fatal("NewSignature() returned nil")
	}
	if sig.SignedInfo == nil {
		t.Error("SignedInfo should not be nil")
	}
	if sig.SignatureValue == nil {
		t.Error("SignatureValue should not be nil")
	}
}

func TestNewReference(t *testing.T) {
	ref := NewReference("#doc-id")
	if ref == nil {
		t.Fatal("NewReference() returned nil")
	}
	if ref.URI != "#doc-id" {
		t.Errorf("URI = %q, want %q", ref.URI, "#doc-id")
	}
	if ref.DigestMethod == nil {
		t.Error("DigestMethod should not be nil")
	}
	if ref.DigestValue == nil {
		t.Error("DigestValue should not be nil")
	}
}

func TestNewKeyInfo(t *testing.T) {
	ki := NewKeyInfo()
	if ki == nil {
		t.Fatal("NewKeyInfo() returned nil")
	}
}

func TestKeyInfoAddX509Certificate(t *testing.T) {
	ki := NewKeyInfo()
	cert1 := []byte("cert1")
	cert2 := []byte("cert2")

	ki.AddX509Certificate(cert1)
	if len(ki.X509Data) != 1 {
		t.Fatalf("expected 1 X509Data, got %d", len(ki.X509Data))
	}
	if len(ki.X509Data[0].X509Certificate) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(ki.X509Data[0].X509Certificate))
	}

	ki.AddX509Certificate(cert2)
	if len(ki.X509Data) != 1 {
		t.Errorf("expected 1 X509Data after second add, got %d", len(ki.X509Data))
	}
	if len(ki.X509Data[0].X509Certificate) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(ki.X509Data[0].X509Certificate))
	}
}

func TestKeyInfoSetRSAKeyValue(t *testing.T) {
	ki := NewKeyInfo()
	modulus := []byte{0x01, 0x02, 0x03}
	exponent := []byte{0x01, 0x00, 0x01}

	ki.SetRSAKeyValue(modulus, exponent)

	if len(ki.KeyValue) != 1 {
		t.Fatalf("expected 1 KeyValue, got %d", len(ki.KeyValue))
	}
	if ki.KeyValue[0].RSAKeyValue == nil {
		t.Fatal("RSAKeyValue should not be nil")
	}
	if string(ki.KeyValue[0].RSAKeyValue.Modulus) != string(modulus) {
		t.Error("Modulus mismatch")
	}
	if string(ki.KeyValue[0].RSAKeyValue.Exponent) != string(exponent) {
		t.Error("Exponent mismatch")
	}
}

func TestKeyInfoSetDSAKeyValue(t *testing.T) {
	ki := NewKeyInfo()
	p := []byte{0x01}
	q := []byte{0x02}
	g := []byte{0x03}
	y := []byte{0x04}

	ki.SetDSAKeyValue(p, q, g, y)

	if len(ki.KeyValue) != 1 {
		t.Fatalf("expected 1 KeyValue, got %d", len(ki.KeyValue))
	}
	if ki.KeyValue[0].DSAKeyValue == nil {
		t.Fatal("DSAKeyValue should not be nil")
	}
}

func TestSignatureMarshal(t *testing.T) {
	sig := NewSignature()
	sig.SignedInfo.CanonicalizationMethod = &CanonicalizationMethod{
		Algorithm: AlgExcC14N,
	}
	sig.SignedInfo.SignatureMethod = &SignatureMethod{
		Algorithm: AlgRSAWithSHA256,
	}

	ref := NewReference("#signed-data")
	ref.DigestMethod.Algorithm = AlgSHA256
	ref.DigestValue.Value = []byte("test-digest")
	sig.SignedInfo.Reference = append(sig.SignedInfo.Reference, *ref)

	sig.SignatureValue.Value = []byte("test-signature")

	data, err := xml.MarshalIndent(sig, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	// Verify we can unmarshal it back
	var parsed Signature
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.SignedInfo.CanonicalizationMethod.Algorithm != AlgExcC14N {
		t.Error("CanonicalizationMethod algorithm mismatch after roundtrip")
	}
	if parsed.SignedInfo.SignatureMethod.Algorithm != AlgRSAWithSHA256 {
		t.Error("SignatureMethod algorithm mismatch after roundtrip")
	}
	if len(parsed.SignedInfo.Reference) != 1 {
		t.Error("Reference count mismatch after roundtrip")
	}
}

func TestX509IssuerSerial(t *testing.T) {
	xis := X509IssuerSerial{
		X509IssuerName:   "CN=Test,O=Test Org",
		X509SerialNumber: 12345,
	}

	data, err := xml.Marshal(xis)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed X509IssuerSerial
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.X509IssuerName != xis.X509IssuerName {
		t.Error("X509IssuerName mismatch")
	}
	if parsed.X509SerialNumber != xis.X509SerialNumber {
		t.Error("X509SerialNumber mismatch")
	}
}

func TestTransform(t *testing.T) {
	tr := Transform{
		Algorithm: AlgEnvelopedSignature,
	}

	data, err := xml.Marshal(tr)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Transform
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Algorithm != AlgEnvelopedSignature {
		t.Error("Algorithm mismatch")
	}
}
