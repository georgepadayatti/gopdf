package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestAllowedMDAlgorithms(t *testing.T) {
	allowed := []string{"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512", "shake256"}
	notAllowed := []string{"md5", "sha1", "sha224"}

	for _, alg := range allowed {
		if !AllowedMDAlgorithms[alg] {
			t.Errorf("Algorithm %s should be allowed", alg)
		}
	}

	for _, alg := range notAllowed {
		if AllowedMDAlgorithms[alg] {
			t.Errorf("Algorithm %s should not be allowed", alg)
		}
	}
}

func TestDeriveMacKEK(t *testing.T) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	kek, err := DeriveMacKEK(fileKey, salt)
	if err != nil {
		t.Fatalf("DeriveMacKEK failed: %v", err)
	}

	if len(kek) != 32 {
		t.Errorf("KEK length = %d, want 32", len(kek))
	}

	// Same inputs should produce same output
	kek2, err := DeriveMacKEK(fileKey, salt)
	if err != nil {
		t.Fatalf("DeriveMacKEK failed: %v", err)
	}

	if !bytes.Equal(kek, kek2) {
		t.Error("Same inputs should produce same KEK")
	}

	// Different salt should produce different KEK
	salt2 := make([]byte, 32)
	rand.Read(salt2)
	kek3, _ := DeriveMacKEK(fileKey, salt2)
	if bytes.Equal(kek, kek3) {
		t.Error("Different salt should produce different KEK")
	}
}

func TestNewPdfMacTokenHandler(t *testing.T) {
	macKEK := make([]byte, 32)
	rand.Read(macKEK)

	handler := NewPdfMacTokenHandler(macKEK, "sha256")

	if handler == nil {
		t.Fatal("Handler is nil")
	}

	if handler.MDAlgorithm() != "sha256" {
		t.Errorf("MDAlgorithm = %q, want sha256", handler.MDAlgorithm())
	}
}

func TestNewPdfMacTokenHandlerFromKeyMaterial(t *testing.T) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	handler, err := NewPdfMacTokenHandlerFromKeyMaterial(fileKey, salt, "sha256")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	if handler == nil {
		t.Fatal("Handler is nil")
	}
}

func TestGetHashFunc(t *testing.T) {
	testCases := []struct {
		algorithm string
		wantSize  int
		wantErr   bool
	}{
		{"sha256", 32, false},
		{"sha384", 48, false},
		{"sha512", 64, false},
		{"sha3_256", 32, false},
		{"sha3_384", 48, false},
		{"sha3_512", 64, false},
		{"md5", 0, true},
		{"unknown", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			hashFunc, err := GetHashFunc(tc.algorithm)
			if tc.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			h := hashFunc()
			if h.Size() != tc.wantSize {
				t.Errorf("Hash size = %d, want %d", h.Size(), tc.wantSize)
			}
		})
	}
}

func TestPdfMacTokenHandler_ComputeMAC(t *testing.T) {
	macKEK := make([]byte, 32)
	rand.Read(macKEK)

	handler := NewPdfMacTokenHandler(macKEK, "sha256")

	macKey := make([]byte, 32)
	rand.Read(macKey)

	data := []byte("test data for MAC")

	mac := handler.ComputeMAC(macKey, data)

	// MAC should be 32 bytes (HMAC-SHA256)
	if len(mac) != 32 {
		t.Errorf("MAC length = %d, want 32", len(mac))
	}

	// Same inputs should produce same MAC
	mac2 := handler.ComputeMAC(macKey, data)
	if !bytes.Equal(mac, mac2) {
		t.Error("Same inputs should produce same MAC")
	}

	// Different data should produce different MAC
	mac3 := handler.ComputeMAC(macKey, []byte("different data"))
	if bytes.Equal(mac, mac3) {
		t.Error("Different data should produce different MAC")
	}
}

func TestPdfMacTokenHandler_DetermineTokenSize(t *testing.T) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	handler, _ := NewPdfMacTokenHandlerFromKeyMaterial(fileKey, salt, "sha256")

	size, err := handler.DetermineTokenSize(false)
	if err != nil {
		t.Fatalf("DetermineTokenSize failed: %v", err)
	}

	if size <= 0 {
		t.Error("Token size should be positive")
	}

	// With signature digest should be larger
	sizeWithSig, err := handler.DetermineTokenSize(true)
	if err != nil {
		t.Fatalf("DetermineTokenSize with sig failed: %v", err)
	}

	if sizeWithSig <= size {
		t.Error("Token with signature digest should be larger")
	}
}

func TestPdfMacTokenHandler_BuildPdfMacToken(t *testing.T) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	handler, _ := NewPdfMacTokenHandlerFromKeyMaterial(fileKey, salt, "sha256")

	// Create a document digest
	docDigest := sha256.Sum256([]byte("test document"))

	t.Run("WithoutSignatureDigest", func(t *testing.T) {
		token, err := handler.BuildPdfMacToken(docDigest[:], nil, false)
		if err != nil {
			t.Fatalf("BuildPdfMacToken failed: %v", err)
		}

		if len(token) == 0 {
			t.Error("Token should not be empty")
		}
	})

	t.Run("WithSignatureDigest", func(t *testing.T) {
		sigDigest := sha256.Sum256([]byte("signature"))
		token, err := handler.BuildPdfMacToken(docDigest[:], sigDigest[:], false)
		if err != nil {
			t.Fatalf("BuildPdfMacToken failed: %v", err)
		}

		if len(token) == 0 {
			t.Error("Token should not be empty")
		}
	})

	t.Run("DryRun", func(t *testing.T) {
		token, err := handler.BuildPdfMacToken(docDigest[:], nil, true)
		if err != nil {
			t.Fatalf("BuildPdfMacToken dry run failed: %v", err)
		}

		if len(token) == 0 {
			t.Error("Token should not be empty")
		}
	})
}

func TestPdfMacIntegrityInfo(t *testing.T) {
	info := PdfMacIntegrityInfo{
		Version:    0,
		DataDigest: []byte{1, 2, 3, 4},
	}

	data, err := asn1.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded PdfMacIntegrityInfo
	if _, err := asn1.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Version != 0 {
		t.Errorf("Version = %d, want 0", decoded.Version)
	}

	if !bytes.Equal(decoded.DataDigest, info.DataDigest) {
		t.Error("DataDigest mismatch")
	}
}

func TestPdfMacIntegrityInfoWithSignature(t *testing.T) {
	info := PdfMacIntegrityInfo{
		Version:         0,
		DataDigest:      []byte{1, 2, 3, 4},
		SignatureDigest: []byte{5, 6, 7, 8},
	}

	data, err := asn1.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded PdfMacIntegrityInfo
	if _, err := asn1.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !bytes.Equal(decoded.SignatureDigest, info.SignatureDigest) {
		t.Error("SignatureDigest mismatch")
	}
}

func TestMACLocation(t *testing.T) {
	if MACLocationStandalone != "/Standalone" {
		t.Errorf("MACLocationStandalone = %q, want /Standalone", MACLocationStandalone)
	}

	if MACLocationAttachedToSig != "/AttachedToSig" {
		t.Errorf("MACLocationAttachedToSig = %q, want /AttachedToSig", MACLocationAttachedToSig)
	}
}

func TestStandalonePdfMac(t *testing.T) {
	mac := NewStandalonePdfMac(1024)

	if mac == nil {
		t.Fatal("StandalonePdfMac is nil")
	}

	if mac.MACLocation != MACLocationStandalone {
		t.Errorf("MACLocation = %q, want /Standalone", mac.MACLocation)
	}

	if mac.BytesReserved != 1024 {
		t.Errorf("BytesReserved = %d, want 1024", mac.BytesReserved)
	}
}

func TestGetDigestOID(t *testing.T) {
	testCases := []struct {
		algorithm string
		expected  asn1.ObjectIdentifier
	}{
		{"sha256", OIDSHA256},
		{"sha384", OIDSHA384},
		{"sha512", OIDSHA512},
		{"sha3_256", OIDSHA3256},
		{"sha3_384", OIDSHA3384},
		{"sha3_512", OIDSHA3512},
		{"unknown", OIDSHA256}, // Default to SHA256
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			oid := getDigestOID(tc.algorithm)
			if !oid.Equal(tc.expected) {
				t.Errorf("getDigestOID(%q) = %v, want %v", tc.algorithm, oid, tc.expected)
			}
		})
	}
}

func TestISO32004OIDs(t *testing.T) {
	// Test that OIDs are correctly defined
	testCases := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{"PdfMacIntegrityInfo", OIDPdfMacIntegrityInfo, "1.0.32004.1.0"},
		{"PdfMacWrapKDF", OIDPdfMacWrapKDF, "1.0.32004.1.1"},
		{"PdfMacData", OIDPdfMacData, "1.0.32004.1.2"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.oid.String() != tc.expected {
				t.Errorf("OID = %s, want %s", tc.oid.String(), tc.expected)
			}
		})
	}
}

func TestValidatePdfMac_InvalidAlgorithm(t *testing.T) {
	err := ValidatePdfMac(nil, nil, nil, nil, nil, "md5")
	if err == nil {
		t.Error("Expected error for invalid algorithm")
	}

	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("Expected unsupported algorithm error, got: %v", err)
	}
}

func TestAddStandaloneMac(t *testing.T) {
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	docDigest := sha256.Sum256([]byte("test document"))

	token, err := AddStandaloneMac(fileKey, salt, docDigest[:], "sha256")
	if err != nil {
		t.Fatalf("AddStandaloneMac failed: %v", err)
	}

	if len(token) == 0 {
		t.Error("Token should not be empty")
	}
}

func TestComputeDocumentDigest(t *testing.T) {
	data := []byte("Hello, World! This is test data for digest computation.")
	reader := bytes.NewReader(data)

	byteRanges := [][2]int64{
		{0, 13}, // "Hello, World!"
		{14, 5}, // "This "
	}

	digest, err := ComputeDocumentDigest(reader, byteRanges, "sha256")
	if err != nil {
		t.Fatalf("ComputeDocumentDigest failed: %v", err)
	}

	if len(digest) != 32 {
		t.Errorf("Digest length = %d, want 32", len(digest))
	}

	// Compute expected digest
	expected := sha256.Sum256([]byte("Hello, World!This "))
	if !bytes.Equal(digest, expected[:]) {
		t.Error("Digest doesn't match expected value")
	}
}

func TestPdfMacErrors(t *testing.T) {
	// Test that error types are properly defined
	if ErrPdfMacValidation.Error() == "" {
		t.Error("ErrPdfMacValidation should have a message")
	}

	if ErrPdfMacInvalidMAC.Error() == "" {
		t.Error("ErrPdfMacInvalidMAC should have a message")
	}

	if ErrPdfMacMissingData.Error() == "" {
		t.Error("ErrPdfMacMissingData should have a message")
	}

	if ErrPdfMacInvalidDigest.Error() == "" {
		t.Error("ErrPdfMacInvalidDigest should have a message")
	}

	if ErrPdfMacUnsupportedAlg.Error() == "" {
		t.Error("ErrPdfMacUnsupportedAlg should have a message")
	}
}

func TestMustMarshal(t *testing.T) {
	// Test normal case
	data := mustMarshal(asn1.ObjectIdentifier{1, 2, 3})
	if len(data) == 0 {
		t.Error("mustMarshal should return non-empty data")
	}
}

func TestContentInfo(t *testing.T) {
	ci := ContentInfo{
		ContentType: OIDAuthenticatedData,
	}

	data, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	// Just verify it marshals without error and produces output
	if len(data) == 0 {
		t.Error("Marshalled ContentInfo should not be empty")
	}
}

func TestAlgorithmIdentifier(t *testing.T) {
	alg := AlgorithmIdentifier{
		Algorithm: OIDSHA256,
	}

	data, err := asn1.Marshal(alg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded AlgorithmIdentifier
	if _, err := asn1.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !decoded.Algorithm.Equal(OIDSHA256) {
		t.Error("Algorithm mismatch")
	}
}

func TestPasswordRecipientInfo(t *testing.T) {
	pwri := PasswordRecipientInfo{
		Version:      0,
		EncryptedKey: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		KeyDerivationAlgorithm: AlgorithmIdentifier{
			Algorithm: OIDPdfMacWrapKDF,
		},
		KeyEncryptionAlgorithm: AlgorithmIdentifier{
			Algorithm: OIDAes256Wrap,
		},
	}

	data, err := asn1.Marshal(pwri)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshalled data should not be empty")
	}
}

func TestCMSAttribute(t *testing.T) {
	attr := CMSAttribute{
		Type:  OIDContentType,
		Value: asn1.RawValue{FullBytes: []byte{0x06, 0x03, 0x01, 0x02, 0x03}},
	}

	data, err := asn1.Marshal(attr)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshalled data should not be empty")
	}
}

func TestCMSAlgorithmProtection(t *testing.T) {
	// CMSAlgorithmProtection uses pointer fields which need special handling
	// Just test the struct can be created
	prot := CMSAlgorithmProtection{
		DigestAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256},
	}

	if prot.DigestAlgorithm.Algorithm == nil {
		t.Error("DigestAlgorithm should be set")
	}
}

func TestEncapsulatedContentInfo(t *testing.T) {
	eci := EncapsulatedContentInfo{
		ContentType: OIDPdfMacIntegrityInfo,
		Content:     []byte{0x30, 0x00},
	}

	data, err := asn1.Marshal(eci)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshalled data should not be empty")
	}
}

func TestBuildAndValidateToken(t *testing.T) {
	// Create key material
	fileKey := make([]byte, 32)
	rand.Read(fileKey)

	salt := make([]byte, 32)
	rand.Read(salt)

	// Create handler
	handler, err := NewPdfMacTokenHandlerFromKeyMaterial(fileKey, salt, "sha256")
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Create document digest
	docDigest := sha256.Sum256([]byte("test document content"))

	// Build token
	token, err := handler.BuildPdfMacToken(docDigest[:], nil, false)
	if err != nil {
		t.Fatalf("Failed to build token: %v", err)
	}

	// Token should be non-empty and start with a SEQUENCE tag
	if len(token) == 0 {
		t.Error("Token should not be empty")
	}

	// Check it starts with ASN.1 SEQUENCE tag
	if token[0] != 0x30 {
		t.Errorf("Token should start with SEQUENCE tag (0x30), got 0x%02x", token[0])
	}
}
