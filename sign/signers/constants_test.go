package signers

import (
	"crypto/x509"
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/extensions"
	"github.com/georgepadayatti/gopdf/sign/fields"
)

func TestDefaultConstants(t *testing.T) {
	// Test DefaultMD
	if DefaultMD != "sha256" {
		t.Errorf("DefaultMD = %q, want %q", DefaultMD, "sha256")
	}

	// Test DefaultSigSubFilter
	if DefaultSigSubFilter != fields.SubFilterAdobePKCS7Detached {
		t.Errorf("DefaultSigSubFilter = %q, want %q", DefaultSigSubFilter, fields.SubFilterAdobePKCS7Detached)
	}

	// Test SigDetailsDefaultTemplate
	expected := "Digitally signed by %(signer)s.\nTimestamp: %(ts)s."
	if SigDetailsDefaultTemplate != expected {
		t.Errorf("SigDetailsDefaultTemplate = %q, want %q", SigDetailsDefaultTemplate, expected)
	}
}

func TestDefaultSignerKeyUsage(t *testing.T) {
	// Check that non_repudiation (ContentCommitment) is set
	if !DefaultSignerKeyUsage[x509.KeyUsageContentCommitment] {
		t.Error("DefaultSignerKeyUsage should have KeyUsageContentCommitment set")
	}

	// Check the string set
	if !DefaultSignerKeyUsageSet["non_repudiation"] {
		t.Error("DefaultSignerKeyUsageSet should have 'non_repudiation' set")
	}
}

func TestESIC_EXTENSION_1(t *testing.T) {
	ext := ESIC_EXTENSION_1

	if ext.PrefixName != "/ESIC" {
		t.Errorf("ESIC_EXTENSION_1.PrefixName = %q, want %q", ext.PrefixName, "/ESIC")
	}
	if ext.BaseVersion != "/1.7" {
		t.Errorf("ESIC_EXTENSION_1.BaseVersion = %q, want %q", ext.BaseVersion, "/1.7")
	}
	if ext.ExtensionLevel != 1 {
		t.Errorf("ESIC_EXTENSION_1.ExtensionLevel = %d, want %d", ext.ExtensionLevel, 1)
	}
	if !ext.CompareByLevel {
		t.Error("ESIC_EXTENSION_1.CompareByLevel should be true")
	}
	if ext.Multivalued != extensions.ExtensionNever {
		t.Errorf("ESIC_EXTENSION_1.Multivalued = %v, want %v", ext.Multivalued, extensions.ExtensionNever)
	}
}

func TestISO32001(t *testing.T) {
	ext := ISO32001

	if ext.PrefixName != "/ISO_" {
		t.Errorf("ISO32001.PrefixName = %q, want %q", ext.PrefixName, "/ISO_")
	}
	if ext.BaseVersion != "/2.0" {
		t.Errorf("ISO32001.BaseVersion = %q, want %q", ext.BaseVersion, "/2.0")
	}
	if ext.ExtensionLevel != 32001 {
		t.Errorf("ISO32001.ExtensionLevel = %d, want %d", ext.ExtensionLevel, 32001)
	}
	if ext.ExtensionRevision != ":2022" {
		t.Errorf("ISO32001.ExtensionRevision = %q, want %q", ext.ExtensionRevision, ":2022")
	}
	if ext.URL != "https://www.iso.org/standard/45874.html" {
		t.Errorf("ISO32001.URL = %q, want %q", ext.URL, "https://www.iso.org/standard/45874.html")
	}
	if ext.CompareByLevel {
		t.Error("ISO32001.CompareByLevel should be false")
	}
	if ext.Multivalued != extensions.ExtensionAlways {
		t.Errorf("ISO32001.Multivalued = %v, want %v", ext.Multivalued, extensions.ExtensionAlways)
	}
}

func TestISO32002(t *testing.T) {
	ext := ISO32002

	if ext.PrefixName != "/ISO_" {
		t.Errorf("ISO32002.PrefixName = %q, want %q", ext.PrefixName, "/ISO_")
	}
	if ext.BaseVersion != "/2.0" {
		t.Errorf("ISO32002.BaseVersion = %q, want %q", ext.BaseVersion, "/2.0")
	}
	if ext.ExtensionLevel != 32002 {
		t.Errorf("ISO32002.ExtensionLevel = %d, want %d", ext.ExtensionLevel, 32002)
	}
	if ext.ExtensionRevision != ":2022" {
		t.Errorf("ISO32002.ExtensionRevision = %q, want %q", ext.ExtensionRevision, ":2022")
	}
	if ext.URL != "https://www.iso.org/standard/45875.html" {
		t.Errorf("ISO32002.URL = %q, want %q", ext.URL, "https://www.iso.org/standard/45875.html")
	}
	if ext.CompareByLevel {
		t.Error("ISO32002.CompareByLevel should be false")
	}
	if ext.Multivalued != extensions.ExtensionAlways {
		t.Errorf("ISO32002.Multivalued = %v, want %v", ext.Multivalued, extensions.ExtensionAlways)
	}
}

func TestISO32002CurveNames(t *testing.T) {
	expectedCurves := []string{"P-256", "P-384", "P-521", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"}

	for _, curve := range expectedCurves {
		if !ISO32002CurveNames[curve] {
			t.Errorf("ISO32002CurveNames should contain %q", curve)
		}
	}

	// Make sure unexpected curves are not present
	unexpectedCurves := []string{"secp256k1", "curve25519"}
	for _, curve := range unexpectedCurves {
		if ISO32002CurveNames[curve] {
			t.Errorf("ISO32002CurveNames should not contain %q", curve)
		}
	}
}

func TestCurveNameMappings(t *testing.T) {
	testCases := []struct {
		asn1Name string
		goName   string
	}{
		{"secp256r1", "P-256"},
		{"secp384r1", "P-384"},
		{"secp521r1", "P-521"},
		{"brainpoolp256r1", "brainpoolP256r1"},
		{"brainpoolp384r1", "brainpoolP384r1"},
		{"brainpoolp512r1", "brainpoolP512r1"},
	}

	for _, tc := range testCases {
		if got := CurveNameMappings[tc.asn1Name]; got != tc.goName {
			t.Errorf("CurveNameMappings[%q] = %q, want %q", tc.asn1Name, got, tc.goName)
		}
	}
}

func TestRequiresISO32001(t *testing.T) {
	testCases := []struct {
		digestAlg string
		expected  bool
	}{
		{"sha256", false},
		{"sha384", false},
		{"sha512", false},
		{"sha1", false},
		{"sha3-256", true},
		{"sha3-384", true},
		{"sha3-512", true},
		{"shake256", true},
	}

	for _, tc := range testCases {
		if got := RequiresISO32001(tc.digestAlg); got != tc.expected {
			t.Errorf("RequiresISO32001(%q) = %v, want %v", tc.digestAlg, got, tc.expected)
		}
	}
}

func TestRequiresISO32002ForCurve(t *testing.T) {
	testCases := []struct {
		curveName string
		expected  bool
	}{
		// Go crypto names
		{"P-256", true},
		{"P-384", true},
		{"P-521", true},
		{"brainpoolP256r1", true},
		{"brainpoolP384r1", true},
		{"brainpoolP512r1", true},
		// asn1crypto names
		{"secp256r1", true},
		{"secp384r1", true},
		{"secp521r1", true},
		{"brainpoolp256r1", true},
		{"brainpoolp384r1", true},
		{"brainpoolp512r1", true},
		// Not included
		{"secp256k1", false},
		{"curve25519", false},
		{"unknown", false},
	}

	for _, tc := range testCases {
		if got := RequiresISO32002ForCurve(tc.curveName); got != tc.expected {
			t.Errorf("RequiresISO32002ForCurve(%q) = %v, want %v", tc.curveName, got, tc.expected)
		}
	}
}

func TestDigestConstants(t *testing.T) {
	if DigestSHA1 != "sha1" {
		t.Errorf("DigestSHA1 = %q, want %q", DigestSHA1, "sha1")
	}
	if DigestSHA256 != "sha256" {
		t.Errorf("DigestSHA256 = %q, want %q", DigestSHA256, "sha256")
	}
	if DigestSHA384 != "sha384" {
		t.Errorf("DigestSHA384 = %q, want %q", DigestSHA384, "sha384")
	}
	if DigestSHA512 != "sha512" {
		t.Errorf("DigestSHA512 = %q, want %q", DigestSHA512, "sha512")
	}
}
