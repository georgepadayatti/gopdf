// Package signers provides constants and defaults used when creating digital signatures.
package signers

import (
	"crypto/x509"

	"github.com/georgepadayatti/gopdf/pdf/extensions"
	"github.com/georgepadayatti/gopdf/sign/fields"
)

// DefaultMD is the default message digest algorithm used when computing digests
// for use in signatures.
// Note: Some TSAs produce invalid timestamps when presented with SHA-512 requests.
// SHA-256 is used as a safe default.
const DefaultMD = "sha256"

// DefaultSigSubFilter is the default SubFilter to use for PDF signatures.
var DefaultSigSubFilter = fields.SubFilterAdobePKCS7Detached

// SigDetailsDefaultTemplate is the default template string for signature appearances.
const SigDetailsDefaultTemplate = "Digitally signed by %(signer)s.\nTimestamp: %(ts)s."

// DefaultSignerKeyUsage is the default key usage bits required for the signer's certificate.
// Maps to x509.KeyUsage values.
var DefaultSignerKeyUsage = map[x509.KeyUsage]bool{
	x509.KeyUsageContentCommitment: true, // non_repudiation
}

// DefaultSignerKeyUsageSet provides a set of key usage names for compatibility.
var DefaultSignerKeyUsageSet = map[string]bool{
	"non_repudiation": true,
}

// ESIC_EXTENSION_1 is the ESIC extension for PDF 1.7.
// Used to declare usage of PAdES structures.
var ESIC_EXTENSION_1 = &extensions.DeveloperExtension{
	PrefixName:     "/ESIC",
	BaseVersion:    "/1.7",
	ExtensionLevel: 1,
	CompareByLevel: true,
	Multivalued:    extensions.ExtensionNever,
}

// ISO32001 is the ISO extension to PDF 2.0 for SHA-3 and SHAKE256 support.
// This extension is defined in ISO/TS 32001.
// Declared automatically whenever SHA-3 or SHAKE256 is used in signing or
// document digesting process.
var ISO32001 = &extensions.DeveloperExtension{
	PrefixName:        "/ISO_",
	BaseVersion:       "/2.0",
	ExtensionLevel:    32001,
	ExtensionRevision: ":2022",
	URL:               "https://www.iso.org/standard/45874.html",
	CompareByLevel:    false,
	Multivalued:       extensions.ExtensionAlways,
}

// ISO32002 is the ISO extension to PDF 2.0 for EdDSA support and ECDSA curve
// clarifications. This extension is defined in ISO/TS 32002.
// Declared automatically when Ed25519 or Ed448 are used, and when ECDSA is
// used with one of the curves listed in ISO/TS 32002.
var ISO32002 = &extensions.DeveloperExtension{
	PrefixName:        "/ISO_",
	BaseVersion:       "/2.0",
	ExtensionLevel:    32002,
	ExtensionRevision: ":2022",
	URL:               "https://www.iso.org/standard/45875.html",
	CompareByLevel:    false,
	Multivalued:       extensions.ExtensionAlways,
}

// ISO32002CurveNames are curve names (as used by Go crypto) included in ISO/TS 32002.
var ISO32002CurveNames = map[string]bool{
	"P-256":           true, // secp256r1
	"P-384":           true, // secp384r1
	"P-521":           true, // secp521r1
	"brainpoolP256r1": true,
	"brainpoolP384r1": true,
	"brainpoolP512r1": true,
}

// Curve name mappings between asn1crypto names and Go crypto names.
var CurveNameMappings = map[string]string{
	"secp256r1":       "P-256",
	"secp384r1":       "P-384",
	"secp521r1":       "P-521",
	"brainpoolp256r1": "brainpoolP256r1",
	"brainpoolp384r1": "brainpoolP384r1",
	"brainpoolp512r1": "brainpoolP512r1",
}

// Common digest algorithm names
const (
	DigestSHA1   = "sha1"
	DigestSHA256 = "sha256"
	DigestSHA384 = "sha384"
	DigestSHA512 = "sha512"
)

// RequiresISO32001 returns true if the given digest algorithm requires
// the ISO32001 extension declaration.
func RequiresISO32001(digestAlg string) bool {
	switch digestAlg {
	case "sha3-256", "sha3-384", "sha3-512", "shake256":
		return true
	default:
		return false
	}
}

// RequiresISO32002ForCurve returns true if the given curve name requires
// the ISO32002 extension declaration.
func RequiresISO32002ForCurve(curveName string) bool {
	// Check Go crypto curve names
	if ISO32002CurveNames[curveName] {
		return true
	}
	// Check asn1crypto curve names
	if _, ok := CurveNameMappings[curveName]; ok {
		return true
	}
	return false
}
