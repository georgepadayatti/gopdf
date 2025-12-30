// Package certvalidator provides X.509 certificate path validation.
// This file contains utility functions for certificate and signature processing.
package certvalidator

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/url"
	"strings"
)

// ExtractDirectoryName extracts a directory name from GeneralNames.
// This searches for a directoryName type in the general names.
func ExtractDirectoryName(names []asn1.RawValue) (*pkix.Name, error) {
	for _, gn := range names {
		// Tag 4 is directoryName in GeneralName
		if gn.Tag == 4 {
			var rdnSeq pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Bytes, &rdnSeq); err != nil {
				return nil, fmt.Errorf("failed to parse directory name: %w", err)
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdnSeq)
			return &name, nil
		}
	}
	return nil, fmt.Errorf("no directory name found in general names")
}

// GetIssuerDN returns the issuer distinguished name for a certificate.
func GetIssuerDN(cert *x509.Certificate) pkix.Name {
	return cert.Issuer
}

func canonicalNameString(name pkix.Name) string {
	atvs := name.Names
	if len(atvs) == 0 {
		for _, rdn := range name.ToRDNSequence() {
			for _, atv := range rdn {
				atvs = append(atvs, atv)
			}
		}
	}

	parts := make([]string, 0, len(atvs))
	for _, atv := range atvs {
		value := normalizeRDNValue(atv.Value)
		parts = append(parts, fmt.Sprintf("%s=%s", atv.Type.String(), value))
	}
	return strings.Join(parts, ",")
}

func normalizeRDNValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return normalizeDNString(v)
	default:
		return fmt.Sprint(v)
	}
}

func normalizeDNString(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

// CertIssuerSerial returns a unique identifier for a certificate based on issuer and serial.
func CertIssuerSerial(cert *x509.Certificate) []byte {
	h := sha256.Sum256([]byte(canonicalNameString(cert.Issuer)))
	return []byte(fmt.Sprintf("%x:%s", h[:], cert.SerialNumber.String()))
}

// CRLDistributionPoint represents a CRL distribution point.
type CRLDistributionPoint struct {
	URL        string
	Issuer     pkix.Name
	HasIssuer  bool
	ReasonMask int
}

// GetCRLDistributionPoints extracts CRL distribution points from a certificate.
func GetCRLDistributionPoints(cert *x509.Certificate) []CRLDistributionPoint {
	var dps []CRLDistributionPoint
	for _, dp := range cert.CRLDistributionPoints {
		if isHTTPURL(dp) {
			dps = append(dps, CRLDistributionPoint{
				URL: dp,
			})
		}
	}
	return dps
}

// GetDeltaCRLDistributionPoints extracts delta CRL distribution points.
// Note: Go's x509 package doesn't expose freshest CRL extension directly.
func GetDeltaCRLDistributionPoints(cert *x509.Certificate) []CRLDistributionPoint {
	// Delta CRLs would need to be extracted from extensions
	// The standard x509 library doesn't parse freshestCRL extension
	return nil
}

// GetRelevantCRLDPs returns relevant CRL distribution points including deltas if requested.
func GetRelevantCRLDPs(cert *x509.Certificate, useDeltas bool) []CRLDistributionPoint {
	dps := GetCRLDistributionPoints(cert)
	if useDeltas {
		dps = append(dps, GetDeltaCRLDistributionPoints(cert)...)
	}
	return dps
}

// GetOCSPURLs extracts OCSP responder URLs from a certificate.
func GetOCSPURLs(cert *x509.Certificate) []string {
	var urls []string
	for _, ocspURL := range cert.OCSPServer {
		if isHTTPURL(ocspURL) {
			urls = append(urls, ocspURL)
		}
	}
	return urls
}

// RevocationInfoDeclaration describes what revocation info is declared in a certificate.
type RevocationInfoDeclaration struct {
	HasCRL  bool
	HasOCSP bool
}

// GetDeclaredRevInfo returns what revocation information is declared in the certificate.
func GetDeclaredRevInfo(cert *x509.Certificate) RevocationInfoDeclaration {
	hasCRLExt := false
	hasAIAExt := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}) {
			hasCRLExt = true
		}
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}) {
			hasAIAExt = true
		}
	}
	return RevocationInfoDeclaration{
		HasCRL:  len(cert.CRLDistributionPoints) > 0 || hasCRLExt,
		HasOCSP: len(cert.OCSPServer) > 0 || hasAIAExt,
	}
}

// isHTTPURL checks if a URL is HTTP or HTTPS.
func isHTTPURL(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// ParseURL parses a URL string.
func ParseURL(urlStr string) (*url.URL, error) {
	return url.Parse(urlStr)
}

// CertificateFingerprint returns the SHA-256 fingerprint of a certificate.
func CertificateFingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// CompareCertificates checks if two certificates are identical.
func CompareCertificates(a, b *x509.Certificate) bool {
	return CertificateFingerprint(a) == CertificateFingerprint(b)
}

// IssuedBy checks if a certificate was issued by a potential issuer.
func IssuedBy(cert *x509.Certificate, issuer *x509.Certificate) bool {
	// Check issuer name matches
	if !namesEqual(cert.Issuer, issuer.Subject) {
		return false
	}

	// Check authority key identifier if present
	if len(cert.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 {
		for i := range cert.AuthorityKeyId {
			if i >= len(issuer.SubjectKeyId) || cert.AuthorityKeyId[i] != issuer.SubjectKeyId[i] {
				return false
			}
		}
	}

	return true
}

// IsSelfSigned checks if a certificate is self-signed.
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// IsSelfIssued checks if a certificate is self-issued (issuer == subject).
// A certificate is self-issued if the issuer and subject are the same,
// but it may still be signed by a different key.
func IsSelfIssued(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// GetAuthorityInfoAccessOCSP extracts OCSP URLs from the AIA extension.
func GetAuthorityInfoAccessOCSP(cert *x509.Certificate) []string {
	return cert.OCSPServer
}

// GetAuthorityInfoAccessIssuers extracts CA issuer URLs from the AIA extension.
func GetAuthorityInfoAccessIssuers(cert *x509.Certificate) []string {
	return cert.IssuingCertificateURL
}

// HashAlgorithmName returns the name of a hash algorithm from its OID.
func HashAlgorithmName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDSHA1):
		return "sha1"
	case oid.Equal(OIDSHA256):
		return "sha256"
	case oid.Equal(OIDSHA384):
		return "sha384"
	case oid.Equal(OIDSHA512):
		return "sha512"
	default:
		return oid.String()
	}
}

// NormalizeDN normalizes a distinguished name for comparison.
func NormalizeDN(name pkix.Name) string {
	return strings.ToLower(name.String())
}

// CompareDN compares two distinguished names (case-insensitive).
func CompareDN(a, b pkix.Name) bool {
	return NormalizeDN(a) == NormalizeDN(b)
}

// ExtractExtension extracts an extension value by OID from a certificate.
func ExtractExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, true
		}
	}
	return nil, false
}

// ExtractCriticalExtension extracts a critical extension by OID.
func ExtractCriticalExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, ext.Critical, nil
		}
	}
	return nil, false, nil
}

// HasExtension checks if a certificate has a specific extension.
func HasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	_, found := ExtractExtension(cert, oid)
	return found
}

// GetSubjectAltNames extracts subject alternative names from a certificate.
type SubjectAltNames struct {
	DNSNames       []string
	EmailAddresses []string
	URIs           []string
	IPAddresses    []string
}

// GetSubjectAltNames extracts all subject alternative names.
func GetSubjectAltNames(cert *x509.Certificate) *SubjectAltNames {
	sans := &SubjectAltNames{
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		URIs:           make([]string, 0, len(cert.URIs)),
	}

	for _, uri := range cert.URIs {
		sans.URIs = append(sans.URIs, uri.String())
	}

	for _, ip := range cert.IPAddresses {
		sans.IPAddresses = append(sans.IPAddresses, ip.String())
	}

	return sans
}

// CertPathLength returns the path length constraint, or -1 if none.
func CertPathLength(cert *x509.Certificate) int {
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		return cert.MaxPathLen
	}
	return -1
}

// IsCAConstraint checks if a certificate has the CA basic constraint.
func IsCAConstraint(cert *x509.Certificate) bool {
	return cert.IsCA
}

// GetKeyUsage returns the key usage bits as a string slice.
func GetKeyUsage(cert *x509.Certificate) []string {
	var usages []string
	ku := cert.KeyUsage

	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "decipherOnly")
	}

	return usages
}

// GetExtKeyUsage returns the extended key usages as OID strings.
func GetExtKeyUsage(cert *x509.Certificate) []string {
	var usages []string
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "anyExtendedKeyUsage")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "clientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "codeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "emailProtection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "timeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		default:
			usages = append(usages, fmt.Sprintf("unknown(%d)", eku))
		}
	}

	// Add unknown OIDs
	for _, oid := range cert.UnknownExtKeyUsage {
		usages = append(usages, oid.String())
	}

	return usages
}
