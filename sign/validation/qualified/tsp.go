// Package qualified provides TSP (Trust Service Provider) registry and criteria types
// for qualified electronic signature validation according to ETSI standards.
package qualified

import (
	"crypto/x509"
	"encoding/asn1"
	"sort"
	"strings"
	"sync"
	"time"
)

// URI bases for ETSI trust service identifiers.
const (
	TrstSvcURIBase      = "http://uri.etsi.org/TrstSvc"
	CAQCUri             = TrstSvcURIBase + "/Svctype/CA/QC"
	QTSTUri             = TrstSvcURIBase + "/Svctype/TSA/QTST"
	TrustedListURIBase  = TrstSvcURIBase + "/TrustedList"
	SvcInfoExtURIBase   = TrustedListURIBase + "/SvcInfoExt"
	SchemeRulesURIBase  = TrustedListURIBase + "/schemerules"
	LOTLRule            = SchemeRulesURIBase + "/EUlistofthelists"
	StatusGrantedURI    = TrustedListURIBase + "/Svcstatus/granted"
	ETSITSLMimeType     = "application/vnd.etsi.tsl+xml"
)

// QcCertType represents the type of qualified certificate.
type QcCertType string

const (
	QcCertTypeEsign QcCertType = "qct_esign" // Certificate qualified for eSignatures
	QcCertTypeEseal QcCertType = "qct_eseal" // Certificate qualified for eSeals
	QcCertTypeWeb   QcCertType = "qct_web"   // Qualified website authentication certificate (QWAC)
)

// Certificate type URIs.
const (
	ForeSignaturesURI           = SvcInfoExtURIBase + "/ForeSignatures"
	ForeSealsURI                = SvcInfoExtURIBase + "/ForeSeals"
	ForWebSiteAuthenticationURI = SvcInfoExtURIBase + "/ForWebSiteAuthentication"
)

// QcCertTypeFromURI returns the QcCertType from a URI.
func QcCertTypeFromURI(uri string) (QcCertType, bool) {
	switch uri {
	case ForeSignaturesURI:
		return QcCertTypeEsign, true
	case ForeSealsURI:
		return QcCertTypeEseal, true
	case ForWebSiteAuthenticationURI:
		return QcCertTypeWeb, true
	default:
		return "", false
	}
}

// Qualifier represents a qualifier as specified in ETSI TS 119 612, 5.5.9.2.
type Qualifier string

const (
	QualifierWithSSCD            Qualifier = "QCWithSSCD"
	QualifierNoSSCD              Qualifier = "QCNoSSCD"
	QualifierSSCDAsInCert        Qualifier = "QCSSCDStatusAsInCert"
	QualifierWithQSCD            Qualifier = "QCWithQSCD"
	QualifierNoQSCD              Qualifier = "QCNoQSCD"
	QualifierQSCDAsInCert        Qualifier = "QCQSCDStatusAsInCert"
	QualifierQSCDManagedOnBehalf Qualifier = "QCQSCDManagedOnBehalf"
	QualifierLegalPerson         Qualifier = "QCForLegalPerson"
	QualifierForESig             Qualifier = "QCForESig"
	QualifierForESeal            Qualifier = "QCForESeal"
	QualifierForWSA              Qualifier = "QCForWSA"
	QualifierNotQualified        Qualifier = "NotQualified"
	QualifierQCStatement         Qualifier = "QCStatement"
)

// URI returns the ETSI URI for this qualifier.
func (q Qualifier) URI() string {
	return SvcInfoExtURIBase + "/" + string(q)
}

// QualifierFromURI returns the Qualifier for a given URI.
func QualifierFromURI(uri string) (Qualifier, bool) {
	qualifiers := []Qualifier{
		QualifierWithSSCD, QualifierNoSSCD, QualifierSSCDAsInCert,
		QualifierWithQSCD, QualifierNoQSCD, QualifierQSCDAsInCert,
		QualifierQSCDManagedOnBehalf, QualifierLegalPerson,
		QualifierForESig, QualifierForESeal, QualifierForWSA,
		QualifierNotQualified, QualifierQCStatement,
	}
	for _, q := range qualifiers {
		if q.URI() == uri {
			return q, true
		}
	}
	return "", false
}

// CriteriaCombination defines how to combine sub-criteria.
type CriteriaCombination string

const (
	CriteriaCombinationAll        CriteriaCombination = "all"        // All sub-criteria must match
	CriteriaCombinationAtLeastOne CriteriaCombination = "atLeastOne" // At least one sub-criterion must match
	CriteriaCombinationNone       CriteriaCombination = "none"       // None of the sub-criteria must match
)

// Criterion is an interface for qualification criteria.
type Criterion interface {
	// Matches evaluates a certificate against this criterion.
	Matches(cert *x509.Certificate) bool
}

// KeyUsageConstraintsForCriteria represents key usage constraints for criteria matching.
type KeyUsageConstraintsForCriteria struct {
	KeyUsage          map[string]bool // Required key usage bits
	KeyUsageForbidden map[string]bool // Forbidden key usage bits
	ExtdKeyUsage      map[string]bool // Extended key usage OIDs
}

// Validate checks if the certificate meets the key usage constraints.
func (c *KeyUsageConstraintsForCriteria) Validate(cert *x509.Certificate) error {
	// Check required key usages
	for usage, required := range c.KeyUsage {
		if required && !hasKeyUsageBit(cert, usage) {
			return ErrAssessmentFailed
		}
	}
	// Check forbidden key usages
	for usage, forbidden := range c.KeyUsageForbidden {
		if forbidden && hasKeyUsageBit(cert, usage) {
			return ErrAssessmentFailed
		}
	}
	// Check extended key usage
	for ekuOID := range c.ExtdKeyUsage {
		if !hasExtendedKeyUsageBit(cert, ekuOID) {
			return ErrAssessmentFailed
		}
	}
	return nil
}

func hasKeyUsageBit(cert *x509.Certificate, usage string) bool {
	usageMap := map[string]x509.KeyUsage{
		"digital_signature":  x509.KeyUsageDigitalSignature,
		"content_commitment": x509.KeyUsageContentCommitment,
		"key_encipherment":   x509.KeyUsageKeyEncipherment,
		"data_encipherment":  x509.KeyUsageDataEncipherment,
		"key_agreement":      x509.KeyUsageKeyAgreement,
		"key_cert_sign":      x509.KeyUsageCertSign,
		"crl_sign":           x509.KeyUsageCRLSign,
		"encipher_only":      x509.KeyUsageEncipherOnly,
		"decipher_only":      x509.KeyUsageDecipherOnly,
	}
	if ku, ok := usageMap[strings.ToLower(usage)]; ok {
		return cert.KeyUsage&ku != 0
	}
	return false
}

func hasExtendedKeyUsageBit(cert *x509.Certificate, oidStr string) bool {
	// Map known extended key usages to OID strings
	ekuOIDMap := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "2.5.29.37.0",
		x509.ExtKeyUsageServerAuth:                     "1.3.6.1.5.5.7.3.1",
		x509.ExtKeyUsageClientAuth:                     "1.3.6.1.5.5.7.3.2",
		x509.ExtKeyUsageCodeSigning:                    "1.3.6.1.5.5.7.3.3",
		x509.ExtKeyUsageEmailProtection:                "1.3.6.1.5.5.7.3.4",
		x509.ExtKeyUsageIPSECEndSystem:                 "1.3.6.1.5.5.7.3.5",
		x509.ExtKeyUsageIPSECTunnel:                    "1.3.6.1.5.5.7.3.6",
		x509.ExtKeyUsageIPSECUser:                      "1.3.6.1.5.5.7.3.7",
		x509.ExtKeyUsageTimeStamping:                   "1.3.6.1.5.5.7.3.8",
		x509.ExtKeyUsageOCSPSigning:                    "1.3.6.1.5.5.7.3.9",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
	}

	for _, eku := range cert.ExtKeyUsage {
		if ekuOID, ok := ekuOIDMap[eku]; ok && ekuOID == oidStr {
			return true
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.String() == oidStr {
			return true
		}
	}
	return false
}

// KeyUsageCriterion matches certificates that meet specified key usage constraints.
type KeyUsageCriterion struct {
	Settings KeyUsageConstraintsForCriteria
}

// Matches implements Criterion.
func (c *KeyUsageCriterion) Matches(cert *x509.Certificate) bool {
	return c.Settings.Validate(cert) == nil
}

// PolicySetCriterion matches certificates that have specified certificate policies.
type PolicySetCriterion struct {
	RequiredPolicyOIDs map[string]bool // OIDs that must be present
}

// Matches implements Criterion.
func (c *PolicySetCriterion) Matches(cert *x509.Certificate) bool {
	foundPolicies := make(map[string]bool)

	// Parse certificate policies extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 32}) {
			policies, _ := parsePoliciesExtension(ext.Value)
			for _, policy := range policies {
				foundPolicies[policy.OID.String()] = true
			}
		}
	}

	// Check if all required policies are present
	for oid, required := range c.RequiredPolicyOIDs {
		if required && !foundPolicies[oid] {
			return false
		}
	}
	return true
}

// CertSubjectDNCriterion matches certificates with required subject DN components.
type CertSubjectDNCriterion struct {
	RequiredRDNPartOIDs map[string]bool // OIDs of required RDN components
}

// Matches implements Criterion.
func (c *CertSubjectDNCriterion) Matches(cert *x509.Certificate) bool {
	foundOIDs := make(map[string]bool)
	for _, name := range cert.Subject.Names {
		foundOIDs[name.Type.String()] = true
	}
	for oid, required := range c.RequiredRDNPartOIDs {
		if required && !foundOIDs[oid] {
			return false
		}
	}
	return true
}

// CriteriaList combines multiple criteria.
type CriteriaList struct {
	CombineAs CriteriaCombination
	Criteria  []Criterion
}

// Matches implements Criterion.
func (c *CriteriaList) Matches(cert *x509.Certificate) bool {
	if len(c.Criteria) == 0 {
		return true
	}

	switch c.CombineAs {
	case CriteriaCombinationAll:
		for _, criterion := range c.Criteria {
			if !criterion.Matches(cert) {
				return false
			}
		}
		return true
	case CriteriaCombinationAtLeastOne:
		for _, criterion := range c.Criteria {
			if criterion.Matches(cert) {
				return true
			}
		}
		return false
	case CriteriaCombinationNone:
		for _, criterion := range c.Criteria {
			if criterion.Matches(cert) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// TSPQualification represents a qualification in the sense of ETSI TS 119 612, 5.5.9.2.
type TSPQualification struct {
	Qualifiers   map[Qualifier]bool // Set of qualifiers to apply
	CriteriaList *CriteriaList      // Criteria for the qualification
}

// AdditionalServiceInformation contains additional info about a service.
type AdditionalServiceInformation struct {
	URI         string
	Critical    bool
	TextualInfo string
}

// BaseServiceInformation contains common service information.
type BaseServiceInformation struct {
	ServiceType                   string                         // URI of the service type
	ServiceName                   string                         // Name of the service
	ValidFrom                     time.Time                      // Start of validity window
	ValidUntil                    *time.Time                     // End of validity window (nil = indefinite)
	ProviderCerts                 []*x509.Certificate            // Certificates linked to this provider
	AdditionalInfoCertificateType map[QcCertType]bool            // Narrowing scope by cert type
	OtherAdditionalInfo           []AdditionalServiceInformation // Other qualifying info
}

// QualifiedServiceInformation is a service with conditional qualifiers.
type QualifiedServiceInformation struct {
	BaseInfo       BaseServiceInformation
	Qualifications []TSPQualification
}

// CAServiceInformation is a qualified CA service description.
type CAServiceInformation struct {
	QualifiedServiceInformation
	ExpiredCertsRevocationInfo *time.Time // See ETSI TS 119 612, 5.5.9.1
}

// QTSTServiceInformation is a qualified TSA service description.
type QTSTServiceInformation struct {
	QualifiedServiceInformation
}

// Authority represents an authority identified by certificate.
type Authority interface {
	// Certificate returns the authority's certificate.
	Certificate() *x509.Certificate
	// IsPotentialIssuerOf checks if this authority could have issued the cert.
	IsPotentialIssuerOf(cert *x509.Certificate) bool
}

// AuthorityWithCert is an authority identified by its certificate.
type AuthorityWithCert struct {
	cert *x509.Certificate
}

// NewAuthorityWithCert creates a new AuthorityWithCert.
func NewAuthorityWithCert(cert *x509.Certificate) *AuthorityWithCert {
	return &AuthorityWithCert{cert: cert}
}

// Certificate returns the authority's certificate.
func (a *AuthorityWithCert) Certificate() *x509.Certificate {
	return a.cert
}

// IsPotentialIssuerOf checks if this authority could have issued the cert.
func (a *AuthorityWithCert) IsPotentialIssuerOf(cert *x509.Certificate) bool {
	if a.cert == nil || cert == nil {
		return false
	}
	// Check if subject of authority matches issuer of cert
	return a.cert.Subject.String() == cert.Issuer.String()
}

// TSPRegistry is a registry of trust service providers from a trust list.
type TSPRegistry struct {
	mu          sync.RWMutex
	caCertToSI  map[string][]CAServiceInformation   // keyed by cert fingerprint
	tstCertToSI map[string][]QTSTServiceInformation // keyed by cert fingerprint
}

// NewTSPRegistry creates a new TSP registry.
func NewTSPRegistry() *TSPRegistry {
	return &TSPRegistry{
		caCertToSI:  make(map[string][]CAServiceInformation),
		tstCertToSI: make(map[string][]QTSTServiceInformation),
	}
}

// RegisterCA registers a trusted certificate authority.
func (r *TSPRegistry) RegisterCA(info CAServiceInformation) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cert := range info.BaseInfo.ProviderCerts {
		key := certFingerprint(cert)
		r.caCertToSI[key] = append(r.caCertToSI[key], info)
	}
}

// RegisterTST registers a trusted time stamping authority.
func (r *TSPRegistry) RegisterTST(info QTSTServiceInformation) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cert := range info.BaseInfo.ProviderCerts {
		key := certFingerprint(cert)
		r.tstCertToSI[key] = append(r.tstCertToSI[key], info)
	}
}

// ApplicableServiceDefinitions retrieves service definitions for an authority.
func (r *TSPRegistry) ApplicableServiceDefinitions(cert *x509.Certificate, moment *time.Time) []QualifiedServiceInformation {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := certFingerprint(cert)
	var allServices []QualifiedServiceInformation

	// Get CA services
	for _, si := range r.caCertToSI[key] {
		allServices = append(allServices, si.QualifiedServiceInformation)
	}

	// Get TST services
	for _, si := range r.tstCertToSI[key] {
		allServices = append(allServices, si.QualifiedServiceInformation)
	}

	// Sort by validity (most recent first, then indefinite)
	sort.Slice(allServices, func(i, j int) bool {
		vi := allServices[i].BaseInfo.ValidUntil
		vj := allServices[j].BaseInfo.ValidUntil
		if vi == nil && vj == nil {
			return false
		}
		if vi == nil {
			return false
		}
		if vj == nil {
			return true
		}
		return vi.After(*vj)
	})

	// Filter by moment if specified
	if moment != nil {
		var filtered []QualifiedServiceInformation
		for _, si := range allServices {
			if !si.BaseInfo.ValidFrom.After(*moment) {
				if si.BaseInfo.ValidUntil == nil || !si.BaseInfo.ValidUntil.Before(*moment) {
					filtered = append(filtered, si)
				}
			}
		}
		return filtered
	}

	return allServices
}

// KnownCertificateAuthorities lists known CA authorities.
func (r *TSPRegistry) KnownCertificateAuthorities() []*x509.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var certs []*x509.Certificate

	for _, services := range r.caCertToSI {
		for _, si := range services {
			for _, cert := range si.BaseInfo.ProviderCerts {
				fp := certFingerprint(cert)
				if !seen[fp] {
					seen[fp] = true
					certs = append(certs, cert)
				}
			}
		}
	}

	return certs
}

// KnownTimestampAuthorities lists known TSA authorities.
func (r *TSPRegistry) KnownTimestampAuthorities() []*x509.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var certs []*x509.Certificate

	for _, services := range r.tstCertToSI {
		for _, si := range services {
			for _, cert := range si.BaseInfo.ProviderCerts {
				fp := certFingerprint(cert)
				if !seen[fp] {
					seen[fp] = true
					certs = append(certs, cert)
				}
			}
		}
	}

	return certs
}

// ApplicableTSPsOnPath lists applicable TSPs on a certificate path.
func (r *TSPRegistry) ApplicableTSPsOnPath(chain []*x509.Certificate, moment time.Time) []QualifiedServiceInformation {
	var results []QualifiedServiceInformation
	for _, cert := range chain {
		results = append(results, r.ApplicableServiceDefinitions(cert, &moment)...)
	}
	return results
}

func certFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return string(cert.Raw)
}

// TrustedServiceType represents the type of trusted service.
type TrustedServiceType int

const (
	TrustedServiceTypeUnsupported TrustedServiceType = iota
	TrustedServiceTypeCertificateAuthority
	TrustedServiceTypeTimeStampingAuthority
)

// TrustQualifiers contains trust anchor qualifiers.
type TrustQualifiers struct {
	TrustedServiceType TrustedServiceType
	ValidFrom          time.Time
	ValidUntil         *time.Time
}

// TrustAnchor represents a trust anchor.
type TrustAnchor struct {
	Authority Authority
	Quals     TrustQualifiers
}

// TSPTrustManager is a trust manager based on a TSPRegistry.
type TSPTrustManager struct {
	Registry *TSPRegistry
}

// NewTSPTrustManager creates a new TSP trust manager.
func NewTSPTrustManager(registry *TSPRegistry) *TSPTrustManager {
	return &TSPTrustManager{Registry: registry}
}

// AsTrustAnchor returns a trust anchor for the given certificate.
func (m *TSPTrustManager) AsTrustAnchor(cert *x509.Certificate) *TrustAnchor {
	services := m.Registry.ApplicableServiceDefinitions(cert, nil)
	if len(services) == 0 {
		return nil
	}

	sd := services[0]
	var serviceType TrustedServiceType
	switch sd.BaseInfo.ServiceType {
	case CAQCUri:
		serviceType = TrustedServiceTypeCertificateAuthority
	case QTSTUri:
		serviceType = TrustedServiceTypeTimeStampingAuthority
	default:
		serviceType = TrustedServiceTypeUnsupported
	}

	return &TrustAnchor{
		Authority: NewAuthorityWithCert(cert),
		Quals: TrustQualifiers{
			TrustedServiceType: serviceType,
			ValidFrom:          sd.BaseInfo.ValidFrom,
			ValidUntil:         sd.BaseInfo.ValidUntil,
		},
	}
}

// FindPotentialIssuers finds potential issuers for a certificate.
func (m *TSPTrustManager) FindPotentialIssuers(cert *x509.Certificate) []*TrustAnchor {
	var anchors []*TrustAnchor

	for _, ca := range m.Registry.KnownCertificateAuthorities() {
		anchor := m.AsTrustAnchor(ca)
		if anchor != nil && anchor.Authority.IsPotentialIssuerOf(cert) {
			anchors = append(anchors, anchor)
		}
	}

	return anchors
}

// TSPServiceParsingError represents a parsing error for TSP services.
type TSPServiceParsingError struct {
	Message string
}

func (e *TSPServiceParsingError) Error() string {
	return e.Message
}

// NewTSPServiceParsingError creates a new TSP service parsing error.
func NewTSPServiceParsingError(msg string) *TSPServiceParsingError {
	return &TSPServiceParsingError{Message: msg}
}
