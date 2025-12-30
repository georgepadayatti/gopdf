// Package qualified provides qualified electronic signature validation
// according to EU eIDAS regulation and ETSI standards.
package qualified

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Common errors
var (
	ErrNotQualified        = errors.New("certificate is not qualified")
	ErrTSPNotFound         = errors.New("trust service provider not found")
	ErrTSPNotQualified     = errors.New("trust service provider is not qualified")
	ErrServiceNotFound     = errors.New("service not found in trusted list")
	ErrTrustedListExpired  = errors.New("trusted list has expired")
	ErrTrustedListInvalid  = errors.New("trusted list is invalid")
	ErrCountryNotSupported = errors.New("country not supported")
	ErrQCStatementNotFound = errors.New("QC statement not found")
	ErrAssessmentFailed    = errors.New("qualified assessment failed")
)

// QC Statement OIDs from ETSI EN 319 412-5
var (
	OIDQcStatements      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	OIDQcCompliance      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}
	OIDQcLimitValue      = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 2}
	OIDQcRetentionPeriod = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3}
	OIDQcSSCD            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}
	OIDQcPDS             = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}
	OIDQcType            = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}
	OIDQcCCLegislation   = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 7}

	// QC Type OIDs
	OIDQcTypeEsign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}
	OIDQcTypeEseal = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}
	OIDQcTypeWeb   = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}

	// ETSI PSD2 OIDs
	OIDPSD2QcStatement = asn1.ObjectIdentifier{0, 4, 0, 19495, 2}
)

// QCType represents the type of qualified certificate.
type QCType int

const (
	QCTypeUnknown QCType = iota
	QCTypeEsign          // Electronic signature
	QCTypeEseal          // Electronic seal
	QCTypeWeb            // Website authentication
)

// String returns the string representation of QC type.
func (t QCType) String() string {
	switch t {
	case QCTypeEsign:
		return "esign"
	case QCTypeEseal:
		return "eseal"
	case QCTypeWeb:
		return "web"
	default:
		return "unknown"
	}
}

// QCTypeFromOID returns the QC type for an OID.
func QCTypeFromOID(oid asn1.ObjectIdentifier) QCType {
	if oid.Equal(OIDQcTypeEsign) {
		return QCTypeEsign
	}
	if oid.Equal(OIDQcTypeEseal) {
		return QCTypeEseal
	}
	if oid.Equal(OIDQcTypeWeb) {
		return QCTypeWeb
	}
	return QCTypeUnknown
}

// QualificationStatus represents the qualification status of a certificate.
type QualificationStatus int

const (
	StatusNotDetermined QualificationStatus = iota
	StatusQualified
	StatusNotQualified
	StatusQualifiedAtIssuance
	StatusWithdrawn
)

// String returns the string representation of qualification status.
func (s QualificationStatus) String() string {
	switch s {
	case StatusQualified:
		return "qualified"
	case StatusNotQualified:
		return "not_qualified"
	case StatusQualifiedAtIssuance:
		return "qualified_at_issuance"
	case StatusWithdrawn:
		return "withdrawn"
	default:
		return "not_determined"
	}
}

// QCStatement represents a qualified certificate statement.
type QCStatement struct {
	OID   asn1.ObjectIdentifier
	Value interface{}
}

// QCStatements represents the QC statements extension.
type QCStatements struct {
	Statements []QCStatement
}

// HasCompliance checks if QcCompliance statement is present.
func (s *QCStatements) HasCompliance() bool {
	for _, stmt := range s.Statements {
		if stmt.OID.Equal(OIDQcCompliance) {
			return true
		}
	}
	return false
}

// HasSSCD checks if QcSSCD statement is present.
func (s *QCStatements) HasSSCD() bool {
	for _, stmt := range s.Statements {
		if stmt.OID.Equal(OIDQcSSCD) {
			return true
		}
	}
	return false
}

// GetType returns the QC type if present.
func (s *QCStatements) GetType() QCType {
	for _, stmt := range s.Statements {
		if stmt.OID.Equal(OIDQcType) {
			if typeOIDs, ok := stmt.Value.([]asn1.ObjectIdentifier); ok {
				for _, oid := range typeOIDs {
					t := QCTypeFromOID(oid)
					if t != QCTypeUnknown {
						return t
					}
				}
			}
		}
	}
	return QCTypeUnknown
}

// GetLegislation returns the legislation countries if present.
func (s *QCStatements) GetLegislation() []string {
	for _, stmt := range s.Statements {
		if stmt.OID.Equal(OIDQcCCLegislation) {
			if countries, ok := stmt.Value.([]string); ok {
				return countries
			}
		}
	}
	return nil
}

// ParseQCStatements parses QC statements from a certificate.
func ParseQCStatements(cert *x509.Certificate) (*QCStatements, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDQcStatements) {
			return parseQCStatementsExtension(ext.Value)
		}
	}
	return nil, ErrQCStatementNotFound
}

func parseQCStatementsExtension(data []byte) (*QCStatements, error) {
	var rawStatements []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &rawStatements); err != nil {
		return nil, fmt.Errorf("failed to parse QC statements: %w", err)
	}

	statements := &QCStatements{}
	for _, raw := range rawStatements {
		var seq struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &seq); err != nil {
			continue
		}
		statements.Statements = append(statements.Statements, QCStatement{
			OID:   seq.OID,
			Value: seq.Value.Bytes,
		})
	}

	return statements, nil
}

// ServiceType represents the type of trust service.
type ServiceType int

const (
	ServiceTypeUnknown ServiceType = iota
	ServiceTypeCA
	ServiceTypeOCSP
	ServiceTypeCRL
	ServiceTypeTSA
	ServiceTypeQESCD
	ServiceTypeQESCDManagement
)

// String returns the string representation of service type.
func (t ServiceType) String() string {
	switch t {
	case ServiceTypeCA:
		return "CA"
	case ServiceTypeOCSP:
		return "OCSP"
	case ServiceTypeCRL:
		return "CRL"
	case ServiceTypeTSA:
		return "TSA"
	case ServiceTypeQESCD:
		return "QESCD"
	case ServiceTypeQESCDManagement:
		return "QESCDManagement"
	default:
		return "unknown"
	}
}

// ServiceStatus represents the status of a trust service.
type ServiceStatus int

const (
	ServiceStatusUnknown ServiceStatus = iota
	ServiceStatusGranted
	ServiceStatusWithdrawn
	ServiceStatusSupervisionInCessation
	ServiceStatusSupervisionCeased
	ServiceStatusSupervisionRevoked
	ServiceStatusAccredited
	ServiceStatusAccreditationCeased
	ServiceStatusAccreditationRevoked
)

// String returns the string representation of service status.
func (s ServiceStatus) String() string {
	switch s {
	case ServiceStatusGranted:
		return "granted"
	case ServiceStatusWithdrawn:
		return "withdrawn"
	case ServiceStatusSupervisionInCessation:
		return "supervision_in_cessation"
	case ServiceStatusSupervisionCeased:
		return "supervision_ceased"
	case ServiceStatusSupervisionRevoked:
		return "supervision_revoked"
	case ServiceStatusAccredited:
		return "accredited"
	case ServiceStatusAccreditationCeased:
		return "accreditation_ceased"
	case ServiceStatusAccreditationRevoked:
		return "accreditation_revoked"
	default:
		return "unknown"
	}
}

// IsActive returns true if the service is currently active/qualified.
func (s ServiceStatus) IsActive() bool {
	return s == ServiceStatusGranted || s == ServiceStatusAccredited
}

// TrustService represents a trust service from a trusted list.
type TrustService struct {
	Name              string
	Type              ServiceType
	Status            ServiceStatus
	StatusStartTime   time.Time
	ServiceDigitalIDs []ServiceDigitalID
	Extensions        []ServiceExtension
	History           []ServiceHistoryInstance
}

// ServiceDigitalID represents a digital identity of a service.
type ServiceDigitalID struct {
	Certificate    *x509.Certificate
	SubjectName    string
	SKI            []byte // Subject Key Identifier
	X509CertDigest []byte
}

// ServiceExtension represents an extension to a service.
type ServiceExtension struct {
	Critical bool
	OID      asn1.ObjectIdentifier
	Value    []byte
}

// ServiceHistoryInstance represents a historical status of a service.
type ServiceHistoryInstance struct {
	Status          ServiceStatus
	StatusStartTime time.Time
}

// IsActiveAt checks if the service was active at the given time.
func (s *TrustService) IsActiveAt(at time.Time) bool {
	// Check current status
	if at.After(s.StatusStartTime) || at.Equal(s.StatusStartTime) {
		return s.Status.IsActive()
	}

	// Check history
	for i := len(s.History) - 1; i >= 0; i-- {
		h := s.History[i]
		if at.After(h.StatusStartTime) || at.Equal(h.StatusStartTime) {
			return h.Status.IsActive()
		}
	}

	return false
}

// MatchesCertificate checks if the service matches the given certificate.
func (s *TrustService) MatchesCertificate(cert *x509.Certificate) bool {
	for _, id := range s.ServiceDigitalIDs {
		if id.Certificate != nil && id.Certificate.Equal(cert) {
			return true
		}
		if len(id.SKI) > 0 && len(cert.SubjectKeyId) > 0 {
			if string(id.SKI) == string(cert.SubjectKeyId) {
				return true
			}
		}
	}
	return false
}

// TrustServiceProvider represents a trust service provider.
type TrustServiceProvider struct {
	Name        string
	TradeName   string
	Country     string
	Information *TSPInformation
	Services    []*TrustService
}

// TSPInformation contains additional TSP information.
type TSPInformation struct {
	Address        string
	Email          string
	URI            string
	InformationURI string
}

// FindService finds a service that matches the certificate.
func (tsp *TrustServiceProvider) FindService(cert *x509.Certificate) *TrustService {
	for _, service := range tsp.Services {
		if service.MatchesCertificate(cert) {
			return service
		}
	}
	return nil
}

// FindServiceByIssuer finds a service that could have issued the certificate.
func (tsp *TrustServiceProvider) FindServiceByIssuer(cert *x509.Certificate) *TrustService {
	for _, service := range tsp.Services {
		for _, id := range service.ServiceDigitalIDs {
			if id.Certificate != nil {
				if err := cert.CheckSignatureFrom(id.Certificate); err == nil {
					return service
				}
			}
		}
	}
	return nil
}

// TrustedList represents an EU Trusted List.
type TrustedList struct {
	SchemeOperatorName string
	SchemeTerritory    string
	ListIssueDateTime  time.Time
	NextUpdate         time.Time
	SequenceNumber     int
	Version            int
	TSPs               []*TrustServiceProvider
	PointersToOtherTSL []*TSLPointer
}

// TSLPointer represents a pointer to another trusted list.
type TSLPointer struct {
	Territory    string
	MimeType     string
	Location     string
	Certificates []*x509.Certificate
}

// IsExpired checks if the trusted list has expired.
func (tl *TrustedList) IsExpired() bool {
	return time.Now().After(tl.NextUpdate)
}

// IsValidAt checks if the trusted list was valid at the given time.
func (tl *TrustedList) IsValidAt(at time.Time) bool {
	return !at.Before(tl.ListIssueDateTime) && !at.After(tl.NextUpdate)
}

// FindTSP finds a TSP by name.
func (tl *TrustedList) FindTSP(name string) *TrustServiceProvider {
	nameLower := strings.ToLower(name)
	for _, tsp := range tl.TSPs {
		if strings.ToLower(tsp.Name) == nameLower {
			return tsp
		}
		if strings.ToLower(tsp.TradeName) == nameLower {
			return tsp
		}
	}
	return nil
}

// FindServiceForCertificate finds a service that matches the certificate.
func (tl *TrustedList) FindServiceForCertificate(cert *x509.Certificate) (*TrustServiceProvider, *TrustService) {
	for _, tsp := range tl.TSPs {
		if service := tsp.FindService(cert); service != nil {
			return tsp, service
		}
	}
	return nil, nil
}

// FindServiceForIssuer finds a service that could have issued the certificate.
func (tl *TrustedList) FindServiceForIssuer(cert *x509.Certificate) (*TrustServiceProvider, *TrustService) {
	for _, tsp := range tl.TSPs {
		if service := tsp.FindServiceByIssuer(cert); service != nil {
			return tsp, service
		}
	}
	return nil, nil
}

// TrustedListRegistry manages multiple trusted lists.
type TrustedListRegistry struct {
	mu    sync.RWMutex
	lists map[string]*TrustedList // keyed by territory
}

// NewTrustedListRegistry creates a new trusted list registry.
func NewTrustedListRegistry() *TrustedListRegistry {
	return &TrustedListRegistry{
		lists: make(map[string]*TrustedList),
	}
}

// Add adds a trusted list to the registry.
func (r *TrustedListRegistry) Add(list *TrustedList) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lists[list.SchemeTerritory] = list
}

// Get retrieves a trusted list by territory.
func (r *TrustedListRegistry) Get(territory string) *TrustedList {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lists[territory]
}

// GetAll returns all trusted lists.
func (r *TrustedListRegistry) GetAll() []*TrustedList {
	r.mu.RLock()
	defer r.mu.RUnlock()
	lists := make([]*TrustedList, 0, len(r.lists))
	for _, list := range r.lists {
		lists = append(lists, list)
	}
	return lists
}

// Territories returns all territory codes.
func (r *TrustedListRegistry) Territories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	territories := make([]string, 0, len(r.lists))
	for t := range r.lists {
		territories = append(territories, t)
	}
	return territories
}

// FindServiceForCertificate searches all lists for a matching service.
func (r *TrustedListRegistry) FindServiceForCertificate(cert *x509.Certificate) (*TrustedList, *TrustServiceProvider, *TrustService) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, list := range r.lists {
		if tsp, service := list.FindServiceForCertificate(cert); service != nil {
			return list, tsp, service
		}
	}
	return nil, nil, nil
}

// QualifiedAssessment represents the result of a qualified assessment.
type QualifiedAssessment struct {
	Certificate     *x509.Certificate
	QCStatements    *QCStatements
	Status          QualificationStatus
	QCType          QCType
	HasSSCD         bool
	HasQcCompliance bool
	TrustedList     *TrustedList
	TSP             *TrustServiceProvider
	Service         *TrustService
	ValidationTime  time.Time
	Legislation     []string
	Errors          []error
	Warnings        []string
}

// NewQualifiedAssessment creates a new qualified assessment.
func NewQualifiedAssessment(cert *x509.Certificate) *QualifiedAssessment {
	return &QualifiedAssessment{
		Certificate:    cert,
		Status:         StatusNotDetermined,
		ValidationTime: time.Now(),
	}
}

// IsQualified returns true if the certificate is qualified.
func (a *QualifiedAssessment) IsQualified() bool {
	return a.Status == StatusQualified || a.Status == StatusQualifiedAtIssuance
}

// AddError adds an error to the assessment.
func (a *QualifiedAssessment) AddError(err error) {
	a.Errors = append(a.Errors, err)
}

// AddWarning adds a warning to the assessment.
func (a *QualifiedAssessment) AddWarning(warning string) {
	a.Warnings = append(a.Warnings, warning)
}

// HasErrors returns true if there are any errors.
func (a *QualifiedAssessment) HasErrors() bool {
	return len(a.Errors) > 0
}

// QualifiedValidator validates qualified certificates.
type QualifiedValidator struct {
	Registry       *TrustedListRegistry
	AllowExpired   bool
	StrictMode     bool
	ValidationTime *time.Time
}

// NewQualifiedValidator creates a new qualified validator.
func NewQualifiedValidator(registry *TrustedListRegistry) *QualifiedValidator {
	return &QualifiedValidator{
		Registry: registry,
	}
}

// Assess performs a qualified assessment on a certificate.
func (v *QualifiedValidator) Assess(cert *x509.Certificate) *QualifiedAssessment {
	assessment := NewQualifiedAssessment(cert)

	if v.ValidationTime != nil {
		assessment.ValidationTime = *v.ValidationTime
	}

	// Parse QC statements
	qcStatements, err := ParseQCStatements(cert)
	if err != nil {
		assessment.AddWarning("No QC statements found in certificate")
	} else {
		assessment.QCStatements = qcStatements
		assessment.HasQcCompliance = qcStatements.HasCompliance()
		assessment.HasSSCD = qcStatements.HasSSCD()
		assessment.QCType = qcStatements.GetType()
		assessment.Legislation = qcStatements.GetLegislation()
	}

	// Check certificate against trusted lists
	if v.Registry != nil {
		list, tsp, service := v.Registry.FindServiceForCertificate(cert)
		if service != nil {
			assessment.TrustedList = list
			assessment.TSP = tsp
			assessment.Service = service

			// Check if service was active at validation time
			if service.IsActiveAt(assessment.ValidationTime) {
				if assessment.HasQcCompliance {
					assessment.Status = StatusQualified
				} else {
					assessment.Status = StatusQualifiedAtIssuance
					assessment.AddWarning("Certificate may be qualified at issuance but lacks QcCompliance")
				}
			} else {
				assessment.Status = StatusWithdrawn
				assessment.AddWarning("Service was not active at validation time")
			}
		} else {
			assessment.Status = StatusNotQualified
			assessment.AddError(ErrServiceNotFound)
		}
	} else {
		// No registry available, assess based on QC statements only
		if assessment.HasQcCompliance {
			assessment.Status = StatusQualified
			assessment.AddWarning("Assessment based on QC statements only (no trusted list available)")
		} else {
			assessment.Status = StatusNotDetermined
		}
	}

	return assessment
}

// AssessChain performs qualified assessment on a certificate chain.
func (v *QualifiedValidator) AssessChain(chain []*x509.Certificate) []*QualifiedAssessment {
	assessments := make([]*QualifiedAssessment, len(chain))
	for i, cert := range chain {
		assessments[i] = v.Assess(cert)
	}
	return assessments
}

// EUTLInfo contains information about the EU Trusted List of Lists.
type EUTLInfo struct {
	URL            string
	LastFetch      time.Time
	SchemeOperator string
	Pointers       []*TSLPointer
}

// DefaultEUTLURL is the official EU Trusted List of Lists URL.
const DefaultEUTLURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

// EUMemberStates is a list of EU member state country codes.
var EUMemberStates = []string{
	"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
	"FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
	"NL", "PL", "PT", "RO", "SE", "SI", "SK",
}

// IsEUMemberState checks if the country code is an EU member state.
func IsEUMemberState(countryCode string) bool {
	code := strings.ToUpper(countryCode)
	for _, ms := range EUMemberStates {
		if ms == code {
			return true
		}
	}
	return false
}

// CountryName returns the country name for an EU country code.
func CountryName(code string) string {
	names := map[string]string{
		"AT": "Austria", "BE": "Belgium", "BG": "Bulgaria",
		"CY": "Cyprus", "CZ": "Czech Republic", "DE": "Germany",
		"DK": "Denmark", "EE": "Estonia", "ES": "Spain",
		"FI": "Finland", "FR": "France", "GR": "Greece",
		"HR": "Croatia", "HU": "Hungary", "IE": "Ireland",
		"IT": "Italy", "LT": "Lithuania", "LU": "Luxembourg",
		"LV": "Latvia", "MT": "Malta", "NL": "Netherlands",
		"PL": "Poland", "PT": "Portugal", "RO": "Romania",
		"SE": "Sweden", "SI": "Slovenia", "SK": "Slovakia",
		"UK": "United Kingdom", "CH": "Switzerland", "NO": "Norway",
		"IS": "Iceland", "LI": "Liechtenstein",
	}
	return names[strings.ToUpper(code)]
}

// GetCertificateCountry attempts to extract the country from a certificate.
func GetCertificateCountry(cert *x509.Certificate) string {
	if len(cert.Subject.Country) > 0 {
		return cert.Subject.Country[0]
	}
	// Try to parse from Subject DN
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 6}) { // countryName
			if country, ok := name.Value.(string); ok {
				return country
			}
		}
	}
	return ""
}

// CertificatePolicy represents a certificate policy.
type CertificatePolicy struct {
	OID        asn1.ObjectIdentifier
	Qualifiers []PolicyQualifier
}

// PolicyQualifier represents a policy qualifier.
type PolicyQualifier struct {
	OID   asn1.ObjectIdentifier
	Value interface{}
}

// ParseCertificatePolicies parses certificate policies extension.
func ParseCertificatePolicies(cert *x509.Certificate) ([]CertificatePolicy, error) {
	oidCertPolicies := asn1.ObjectIdentifier{2, 5, 29, 32}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCertPolicies) {
			return parsePoliciesExtension(ext.Value)
		}
	}
	return nil, nil
}

func parsePoliciesExtension(data []byte) ([]CertificatePolicy, error) {
	var rawPolicies []asn1.RawValue
	if _, err := asn1.Unmarshal(data, &rawPolicies); err != nil {
		return nil, err
	}

	var policies []CertificatePolicy
	for _, raw := range rawPolicies {
		var policy struct {
			OID        asn1.ObjectIdentifier
			Qualifiers []asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &policy); err != nil {
			continue
		}
		policies = append(policies, CertificatePolicy{OID: policy.OID})
	}
	return policies, nil
}

// QualifiedPolicyOIDs contains OIDs for qualified certificate policies.
var QualifiedPolicyOIDs = struct {
	QCPPublic         asn1.ObjectIdentifier
	QCPPublicWithSSCD asn1.ObjectIdentifier
	QCPLegal          asn1.ObjectIdentifier
	QCPLegalQSCD      asn1.ObjectIdentifier
	QCPNatural        asn1.ObjectIdentifier
	QCPNaturalQSCD    asn1.ObjectIdentifier
	QCPWeb            asn1.ObjectIdentifier
}{
	QCPPublic:         asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 0},
	QCPPublicWithSSCD: asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 1},
	QCPLegal:          asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 2},
	QCPLegalQSCD:      asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 3},
	QCPNatural:        asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 4},
	QCPNaturalQSCD:    asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 5},
	QCPWeb:            asn1.ObjectIdentifier{0, 4, 0, 194112, 1, 6},
}

// HasQualifiedPolicy checks if a certificate has a qualified policy.
func HasQualifiedPolicy(cert *x509.Certificate) bool {
	policies, err := ParseCertificatePolicies(cert)
	if err != nil {
		return false
	}

	qualifiedOIDs := []asn1.ObjectIdentifier{
		QualifiedPolicyOIDs.QCPPublic,
		QualifiedPolicyOIDs.QCPPublicWithSSCD,
		QualifiedPolicyOIDs.QCPLegal,
		QualifiedPolicyOIDs.QCPLegalQSCD,
		QualifiedPolicyOIDs.QCPNatural,
		QualifiedPolicyOIDs.QCPNaturalQSCD,
		QualifiedPolicyOIDs.QCPWeb,
	}

	for _, policy := range policies {
		for _, qoid := range qualifiedOIDs {
			if policy.OID.Equal(qoid) {
				return true
			}
		}
	}
	return false
}

// ValidationReport contains the full validation report for a qualified signature.
type ValidationReport struct {
	SignatureTime    *time.Time
	ValidationTime   time.Time
	SignerAssessment *QualifiedAssessment
	ChainAssessments []*QualifiedAssessment
	IsQualifiedSig   bool
	IsAdvancedSig    bool
	Indication       string
	SubIndication    string
	Errors           []error
	Warnings         []string
}

// NewValidationReport creates a new validation report.
func NewValidationReport() *ValidationReport {
	return &ValidationReport{
		ValidationTime: time.Now(),
	}
}

// DetermineSignatureLevel determines if the signature is qualified or advanced.
func (r *ValidationReport) DetermineSignatureLevel() {
	// Reset values before computing
	r.IsQualifiedSig = false
	r.IsAdvancedSig = false

	if r.SignerAssessment == nil {
		return
	}

	// Qualified signature requires:
	// 1. Qualified certificate
	// 2. Created using a QSCD (Qualified Signature Creation Device)
	if r.SignerAssessment.IsQualified() && r.SignerAssessment.HasSSCD {
		r.IsQualifiedSig = true
		r.IsAdvancedSig = true
	} else if r.SignerAssessment.IsQualified() || r.SignerAssessment.HasQcCompliance {
		r.IsAdvancedSig = true
	}
}

// TSLLocation represents a trusted list location.
type TSLLocation struct {
	Territory string
	URL       *url.URL
	MimeType  string
}

// NewTSLLocation creates a new TSL location.
func NewTSLLocation(territory, urlStr, mimeType string) (*TSLLocation, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	return &TSLLocation{
		Territory: territory,
		URL:       u,
		MimeType:  mimeType,
	}, nil
}

// IssuerInfo extracts issuer information from a certificate.
type IssuerInfo struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	SerialNumber       string
}

// GetIssuerInfo extracts issuer information from a certificate.
func GetIssuerInfo(cert *x509.Certificate) *IssuerInfo {
	return &IssuerInfo{
		CommonName:         cert.Issuer.CommonName,
		Organization:       strings.Join(cert.Issuer.Organization, ", "),
		OrganizationalUnit: strings.Join(cert.Issuer.OrganizationalUnit, ", "),
		Country:            strings.Join(cert.Issuer.Country, ", "),
		SerialNumber:       cert.Issuer.SerialNumber,
	}
}

// SubjectInfo extracts subject information from a certificate.
type SubjectInfo struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	SerialNumber       string
	GivenName          string
	Surname            string
}

// GetSubjectInfo extracts subject information from a certificate.
func GetSubjectInfo(cert *x509.Certificate) *SubjectInfo {
	info := &SubjectInfo{
		CommonName:         cert.Subject.CommonName,
		Organization:       strings.Join(cert.Subject.Organization, ", "),
		OrganizationalUnit: strings.Join(cert.Subject.OrganizationalUnit, ", "),
		Country:            strings.Join(cert.Subject.Country, ", "),
		SerialNumber:       cert.Subject.SerialNumber,
	}

	// Try to extract given name and surname from Subject
	for _, name := range cert.Subject.Names {
		switch {
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 42}): // givenName
			if s, ok := name.Value.(string); ok {
				info.GivenName = s
			}
		case name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 4}): // surname
			if s, ok := name.Value.(string); ok {
				info.Surname = s
			}
		}
	}

	return info
}

// FullName returns the full name from subject info.
func (s *SubjectInfo) FullName() string {
	if s.GivenName != "" && s.Surname != "" {
		return s.GivenName + " " + s.Surname
	}
	if s.CommonName != "" {
		return s.CommonName
	}
	return s.Organization
}

// Helper to check if a certificate extension exists
func HasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// GetExtension retrieves an extension by OID.
func GetExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return &ext
		}
	}
	return nil
}
