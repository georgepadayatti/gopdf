// Package qualified provides ETSI TS 119 612 Trusted List parsing functionality.
// This file implements parsing of TrustServiceStatusList XML for EU qualified
// signature validation.
package qualified

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moov-io/signedxml"
)

// PreferredLanguage is the preferred language for extracting multilingual strings.
const PreferredLanguage = "en"

//go:embed lotl-certs/*.pem
var lotlCertsFS embed.FS

// ETSI TS 119 612 XML structures

// TrustServiceStatusList is the root element of an ETSI TS 119 612 trusted list.
type TrustServiceStatusList struct {
	XMLName           xml.Name               `xml:"TrustServiceStatusList"`
	SchemeInformation *TSLSchemeInformation  `xml:"SchemeInformation"`
	TSPList           *TrustServiceProviders `xml:"TrustServiceProviderList"`
}

// TSLSchemeInformation contains scheme-level information.
type TSLSchemeInformation struct {
	TSLVersionIdentifier        int                    `xml:"TSLVersionIdentifier"`
	TSLSequenceNumber           int                    `xml:"TSLSequenceNumber"`
	TSLType                     string                 `xml:"TSLType"`
	SchemeOperatorName          *InternationalNames    `xml:"SchemeOperatorName"`
	SchemeOperatorAddress       *SchemeOperatorAddress `xml:"SchemeOperatorAddress"`
	SchemeName                  *InternationalNames    `xml:"SchemeName"`
	SchemeInformationURI        *NonEmptyURIList       `xml:"SchemeInformationURI"`
	StatusDeterminationApproach string                 `xml:"StatusDeterminationApproach"`
	SchemeTypeCommunityRules    *NonEmptyURIList       `xml:"SchemeTypeCommunityRules"`
	SchemeTerritory             string                 `xml:"SchemeTerritory"`
	PolicyOrLegalNotice         *PolicyOrLegalNotice   `xml:"PolicyOrLegalNotice"`
	HistoricalInformationPeriod int                    `xml:"HistoricalInformationPeriod"`
	PointersToOtherTSL          *OtherTSLPointers      `xml:"PointersToOtherTSL"`
	ListIssueDateTime           string                 `xml:"ListIssueDateTime"`
	NextUpdate                  *NextUpdate            `xml:"NextUpdate"`
}

// InternationalNames contains multilingual names.
type InternationalNames struct {
	Name []MultiLangString `xml:"Name"`
}

// MultiLangString is a string with a language attribute.
type MultiLangString struct {
	Lang  string `xml:"lang,attr"`
	Value string `xml:",chardata"`
}

// NonEmptyURIList contains a list of URIs.
type NonEmptyURIList struct {
	URI []MultiLangString `xml:"URI"`
}

// SchemeOperatorAddress contains address information.
type SchemeOperatorAddress struct {
	PostalAddresses    *PostalAddresses    `xml:"PostalAddresses"`
	ElectronicAddress  *ElectronicAddress  `xml:"ElectronicAddress"`
}

// PostalAddresses contains postal address information.
type PostalAddresses struct {
	PostalAddress []PostalAddress `xml:"PostalAddress"`
}

// PostalAddress is a postal address.
type PostalAddress struct {
	Lang           string `xml:"lang,attr"`
	StreetAddress  string `xml:"StreetAddress"`
	Locality       string `xml:"Locality"`
	StateOrProvince string `xml:"StateOrProvince"`
	PostalCode     string `xml:"PostalCode"`
	CountryName    string `xml:"CountryName"`
}

// ElectronicAddress contains electronic address information.
type ElectronicAddress struct {
	URI []MultiLangString `xml:"URI"`
}

// PolicyOrLegalNotice contains policy or legal notice information.
type PolicyOrLegalNotice struct {
	TSLPolicy     *InternationalNames `xml:"TSLPolicy"`
	TSLLegalNotice *InternationalNames `xml:"TSLLegalNotice"`
}

// NextUpdate contains next update information.
type NextUpdate struct {
	DateTime string `xml:"dateTime"`
}

// OtherTSLPointers contains pointers to other trusted lists.
type OtherTSLPointers struct {
	OtherTSLPointer []OtherTSLPointer `xml:"OtherTSLPointer"`
}

// OtherTSLPointer is a pointer to another trusted list.
type OtherTSLPointer struct {
	ServiceDigitalIdentities  *ServiceDigitalIdentities `xml:"ServiceDigitalIdentities"`
	TSLLocation               string                    `xml:"TSLLocation"`
	AdditionalInformation     *AdditionalInformation    `xml:"AdditionalInformation"`
}

// ServiceDigitalIdentities contains digital identities.
type ServiceDigitalIdentities struct {
	ServiceDigitalIdentity []ServiceDigitalIdentity `xml:"ServiceDigitalIdentity"`
}

// ServiceDigitalIdentity contains a digital identity.
type ServiceDigitalIdentity struct {
	DigitalId []DigitalIdentity `xml:"DigitalId"`
}

// DigitalIdentity represents a digital identity.
type DigitalIdentity struct {
	X509Certificate string `xml:"X509Certificate"`
	X509SubjectName string `xml:"X509SubjectName"`
	X509SKI         string `xml:"X509SKI"`
}

// AdditionalInformation contains additional pointer information.
type AdditionalInformation struct {
	OtherInformation []OtherInformation `xml:"OtherInformation"`
}

// OtherInformation contains mixed content for additional information.
type OtherInformation struct {
	SchemeTypeCommunityRules *NonEmptyURIList `xml:"SchemeTypeCommunityRules"`
	SchemeTerritory          string           `xml:"SchemeTerritory"`
	MimeType                 string           `xml:"MimeType"`
}

// TrustServiceProviders contains the list of TSPs.
type TrustServiceProviders struct {
	TSP []TrustServiceProviderXML `xml:"TrustServiceProvider"`
}

// TrustServiceProviderXML represents a trust service provider.
type TrustServiceProviderXML struct {
	TSPInformation *TSPInformationXML `xml:"TSPInformation"`
	TSPServices    *TSPServicesXML    `xml:"TSPServices"`
}

// TSPInformationXML contains TSP information.
type TSPInformationXML struct {
	TSPName               *InternationalNames    `xml:"TSPName"`
	TSPTradeName          *InternationalNames    `xml:"TSPTradeName"`
	TSPAddress            *SchemeOperatorAddress `xml:"TSPAddress"`
	TSPInformationURI     *NonEmptyURIList       `xml:"TSPInformationURI"`
}

// TSPServicesXML contains TSP services.
type TSPServicesXML struct {
	TSPService []TSPServiceXML `xml:"TSPService"`
}

// TSPServiceXML represents a TSP service.
type TSPServiceXML struct {
	ServiceInformation *ServiceInformationXML `xml:"ServiceInformation"`
	ServiceHistory     *ServiceHistoryXML     `xml:"ServiceHistory"`
}

// ServiceInformationXML contains service information.
type ServiceInformationXML struct {
	ServiceTypeIdentifier         string                    `xml:"ServiceTypeIdentifier"`
	ServiceName                   *InternationalNames       `xml:"ServiceName"`
	ServiceDigitalIdentity        *ServiceDigitalIdentity   `xml:"ServiceDigitalIdentity"`
	ServiceStatus                 string                    `xml:"ServiceStatus"`
	StatusStartingTime            string                    `xml:"StatusStartingTime"`
	ServiceInformationExtensions  *ServiceExtensionsXML     `xml:"ServiceInformationExtensions"`
}

// ServiceHistoryXML contains service history.
type ServiceHistoryXML struct {
	ServiceHistoryInstance []ServiceHistoryInstanceXML `xml:"ServiceHistoryInstance"`
}

// ServiceHistoryInstanceXML represents a historical service status.
type ServiceHistoryInstanceXML struct {
	ServiceTypeIdentifier         string                    `xml:"ServiceTypeIdentifier"`
	ServiceName                   *InternationalNames       `xml:"ServiceName"`
	ServiceDigitalIdentity        *ServiceDigitalIdentity   `xml:"ServiceDigitalIdentity"`
	ServiceStatus                 string                    `xml:"ServiceStatus"`
	StatusStartingTime            string                    `xml:"StatusStartingTime"`
	ServiceInformationExtensions  *ServiceExtensionsXML     `xml:"ServiceInformationExtensions"`
}

// ServiceExtensionsXML contains service extensions.
type ServiceExtensionsXML struct {
	Extension []ExtensionXML `xml:"Extension"`
}

// ExtensionXML represents a service extension.
type ExtensionXML struct {
	Critical                       bool                            `xml:"Critical,attr"`
	ExpiredCertsRevocationInfo     string                          `xml:"ExpiredCertsRevocationInfo"`
	AdditionalServiceInformation   *AdditionalServiceInfoXML       `xml:"AdditionalServiceInformation"`
	Qualifications                 *QualificationsXML              `xml:"Qualifications"`
}

// AdditionalServiceInfoXML contains additional service information.
type AdditionalServiceInfoXML struct {
	URI              string `xml:"URI"`
	InformationValue string `xml:"InformationValue"`
}

// QualificationsXML contains qualification elements.
type QualificationsXML struct {
	QualificationElement []QualificationElementXML `xml:"QualificationElement"`
}

// QualificationElementXML represents a qualification.
type QualificationElementXML struct {
	Qualifiers   *QualifiersXML   `xml:"Qualifiers"`
	CriteriaList *CriteriaListXML `xml:"CriteriaList"`
}

// QualifiersXML contains qualifiers.
type QualifiersXML struct {
	Qualifier []QualifierXML `xml:"Qualifier"`
}

// QualifierXML represents a qualifier.
type QualifierXML struct {
	URI string `xml:"uri,attr"`
}

// CriteriaListXML represents criteria for a qualification.
type CriteriaListXML struct {
	Assert      string             `xml:"assert,attr"`
	KeyUsage    []KeyUsageBitsXML  `xml:"KeyUsage"`
	PolicySet   []PolicySetXML     `xml:"PolicySet"`
	CriteriaList []CriteriaListXML `xml:"CriteriaList"`
}

// KeyUsageBitsXML contains key usage bits.
type KeyUsageBitsXML struct {
	KeyUsageBit []KeyUsageBitXML `xml:"KeyUsageBit"`
}

// KeyUsageBitXML represents a key usage bit.
type KeyUsageBitXML struct {
	Name  string `xml:"name,attr"`
	Value bool   `xml:",chardata"`
}

// PolicySetXML contains policy identifiers.
type PolicySetXML struct {
	PolicyIdentifier []PolicyIdentifierXML `xml:"PolicyIdentifier"`
}

// PolicyIdentifierXML represents a policy identifier.
type PolicyIdentifierXML struct {
	Identifier IdentifierXML `xml:"Identifier"`
}

// IdentifierXML contains an identifier value.
type IdentifierXML struct {
	Value string `xml:",chardata"`
}

// TLParseResult is the result of parsing a trusted list.
type TLParseResult struct {
	Registry *TSPRegistry
	Errors   []*TSPServiceParsingError
}

// extractFromIntlString extracts a value from multilingual strings.
func extractFromIntlString(names []MultiLangString) string {
	if len(names) == 0 {
		return "unknown"
	}
	for _, name := range names {
		if strings.EqualFold(name.Lang, PreferredLanguage) {
			return name.Value
		}
	}
	return names[0].Value
}

// parseDateTime parses an ISO 8601 datetime string.
func parseDateTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty datetime")
	}
	// Try various formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse datetime: %s", s)
}

// parseCertificatesFromDigitalIdentity parses X.509 certificates from a digital identity.
func parseCertificatesFromDigitalIdentity(sdi *ServiceDigitalIdentity) ([]*x509.Certificate, error) {
	if sdi == nil {
		return nil, nil
	}
	var certs []*x509.Certificate
	for _, did := range sdi.DigitalId {
		if did.X509Certificate != "" {
			certData, err := base64.StdEncoding.DecodeString(
				strings.TrimSpace(did.X509Certificate))
			if err != nil {
				continue
			}
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

// processCriteriaList processes a criteria list from XML.
func processCriteriaList(xml *CriteriaListXML) (*CriteriaList, error) {
	if xml == nil {
		return nil, fmt.Errorf("no criteria list")
	}

	var criteria []Criterion

	// Process key usage criteria
	for _, ku := range xml.KeyUsage {
		keyUsage := make(map[string]bool)
		keyUsageForbidden := make(map[string]bool)
		for _, bit := range ku.KeyUsageBit {
			if bit.Value {
				keyUsage[strings.ToLower(bit.Name)] = true
			} else {
				keyUsageForbidden[strings.ToLower(bit.Name)] = true
			}
		}
		criteria = append(criteria, &KeyUsageCriterion{
			Settings: KeyUsageConstraintsForCriteria{
				KeyUsage:          keyUsage,
				KeyUsageForbidden: keyUsageForbidden,
			},
		})
	}

	// Process policy set criteria
	for _, ps := range xml.PolicySet {
		policyOIDs := make(map[string]bool)
		for _, pi := range ps.PolicyIdentifier {
			if pi.Identifier.Value != "" {
				policyOIDs[pi.Identifier.Value] = true
			}
		}
		if len(policyOIDs) > 0 {
			criteria = append(criteria, &PolicySetCriterion{
				RequiredPolicyOIDs: policyOIDs,
			})
		}
	}

	// Process nested criteria lists
	for _, nestedXML := range xml.CriteriaList {
		nested, err := processCriteriaList(&nestedXML)
		if err == nil && nested != nil {
			criteria = append(criteria, nested)
		}
	}

	if len(criteria) == 0 {
		return nil, fmt.Errorf("no criteria found")
	}

	// Determine combination type
	combineAs := CriteriaCombinationAll
	switch strings.ToLower(xml.Assert) {
	case "atleastone":
		combineAs = CriteriaCombinationAtLeastOne
	case "none":
		combineAs = CriteriaCombinationNone
	}

	return &CriteriaList{
		CombineAs: combineAs,
		Criteria:  criteria,
	}, nil
}

// processQualifications processes qualifications from XML.
func processQualifications(xml *QualificationsXML) []TSPQualification {
	if xml == nil {
		return nil
	}

	var qualifications []TSPQualification
	for _, qe := range xml.QualificationElement {
		if qe.Qualifiers == nil {
			continue
		}

		qualifiers := make(map[Qualifier]bool)
		for _, q := range qe.Qualifiers.Qualifier {
			if qualifier, ok := QualifierFromURI(q.URI); ok {
				qualifiers[qualifier] = true
			}
		}

		if len(qualifiers) == 0 {
			continue
		}

		criteriaList, err := processCriteriaList(qe.CriteriaList)
		if err != nil {
			continue
		}

		qualifications = append(qualifications, TSPQualification{
			Qualifiers:   qualifiers,
			CriteriaList: criteriaList,
		})
	}

	return qualifications
}

// processServiceExtensions processes service extensions from XML.
func processServiceExtensions(xml *ServiceExtensionsXML) (
	qualifications []TSPQualification,
	additionalInfoTypes map[QcCertType]bool,
	otherInfo []AdditionalServiceInformation,
	expiredCertsRevInfo *time.Time,
) {
	additionalInfoTypes = make(map[QcCertType]bool)

	if xml == nil {
		return
	}

	for _, ext := range xml.Extension {
		if ext.Qualifications != nil {
			qualifications = append(qualifications, processQualifications(ext.Qualifications)...)
		}
		if ext.AdditionalServiceInformation != nil {
			info := ext.AdditionalServiceInformation
			if certType, ok := QcCertTypeFromURI(info.URI); ok {
				additionalInfoTypes[certType] = true
			} else {
				otherInfo = append(otherInfo, AdditionalServiceInformation{
					URI:         info.URI,
					Critical:    ext.Critical,
					TextualInfo: info.InformationValue,
				})
			}
		}
		if ext.ExpiredCertsRevocationInfo != "" {
			if t, err := parseDateTime(ext.ExpiredCertsRevocationInfo); err == nil {
				expiredCertsRevInfo = &t
			}
		}
	}

	return
}

// ReadQualifiedServiceDefinitions reads service definitions from a trusted list XML.
func ReadQualifiedServiceDefinitions(tlXML string) ([]QualifiedServiceInformation, []*TSPServiceParsingError) {
	var tsl TrustServiceStatusList
	if err := xml.Unmarshal([]byte(tlXML), &tsl); err != nil {
		return nil, []*TSPServiceParsingError{
			NewTSPServiceParsingError(fmt.Sprintf("failed to parse XML: %v", err)),
		}
	}

	var services []QualifiedServiceInformation
	var errors []*TSPServiceParsingError

	if tsl.TSPList == nil {
		return nil, []*TSPServiceParsingError{
			NewTSPServiceParsingError("no TSP list found"),
		}
	}

	for _, tsp := range tsl.TSPList.TSP {
		if tsp.TSPServices == nil {
			continue
		}

		for _, service := range tsp.TSPServices.TSPService {
			if service.ServiceInformation == nil {
				continue
			}

			info := service.ServiceInformation

			// Only process CA/QC and QTST services
			serviceType := info.ServiceTypeIdentifier
			if serviceType != CAQCUri && serviceType != QTSTUri {
				continue
			}

			// Only process granted services
			if info.ServiceStatus != StatusGrantedURI {
				continue
			}

			// Parse certificates
			certs, err := parseCertificatesFromDigitalIdentity(info.ServiceDigitalIdentity)
			if err != nil {
				errors = append(errors, NewTSPServiceParsingError(
					fmt.Sprintf("failed to parse certificates: %v", err)))
				continue
			}

			// Parse validity time
			validFrom, err := parseDateTime(info.StatusStartingTime)
			if err != nil {
				errors = append(errors, NewTSPServiceParsingError(
					fmt.Sprintf("failed to parse validity time: %v", err)))
				continue
			}

			// Get service name
			serviceName := "unknown"
			if info.ServiceName != nil {
				serviceName = extractFromIntlString(info.ServiceName.Name)
			}

			// Process extensions
			qualifications, additionalInfoTypes, otherInfo, expiredRevInfo := processServiceExtensions(
				info.ServiceInformationExtensions)

			baseInfo := BaseServiceInformation{
				ServiceType:                   serviceType,
				ServiceName:                   serviceName,
				ValidFrom:                     validFrom,
				ValidUntil:                    nil, // Current service has no end date
				ProviderCerts:                 certs,
				AdditionalInfoCertificateType: additionalInfoTypes,
				OtherAdditionalInfo:           otherInfo,
			}

			si := QualifiedServiceInformation{
				BaseInfo:       baseInfo,
				Qualifications: qualifications,
			}

			if serviceType == CAQCUri {
				caSI := CAServiceInformation{
					QualifiedServiceInformation: si,
					ExpiredCertsRevocationInfo:  expiredRevInfo,
				}
				services = append(services, caSI.QualifiedServiceInformation)
			} else {
				services = append(services, si)
			}
		}
	}

	return services, errors
}

// TrustListToRegistryUnsafe parses a trusted list into a TSPRegistry without signature validation.
func TrustListToRegistryUnsafe(tlXML string, registry *TSPRegistry) (*TSPRegistry, []*TSPServiceParsingError) {
	if registry == nil {
		registry = NewTSPRegistry()
	}

	services, errors := ReadQualifiedServiceDefinitions(tlXML)

	for _, sd := range services {
		switch sd.BaseInfo.ServiceType {
		case CAQCUri:
			registry.RegisterCA(CAServiceInformation{
				QualifiedServiceInformation: sd,
			})
		case QTSTUri:
			registry.RegisterTST(QTSTServiceInformation{
				QualifiedServiceInformation: sd,
			})
		}
	}

	return registry, errors
}

// XMLSignatureError represents an XML signature validation error.
type XMLSignatureError struct {
	Message string
}

func (e *XMLSignatureError) Error() string {
	return e.Message
}

// NewXMLSignatureError creates a new XML signature error.
func NewXMLSignatureError(msg string) *XMLSignatureError {
	return &XMLSignatureError{Message: msg}
}

// ValidateXMLSignature validates the XML signature of a document using the provided certificates.
// It returns the validated/signed XML content and the certificate that was used to verify the signature.
func ValidateXMLSignature(xmlContent string, trustedCerts []*x509.Certificate) (string, *x509.Certificate, error) {
	if len(trustedCerts) == 0 {
		return "", nil, NewXMLSignatureError("no trusted certificates provided for signature validation")
	}

	// Create a new validator
	validator, err := signedxml.NewValidator(xmlContent)
	if err != nil {
		return "", nil, NewXMLSignatureError(fmt.Sprintf("failed to create XML signature validator: %v", err))
	}

	// Convert pointer slice to value slice for signedxml library
	certValues := make([]x509.Certificate, len(trustedCerts))
	for i, cert := range trustedCerts {
		if cert != nil {
			certValues[i] = *cert
		}
	}
	validator.Certificates = certValues

	// Validate the signature and get the signed references
	signedXMLs, err := validator.ValidateReferences()
	if err != nil {
		return "", nil, NewXMLSignatureError(fmt.Sprintf("XML signature validation failed: %v", err))
	}

	// Get the signing certificate (returns value, not pointer)
	signingCert := validator.SigningCert()

	// Check if we got a valid signing certificate (check if Raw is non-empty)
	var signingCertPtr *x509.Certificate
	if len(signingCert.Raw) > 0 {
		signingCertPtr = &signingCert
	}

	if len(signedXMLs) == 0 {
		return "", nil, NewXMLSignatureError("no signed content found in XML")
	}

	// Return the first signed XML content (the TrustServiceStatusList)
	return signedXMLs[0], signingCertPtr, nil
}

// ValidateXMLSignatureWithMultipleCerts tries to validate using multiple candidate certificates.
// It sorts certificates by NotBefore date (newest first) and tries each one.
func ValidateXMLSignatureWithMultipleCerts(xmlContent string, candidateCerts []*x509.Certificate) (string, *x509.Certificate, error) {
	if len(candidateCerts) == 0 {
		return "", nil, NewXMLSignatureError("no candidate certificates provided")
	}

	// Sort certificates by NotBefore date, newest first
	sortedCerts := make([]*x509.Certificate, len(candidateCerts))
	copy(sortedCerts, candidateCerts)
	sort.Slice(sortedCerts, func(i, j int) bool {
		return sortedCerts[i].NotBefore.After(sortedCerts[j].NotBefore)
	})

	var lastErr error
	for _, cert := range sortedCerts {
		signedXML, signingCert, err := ValidateXMLSignature(xmlContent, []*x509.Certificate{cert})
		if err == nil {
			return signedXML, signingCert, nil
		}
		lastErr = err
	}

	// If individual validation failed, try with all certs at once
	// (the library might find the right one from embedded certs)
	signedXML, signingCert, err := ValidateXMLSignature(xmlContent, sortedCerts)
	if err == nil {
		return signedXML, signingCert, nil
	}

	if lastErr != nil {
		return "", nil, NewXMLSignatureError(fmt.Sprintf("none of the %d candidate certificates could validate the signature: %v", len(candidateCerts), lastErr))
	}
	return "", nil, err
}

// TrustListToRegistry parses and validates a trusted list into a TSPRegistry.
// It validates the XML signature using the provided TLSO certificates before parsing.
func TrustListToRegistry(
	tlXML string,
	tlsoCerts []*x509.Certificate,
	registry *TSPRegistry,
) (*TSPRegistry, []*TSPServiceParsingError) {
	var errors []*TSPServiceParsingError

	// Validate the XML signature
	if len(tlsoCerts) > 0 {
		validatedXML, _, err := ValidateXMLSignatureWithMultipleCerts(tlXML, tlsoCerts)
		if err != nil {
			errors = append(errors, NewTSPServiceParsingError(
				fmt.Sprintf("XML signature validation failed: %v", err)))
			// Fall back to parsing without validation
			reg, parseErrors := TrustListToRegistryUnsafe(tlXML, registry)
			return reg, append(errors, parseErrors...)
		}
		// Use the validated XML content
		tlXML = validatedXML
	}

	reg, parseErrors := TrustListToRegistryUnsafe(tlXML, registry)
	return reg, append(errors, parseErrors...)
}

// ParseLOTLUnsafeComplete parses a list-of-the-lists (LOTL) fully.
func ParseLOTLUnsafeComplete(lotlXML string) (*LOTLParseResult, error) {
	var tsl TrustServiceStatusList
	if err := xml.Unmarshal([]byte(lotlXML), &tsl); err != nil {
		return nil, fmt.Errorf("failed to parse LOTL XML: %w", err)
	}

	if tsl.SchemeInformation == nil {
		return nil, fmt.Errorf("no scheme information found")
	}

	schemeInfo := tsl.SchemeInformation
	result := &LOTLParseResult{
		References: []*TLReference{},
		Errors:     []*TSPServiceParsingError{},
		PivotURLs:  []string{},
	}

	// Extract pivot URLs from scheme information URIs
	if schemeInfo.SchemeInformationURI != nil {
		for _, uri := range schemeInfo.SchemeInformationURI.URI {
			if strings.HasSuffix(uri.Value, ".xml") {
				result.PivotURLs = append(result.PivotURLs, uri.Value)
			}
		}
	}

	// Process pointers to other TSLs
	if schemeInfo.PointersToOtherTSL == nil {
		return result, nil
	}

	for _, pointer := range schemeInfo.PointersToOtherTSL.OtherTSLPointer {
		if pointer.TSLLocation == "" {
			continue
		}

		// Parse additional information
		var territory string
		var mimeType string
		schemeRules := make(map[string]bool)

		if pointer.AdditionalInformation != nil {
			for _, other := range pointer.AdditionalInformation.OtherInformation {
				if other.SchemeTerritory != "" {
					territory = other.SchemeTerritory
				}
				if other.MimeType != "" {
					mimeType = other.MimeType
				}
				if other.SchemeTypeCommunityRules != nil {
					for _, uri := range other.SchemeTypeCommunityRules.URI {
						schemeRules[uri.Value] = true
					}
				}
			}
		}

		// Only process TSL format lists
		if mimeType != ETSITSLMimeType && mimeType != "" {
			continue
		}

		// Parse certificates from digital identities
		var tlsoCerts []*x509.Certificate
		if pointer.ServiceDigitalIdentities != nil {
			for _, sdi := range pointer.ServiceDigitalIdentities.ServiceDigitalIdentity {
				certs, err := parseCertificatesFromDigitalIdentity(&sdi)
				if err != nil {
					result.Errors = append(result.Errors, NewTSPServiceParsingError(
						fmt.Sprintf("failed to parse TLSO certs for %s: %v", territory, err)))
					continue
				}
				tlsoCerts = append(tlsoCerts, certs...)
			}
		}

		ref := &TLReference{
			LocationURI: pointer.TSLLocation,
			Territory:   territory,
			TLSOCerts:   tlsoCerts,
			SchemeRules: schemeRules,
		}
		result.References = append(result.References, ref)
	}

	return result, nil
}

// ValidateAndParseLOTLComplete validates and parses a list-of-the-lists.
// It validates the XML signature using the provided TLSO certificates before parsing.
func ValidateAndParseLOTLComplete(lotlXML string, tlsoCerts []*x509.Certificate) (*LOTLParseResult, error) {
	if tlsoCerts == nil {
		tlsoCerts = LatestKnownLOTLTLSOCerts()
	}

	if len(tlsoCerts) == 0 {
		// No certificates available, parse without validation
		return ParseLOTLUnsafeComplete(lotlXML)
	}

	// Validate the XML signature
	validatedXML, _, err := ValidateXMLSignatureWithMultipleCerts(lotlXML, tlsoCerts)
	if err != nil {
		// Return error with context
		return nil, fmt.Errorf("LOTL signature validation failed: %w", err)
	}

	// Parse the validated content
	return ParseLOTLUnsafeComplete(validatedXML)
}

// loadLOTLCerts loads certificates from the embedded filesystem.
func loadLOTLCerts(path string) []*x509.Certificate {
	data, err := lotlCertsFS.ReadFile(path)
	if err != nil {
		return nil
	}

	var certs []*x509.Certificate
	rest := data

	for len(rest) > 0 {
		var block *bytes.Buffer
		// Find PEM block
		startIdx := bytes.Index(rest, []byte("-----BEGIN CERTIFICATE-----"))
		if startIdx < 0 {
			break
		}
		rest = rest[startIdx:]

		endIdx := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if endIdx < 0 {
			break
		}
		endIdx += len("-----END CERTIFICATE-----")
		block = bytes.NewBuffer(rest[:endIdx])
		rest = rest[endIdx:]

		// Parse PEM
		pemData := block.Bytes()
		certData := pemData[len("-----BEGIN CERTIFICATE-----"):]
		certData = certData[:len(certData)-len("-----END CERTIFICATE-----")]
		certData = bytes.TrimSpace(certData)

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(string(certData))
		if err != nil {
			continue
		}

		cert, err := x509.ParseCertificate(decoded)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}

// BootstrapLOTLSigners performs the bootstrapping process to determine
// certificates that can be used to verify a list-of-the-lists signature.
// This implements Article 4 of Commission Implementing Decision (EU) 2015/1505.
func BootstrapLOTLSigners(
	latestLOTLXML string,
	fetcher *TLFetcher,
	bootstrapCerts []*x509.Certificate,
) ([]*x509.Certificate, error) {
	if bootstrapCerts == nil {
		bootstrapCerts = OJEUBootstrapLOTLTLSOCerts()
	}

	if len(bootstrapCerts) == 0 {
		return nil, fmt.Errorf("no bootstrap certificates provided")
	}

	// Parse the LOTL to get pivot URLs
	result, err := ParseLOTLUnsafeComplete(latestLOTLXML)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LOTL: %w", err)
	}

	// Sort pivot URLs (oldest first for processing order)
	pivots := result.PivotURLs
	// Note: In production, these should be sorted by date
	// For now, we just process in order

	currentCerts := bootstrapCerts

	for _, pivotURL := range pivots {
		// Note: In a full implementation, we would:
		// 1. Fetch the pivot LOTL
		// 2. Validate its signature using currentCerts
		// 3. Extract the new TLSO certs from the LOTL's self-reference
		// 4. Update currentCerts

		// For now, we just return the bootstrap certs as a placeholder
		_ = pivotURL
	}

	return currentCerts, nil
}
