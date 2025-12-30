// Package etsi provides ETSI XML structures.
// This file contains structures for ETSI TS 119.612 Trusted Lists.
//
// ETSI TS 119.612 specifies the XML format for Trusted Lists of
// Trust Service Providers in the European Union.
package etsi

import (
	"encoding/xml"
	"time"

	"github.com/georgepadayatti/gopdf/generated/w3c"
)

// TS119612 namespace
const TS119612Namespace = "http://uri.etsi.org/02231/v2#"

// TSLAnyType contains wildcard content.
type TSLAnyType struct {
	Content []byte `xml:",innerxml"`
}

// AttributedNonEmptyURIType is a URI with optional type attribute.
type AttributedNonEmptyURIType struct {
	Value    string `xml:",chardata"`
	TypeAttr string `xml:"type,attr,omitempty"`
}

// ExpiredCertsRevocationInfo contains expiration info for revoked certs.
type ExpiredCertsRevocationInfo struct {
	XMLName xml.Name   `xml:"http://uri.etsi.org/02231/v2# ExpiredCertsRevocationInfo"`
	Value   *time.Time `xml:",chardata"`
}

// NextUpdateType contains the next update time.
type NextUpdateType struct {
	DateTime *time.Time `xml:"dateTime,omitempty"`
}

// NextUpdate is the element form of NextUpdateType.
type NextUpdate struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# NextUpdate"`
	NextUpdateType
}

// NonEmptyURIListType contains a list of URIs.
type NonEmptyURIListType struct {
	URI []string `xml:"URI"`
}

// SchemeTerritory identifies the territory.
type SchemeTerritory struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# SchemeTerritory"`
	Value   string   `xml:",chardata"`
}

// ServiceStatus identifies the service status.
type ServiceStatus struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceStatus"`
	Value   string   `xml:",chardata"`
}

// ServiceTypeIdentifier identifies the service type.
type ServiceTypeIdentifier struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceTypeIdentifier"`
	Value   string   `xml:",chardata"`
}

// TSLType identifies the TSL type.
type TSLType struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TSLType"`
	Value   string   `xml:",chardata"`
}

// DigitalIdentityType contains digital identity information.
type DigitalIdentityType struct {
	X509Certificate []byte         `xml:"X509Certificate,omitempty"`
	X509SubjectName string         `xml:"X509SubjectName,omitempty"`
	KeyValue        *w3c.KeyValue  `xml:"http://www.w3.org/2000/09/xmldsig# KeyValue,omitempty"`
	X509SKI         []byte         `xml:"X509SKI,omitempty"`
	Other           *TSLAnyType    `xml:"Other,omitempty"`
}

// DistributionPoints is a list of distribution point URIs.
type DistributionPoints struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# DistributionPoints"`
	NonEmptyURIListType
}

// ExtensionType contains an extension with criticality.
type ExtensionType struct {
	TSLAnyType
	Critical bool `xml:"Critical,attr"`
}

// Extension is the element form of ExtensionType.
type Extension struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# Extension"`
	ExtensionType
}

// MultiLangNormStringType is a normalized string with language.
type MultiLangNormStringType struct {
	Value string `xml:",chardata"`
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
}

// MultiLangStringType is a string with language.
type MultiLangStringType struct {
	Value string `xml:",chardata"`
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
}

// NonEmptyMultiLangURIType is a URI with language.
type NonEmptyMultiLangURIType struct {
	Value string `xml:",chardata"`
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
}

// PostalAddressType contains postal address information.
type PostalAddressType struct {
	StreetAddress   string `xml:"StreetAddress"`
	Locality        string `xml:"Locality"`
	StateOrProvince string `xml:"StateOrProvince,omitempty"`
	PostalCode      string `xml:"PostalCode,omitempty"`
	CountryName     string `xml:"CountryName"`
	Lang            string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
}

// PostalAddress is the element form of PostalAddressType.
type PostalAddress struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# PostalAddress"`
	PostalAddressType
}

// ServiceSupplyPointsType contains service supply points.
type ServiceSupplyPointsType struct {
	ServiceSupplyPoint []AttributedNonEmptyURIType `xml:"ServiceSupplyPoint"`
}

// ServiceSupplyPoints is the element form.
type ServiceSupplyPoints struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceSupplyPoints"`
	ServiceSupplyPointsType
}

// AdditionalInformationType contains additional information.
type AdditionalInformationType struct {
	TextualInformation []MultiLangStringType `xml:"TextualInformation,omitempty"`
	OtherInformation   []TSLAnyType          `xml:"OtherInformation,omitempty"`
}

// AdditionalInformation is the element form.
type AdditionalInformation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# AdditionalInformation"`
	AdditionalInformationType
}

// AdditionalServiceInformationType contains additional service information.
type AdditionalServiceInformationType struct {
	URI              *NonEmptyMultiLangURIType `xml:"URI"`
	InformationValue string                    `xml:"InformationValue,omitempty"`
	OtherInformation *TSLAnyType               `xml:"OtherInformation,omitempty"`
}

// AdditionalServiceInformation is the element form.
type AdditionalServiceInformation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# AdditionalServiceInformation"`
	AdditionalServiceInformationType
}

// DigitalIdentityListType contains a list of digital identities.
type DigitalIdentityListType struct {
	DigitalId []DigitalIdentityType `xml:"DigitalId,omitempty"`
}

// ElectronicAddressType contains electronic address URIs.
type ElectronicAddressType struct {
	URI []NonEmptyMultiLangURIType `xml:"URI"`
}

// ElectronicAddress is the element form.
type ElectronicAddress struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ElectronicAddress"`
	ElectronicAddressType
}

// InternationalNamesType contains names in multiple languages.
type InternationalNamesType struct {
	Name []MultiLangNormStringType `xml:"Name"`
}

// NonEmptyMultiLangURIListType contains URIs with languages.
type NonEmptyMultiLangURIListType struct {
	URI []NonEmptyMultiLangURIType `xml:"URI"`
}

// PolicyOrLegalnoticeType contains policy or legal notice.
type PolicyOrLegalnoticeType struct {
	TSLPolicy     []NonEmptyMultiLangURIType `xml:"TSLPolicy,omitempty"`
	TSLLegalNotice []MultiLangStringType     `xml:"TSLLegalNotice,omitempty"`
}

// PolicyOrLegalNotice is the element form.
type PolicyOrLegalNotice struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# PolicyOrLegalNotice"`
	PolicyOrLegalnoticeType
}

// PostalAddressListType contains a list of postal addresses.
type PostalAddressListType struct {
	PostalAddress []PostalAddress `xml:"PostalAddress"`
}

// PostalAddresses is the element form.
type PostalAddresses struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# PostalAddresses"`
	PostalAddressListType
}

// SchemeInformationURI is the scheme information URI list.
type SchemeInformationURI struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# SchemeInformationURI"`
	NonEmptyMultiLangURIListType
}

// SchemeName is the scheme name.
type SchemeName struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# SchemeName"`
	InternationalNamesType
}

// SchemeOperatorName is the scheme operator name.
type SchemeOperatorName struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# SchemeOperatorName"`
	InternationalNamesType
}

// SchemeTypeCommunityRules contains community rules URIs.
type SchemeTypeCommunityRules struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# SchemeTypeCommunityRules"`
	NonEmptyMultiLangURIListType
}

// ServiceDigitalIdentity contains digital identity for a service.
type ServiceDigitalIdentity struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceDigitalIdentity"`
	DigitalIdentityListType
}

// ExtensionsListType contains a list of extensions.
type ExtensionsListType struct {
	Extension []Extension `xml:"Extension"`
}

// ServiceDigitalIdentityListType contains multiple service digital identities.
type ServiceDigitalIdentityListType struct {
	ServiceDigitalIdentity []ServiceDigitalIdentity `xml:"ServiceDigitalIdentity"`
}

// ServiceDigitalIdentities is the element form.
type ServiceDigitalIdentities struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceDigitalIdentities"`
	ServiceDigitalIdentityListType
}

// ServiceHistoryInstanceType contains service history.
type ServiceHistoryInstanceType struct {
	ServiceTypeIdentifier        *ServiceTypeIdentifier  `xml:"ServiceTypeIdentifier"`
	ServiceName                  *InternationalNamesType `xml:"ServiceName"`
	ServiceDigitalIdentity       *ServiceDigitalIdentity `xml:"ServiceDigitalIdentity"`
	ServiceStatus                *ServiceStatus          `xml:"ServiceStatus"`
	StatusStartingTime           *time.Time              `xml:"StatusStartingTime"`
	ServiceInformationExtensions *ExtensionsListType     `xml:"ServiceInformationExtensions,omitempty"`
}

// ServiceHistoryInstance is the element form.
type ServiceHistoryInstance struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceHistoryInstance"`
	ServiceHistoryInstanceType
}

// TSPServiceInformationType contains TSP service information.
type TSPServiceInformationType struct {
	ServiceTypeIdentifier        *ServiceTypeIdentifier        `xml:"ServiceTypeIdentifier"`
	ServiceName                  *InternationalNamesType       `xml:"ServiceName"`
	ServiceDigitalIdentity       *ServiceDigitalIdentity       `xml:"ServiceDigitalIdentity"`
	ServiceStatus                *ServiceStatus                `xml:"ServiceStatus"`
	StatusStartingTime           *time.Time                    `xml:"StatusStartingTime"`
	SchemeServiceDefinitionURI   *NonEmptyMultiLangURIListType `xml:"SchemeServiceDefinitionURI,omitempty"`
	ServiceSupplyPoints          *ServiceSupplyPoints          `xml:"ServiceSupplyPoints,omitempty"`
	TSPServiceDefinitionURI      *NonEmptyMultiLangURIListType `xml:"TSPServiceDefinitionURI,omitempty"`
	ServiceInformationExtensions *ExtensionsListType           `xml:"ServiceInformationExtensions,omitempty"`
}

// ServiceInformation is the element form.
type ServiceInformation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceInformation"`
	TSPServiceInformationType
}

// AddressType contains postal and electronic addresses.
type AddressType struct {
	PostalAddresses   *PostalAddresses   `xml:"PostalAddresses"`
	ElectronicAddress *ElectronicAddress `xml:"ElectronicAddress"`
}

// ServiceHistoryType contains service history instances.
type ServiceHistoryType struct {
	ServiceHistoryInstance []ServiceHistoryInstance `xml:"ServiceHistoryInstance,omitempty"`
}

// ServiceHistory is the element form.
type ServiceHistory struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# ServiceHistory"`
	ServiceHistoryType
}

// TSPInformationType contains TSP information.
type TSPInformationType struct {
	TSPName                 *InternationalNamesType       `xml:"TSPName"`
	TSPTradeName            *InternationalNamesType       `xml:"TSPTradeName,omitempty"`
	TSPAddress              *AddressType                  `xml:"TSPAddress"`
	TSPInformationURI       *NonEmptyMultiLangURIListType `xml:"TSPInformationURI"`
	TSPInformationExtensions *ExtensionsListType          `xml:"TSPInformationExtensions,omitempty"`
}

// TSPInformation is the element form.
type TSPInformation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TSPInformation"`
	TSPInformationType
}

// OtherTSLPointerType points to another TSL.
type OtherTSLPointerType struct {
	ServiceDigitalIdentities *ServiceDigitalIdentities `xml:"ServiceDigitalIdentities,omitempty"`
	TSLLocation              string                    `xml:"TSLLocation"`
	AdditionalInformation    *AdditionalInformation    `xml:"AdditionalInformation,omitempty"`
}

// OtherTSLPointer is the element form.
type OtherTSLPointer struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# OtherTSLPointer"`
	OtherTSLPointerType
}

// OtherTSLPointersType contains pointers to other TSLs.
type OtherTSLPointersType struct {
	OtherTSLPointer []OtherTSLPointer `xml:"OtherTSLPointer"`
}

// PointersToOtherTSL is the element form.
type PointersToOtherTSL struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# PointersToOtherTSL"`
	OtherTSLPointersType
}

// TSPServiceType contains service information and history.
type TSPServiceType struct {
	ServiceInformation *ServiceInformation `xml:"ServiceInformation"`
	ServiceHistory     *ServiceHistory     `xml:"ServiceHistory,omitempty"`
}

// TSPService is the element form.
type TSPService struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TSPService"`
	TSPServiceType
}

// TSLSchemeInformationType contains TSL scheme information.
type TSLSchemeInformationType struct {
	TSLVersionIdentifier        int                       `xml:"TSLVersionIdentifier"`
	TSLSequenceNumber           int                       `xml:"TSLSequenceNumber"`
	TSLType                     *TSLType                  `xml:"TSLType"`
	SchemeOperatorName          *SchemeOperatorName       `xml:"SchemeOperatorName"`
	SchemeOperatorAddress       *AddressType              `xml:"SchemeOperatorAddress"`
	SchemeName                  *SchemeName               `xml:"SchemeName"`
	SchemeInformationURI        *SchemeInformationURI     `xml:"SchemeInformationURI"`
	StatusDeterminationApproach string                    `xml:"StatusDeterminationApproach"`
	SchemeTypeCommunityRules    *SchemeTypeCommunityRules `xml:"SchemeTypeCommunityRules,omitempty"`
	SchemeTerritory             *SchemeTerritory          `xml:"SchemeTerritory,omitempty"`
	PolicyOrLegalNotice         *PolicyOrLegalNotice      `xml:"PolicyOrLegalNotice,omitempty"`
	HistoricalInformationPeriod int                       `xml:"HistoricalInformationPeriod"`
	PointersToOtherTSL          *PointersToOtherTSL       `xml:"PointersToOtherTSL,omitempty"`
	ListIssueDateTime           *time.Time                `xml:"ListIssueDateTime"`
	NextUpdate                  *NextUpdate               `xml:"NextUpdate"`
	DistributionPoints          *DistributionPoints       `xml:"DistributionPoints,omitempty"`
	SchemeExtensions            *ExtensionsListType       `xml:"SchemeExtensions,omitempty"`
}

// SchemeInformation is the element form.
type SchemeInformation struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# SchemeInformation"`
	TSLSchemeInformationType
}

// TSPServicesListType contains a list of TSP services.
type TSPServicesListType struct {
	TSPService []TSPService `xml:"TSPService"`
}

// TSPServices is the element form.
type TSPServices struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TSPServices"`
	TSPServicesListType
}

// TSPType contains TSP information and services.
type TSPType struct {
	TSPInformation *TSPInformation `xml:"TSPInformation"`
	TSPServices    *TSPServices    `xml:"TSPServices"`
}

// TrustServiceProvider is the element form of TSPType.
type TrustServiceProvider struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TrustServiceProvider"`
	TSPType
}

// TrustServiceProviderListType contains a list of TSPs.
type TrustServiceProviderListType struct {
	TrustServiceProvider []TrustServiceProvider `xml:"TrustServiceProvider"`
}

// TrustServiceProviderList is the element form.
type TrustServiceProviderList struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TrustServiceProviderList"`
	TrustServiceProviderListType
}

// TrustStatusListType is the main TSL structure.
type TrustStatusListType struct {
	SchemeInformation        *SchemeInformation        `xml:"SchemeInformation"`
	TrustServiceProviderList *TrustServiceProviderList `xml:"TrustServiceProviderList,omitempty"`
	Signature                *w3c.Signature            `xml:"http://www.w3.org/2000/09/xmldsig# Signature,omitempty"`
	TSLTag                   string                    `xml:"TSLTag,attr"`
	ID                       string                    `xml:"Id,attr,omitempty"`
}

// TrustServiceStatusList is the element form (root element).
type TrustServiceStatusList struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/02231/v2# TrustServiceStatusList"`
	TrustStatusListType
}

// NewTrustServiceStatusList creates a new TrustServiceStatusList.
func NewTrustServiceStatusList() *TrustServiceStatusList {
	return &TrustServiceStatusList{}
}

// GetServicesByType returns services matching the given type.
func (tsl *TrustServiceStatusList) GetServicesByType(serviceType string) []*TSPService {
	var services []*TSPService
	if tsl.TrustServiceProviderList == nil {
		return services
	}
	for i := range tsl.TrustServiceProviderList.TrustServiceProvider {
		tsp := &tsl.TrustServiceProviderList.TrustServiceProvider[i]
		if tsp.TSPServices == nil {
			continue
		}
		for j := range tsp.TSPServices.TSPService {
			svc := &tsp.TSPServices.TSPService[j]
			if svc.ServiceInformation != nil &&
				svc.ServiceInformation.ServiceTypeIdentifier != nil &&
				svc.ServiceInformation.ServiceTypeIdentifier.Value == serviceType {
				services = append(services, svc)
			}
		}
	}
	return services
}

// GetServicesByStatus returns services matching the given status.
func (tsl *TrustServiceStatusList) GetServicesByStatus(status string) []*TSPService {
	var services []*TSPService
	if tsl.TrustServiceProviderList == nil {
		return services
	}
	for i := range tsl.TrustServiceProviderList.TrustServiceProvider {
		tsp := &tsl.TrustServiceProviderList.TrustServiceProvider[i]
		if tsp.TSPServices == nil {
			continue
		}
		for j := range tsp.TSPServices.TSPService {
			svc := &tsp.TSPServices.TSPService[j]
			if svc.ServiceInformation != nil &&
				svc.ServiceInformation.ServiceStatus != nil &&
				svc.ServiceInformation.ServiceStatus.Value == status {
				services = append(services, svc)
			}
		}
	}
	return services
}
