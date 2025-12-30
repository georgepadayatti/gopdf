// Package etsi provides ETSI XML structures.
// This file contains Service Information Extension types for ETSI TS 119.612.
package etsi

import (
	"encoding/xml"
)

// SIENamespace is the Service Information Extension namespace.
const SIENamespace = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"

// CriteriaListAssert specifies how criteria should be evaluated.
type CriteriaListAssert string

const (
	CriteriaListAssertAll        CriteriaListAssert = "all"
	CriteriaListAssertAtLeastOne CriteriaListAssert = "atLeastOne"
	CriteriaListAssertNone       CriteriaListAssert = "none"
)

// KeyUsageBitName identifies a key usage bit.
type KeyUsageBitName string

const (
	KeyUsageDigitalSignature KeyUsageBitName = "digitalSignature"
	KeyUsageNonRepudiation   KeyUsageBitName = "nonRepudiation"
	KeyUsageKeyEncipherment  KeyUsageBitName = "keyEncipherment"
	KeyUsageDataEncipherment KeyUsageBitName = "dataEncipherment"
	KeyUsageKeyAgreement     KeyUsageBitName = "keyAgreement"
	KeyUsageKeyCertSign      KeyUsageBitName = "keyCertSign"
	KeyUsageCRLSign          KeyUsageBitName = "crlSign"
	KeyUsageEncipherOnly     KeyUsageBitName = "encipherOnly"
	KeyUsageDecipherOnly     KeyUsageBitName = "decipherOnly"
)

// SIEQualifierType contains a qualifier URI.
type SIEQualifierType struct {
	URI string `xml:"uri,attr,omitempty"`
}

// KeyUsageBitType represents a single key usage bit.
type KeyUsageBitType struct {
	Value bool            `xml:",chardata"`
	Name  KeyUsageBitName `xml:"name,attr,omitempty"`
}

// PoliciesListType contains a list of policy identifiers.
type PoliciesListType struct {
	PolicyIdentifier []ObjectIdentifierType `xml:"PolicyIdentifier"`
}

// SIEQualifiersType contains a list of qualifiers.
type SIEQualifiersType struct {
	Qualifier []SIEQualifierType `xml:"Qualifier"`
}

// KeyUsageTypeList contains key usage bits.
type KeyUsageTypeList struct {
	KeyUsageBit []KeyUsageBitType `xml:"KeyUsageBit"`
}

// CriteriaListType contains criteria for qualification.
type CriteriaListType struct {
	KeyUsage          []KeyUsageTypeList  `xml:"KeyUsage,omitempty"`
	PolicySet         []PoliciesListType  `xml:"PolicySet,omitempty"`
	CriteriaList      []CriteriaListType  `xml:"CriteriaList,omitempty"`
	Description       string              `xml:"Description,omitempty"`
	OtherCriteriaList *AnyType            `xml:"otherCriteriaList,omitempty"`
	Assert            CriteriaListAssert  `xml:"assert,attr,omitempty"`
}

// QualificationElementType contains a qualification element.
type QualificationElementType struct {
	Qualifiers   *SIEQualifiersType `xml:"Qualifiers"`
	CriteriaList *CriteriaListType  `xml:"CriteriaList"`
}

// QualificationsType contains qualification elements.
type QualificationsType struct {
	QualificationElement []QualificationElementType `xml:"QualificationElement"`
}

// Qualifications is the element form of QualificationsType.
type Qualifications struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/# Qualifications"`
	QualificationsType
}
