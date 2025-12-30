// Package qualified provides QualificationAssessor for evaluating the qualified
// status of certificates against TSP registries according to EU eIDAS regulation.
package qualified

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"time"
)

// EIDASStartDate is the date when eIDAS regulation came into effect.
var EIDASStartDate = time.Date(2016, 7, 1, 0, 0, 0, 0, time.FixedZone("CET", 1*60*60))

// Pre-eIDAS policy OIDs.
const (
	PreEIDASQCPPolicy     = "0.4.0.1456.1.1"
	PreEIDASQCPPlusPolicy = "0.4.0.1456.1.2"
)

// QualificationPolicyError is an error triggered by a qualification policy violation.
type QualificationPolicyError struct {
	Message       string
	SubIndication string
}

func (e *QualificationPolicyError) Error() string {
	return e.Message
}

// NewQualificationPolicyError creates a new qualification policy error.
func NewQualificationPolicyError(msg string, subIndication string) *QualificationPolicyError {
	return &QualificationPolicyError{
		Message:       msg,
		SubIndication: subIndication,
	}
}

// QualificationAssessor assesses the qualification status of certificates
// against a TSPRegistry.
type QualificationAssessor struct {
	registry *TSPRegistry
}

// NewQualificationAssessor creates a new QualificationAssessor.
func NewQualificationAssessor(registry *TSPRegistry) *QualificationAssessor {
	return &QualificationAssessor{
		registry: registry,
	}
}

// processQCStatements extracts qualification status from certificate QC statements.
func processQCStatements(cert *x509.Certificate) QualifiedStatusInfo {
	qcStatements, err := ParseQCStatements(cert)
	if err != nil {
		return UnqualifiedStatus()
	}

	qualified := qcStatements.HasCompliance()
	keySecure := qcStatements.HasSSCD()
	qcType := QcCertTypeEsign

	// Determine QC type from statements
	for _, stmt := range qcStatements.Statements {
		if stmt.OID.Equal(OIDQcType) {
			if data, ok := stmt.Value.([]byte); ok {
				// Parse QC type OIDs
				var typeOIDs []asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(data, &typeOIDs); err == nil && len(typeOIDs) > 0 {
					switch {
					case typeOIDs[0].Equal(OIDQcTypeEsign):
						qcType = QcCertTypeEsign
					case typeOIDs[0].Equal(OIDQcTypeEseal):
						qcType = QcCertTypeEseal
					case typeOIDs[0].Equal(OIDQcTypeWeb):
						qcType = QcCertTypeWeb
					}
				}
			}
		}
	}

	keySecurity := QcKeyMgmtUnknown
	if keySecure && qualified {
		keySecurity = QcKeyMgmtQSCD
	}

	return QualifiedStatusInfo{
		Qualified:     qualified,
		QcType:        qcType,
		QcKeySecurity: keySecurity,
	}
}

// checkSDApplicable checks if a service definition is applicable based on QC type.
func checkSDApplicable(sd BaseServiceInformation, status QualifiedStatusInfo) bool {
	if len(sd.AdditionalInfoCertificateType) == 0 {
		return true
	}
	return sd.AdditionalInfoCertificateType[status.QcType]
}

// applySDQualifications applies service definition qualifications to a certificate.
func applySDQualifications(cert *x509.Certificate, prelimStatus QualifiedStatusInfo, qualifications []TSPQualification) QualifiedStatusInfo {
	applicableQualifiers := make(map[Qualifier]bool)

	for _, qual := range qualifications {
		if qual.CriteriaList == nil || qual.CriteriaList.Matches(cert) {
			for q := range qual.Qualifiers {
				applicableQualifiers[q] = true
			}
		}
	}

	return computeFinalStatus(prelimStatus, applicableQualifiers)
}

// computeFinalStatus computes the final status based on qualifiers.
func computeFinalStatus(prelimStatus QualifiedStatusInfo, qualifiers map[Qualifier]bool) QualifiedStatusInfo {
	// Determine if qualified
	isQualified := prelimStatus.Qualified
	if qualifiers[QualifierNotQualified] || qualifiers[QualifierLegalPerson] {
		isQualified = false
	} else if qualifiers[QualifierQCStatement] {
		isQualified = true
	}

	// Determine QC type
	qcType := prelimStatus.QcType
	if qualifiers[QualifierForWSA] {
		qcType = QcCertTypeWeb
	} else if qualifiers[QualifierForESig] {
		qcType = QcCertTypeEsign
	} else if qualifiers[QualifierForESeal] {
		qcType = QcCertTypeEseal
	}

	// Determine key management
	keyMgmt := prelimStatus.QcKeySecurity
	if !isQualified {
		keyMgmt = QcKeyMgmtUnknown
	} else if qualifiers[QualifierNoSSCD] || qualifiers[QualifierNoQSCD] {
		keyMgmt = QcKeyMgmtUnknown
	} else if qualifiers[QualifierQSCDManagedOnBehalf] {
		keyMgmt = QcKeyMgmtQSCDDelegated
	} else if qualifiers[QualifierWithSSCD] || qualifiers[QualifierWithQSCD] {
		keyMgmt = QcKeyMgmtQSCD
	}

	return QualifiedStatusInfo{
		Qualified:     isQualified,
		QcType:        qcType,
		QcKeySecurity: keyMgmt,
	}
}

// CheckEntityCertQualified evaluates the qualified status of a certificate.
func (a *QualificationAssessor) CheckEntityCertQualified(
	cert *x509.Certificate,
	chain []*x509.Certificate,
	moment *time.Time,
) QualificationResult {
	prelimStatus := processQCStatements(cert)

	// Determine reference time
	referenceTime := time.Now()
	if moment != nil {
		referenceTime = *moment
	}

	// Check for pre-eIDAS policies
	if referenceTime.Before(EIDASStartDate) {
		policies, _ := ParseCertificatePolicies(cert)
		for _, policy := range policies {
			policyOID := policy.OID.String()
			if policyOID == PreEIDASQCPPlusPolicy {
				prelimStatus.Qualified = true
				if !prelimStatus.QcKeySecurity.IsQSCD() {
					prelimStatus.QcKeySecurity = QcKeyMgmtQSCDByPolicy
				}
			} else if policyOID == PreEIDASQCPPolicy {
				prelimStatus.Qualified = true
			}
		}
	}

	// Search for applicable service definitions
	type sdStatus struct {
		sd     QualifiedServiceInformation
		status QualifiedStatusInfo
	}
	var statusesFound []sdStatus

	// Check all certificates in chain against registry
	allCerts := append([]*x509.Certificate{cert}, chain...)
	for _, c := range allCerts {
		services := a.registry.ApplicableServiceDefinitions(c, &referenceTime)
		for _, sd := range services {
			putativeStatus := applySDQualifications(cert, prelimStatus, sd.Qualifications)
			if checkSDApplicable(sd.BaseInfo, putativeStatus) {
				statusesFound = append(statusesFound, sdStatus{sd: sd, status: putativeStatus})
			}
		}
	}

	// Analyze results
	if len(statusesFound) == 0 {
		return QualificationResult{
			Status:            UnqualifiedStatus(),
			ServiceDefinition: nil,
		}
	}

	// Check for consistent results
	uniqueStatuses := make(map[QualifiedStatusInfo]bool)
	for _, ss := range statusesFound {
		uniqueStatuses[ss.status] = true
	}

	if len(statusesFound) == 1 || len(uniqueStatuses) == 1 {
		// Happy path: single result or all results consistent
		return QualificationResult{
			Status:            statusesFound[0].status,
			ServiceDefinition: &statusesFound[0].sd,
		}
	}

	// Contradictory results - return not qualified
	return QualificationResult{
		Status:            UnqualifiedStatus(),
		ServiceDefinition: nil,
	}
}

// Assess performs a simplified qualification assessment (backward compatible).
func (a *QualificationAssessor) Assess(cert *x509.Certificate) QualificationResult {
	return a.CheckEntityCertQualified(cert, nil, nil)
}

// AssessChain performs qualification assessment on a certificate chain.
func (a *QualificationAssessor) AssessChain(chain []*x509.Certificate) []QualificationResult {
	results := make([]QualificationResult, len(chain))
	for i, cert := range chain {
		var subchain []*x509.Certificate
		if i+1 < len(chain) {
			subchain = chain[i+1:]
		}
		results[i] = a.CheckEntityCertQualified(cert, subchain, nil)
	}
	return results
}

// EnforceRequirements enforces qualification requirements on a result.
func EnforceRequirements(
	requirements *QualificationRequirements,
	result QualificationResult,
	cert *x509.Certificate,
) error {
	if requirements == nil {
		return nil
	}

	if !result.IsQualified() {
		return NewQualificationPolicyError(
			"certificate is not qualified",
			"SIG_CONSTRAINTS_FAILURE",
		)
	}

	var errStrs []string

	// Check service type
	if requirements.RequireServiceType != nil && result.ServiceDefinition != nil {
		serviceTypeURI := result.ServiceDefinition.BaseInfo.ServiceType
		var matches bool

		switch st := requirements.RequireServiceType.(type) {
		case string:
			matches = serviceTypeURI == st
		case TrustedServiceType:
			actualType := TrustedServiceTypeUnsupported
			switch serviceTypeURI {
			case CAQCUri:
				actualType = TrustedServiceTypeCertificateAuthority
			case QTSTUri:
				actualType = TrustedServiceTypeTimeStampingAuthority
			}
			matches = actualType == st
		}

		if !matches {
			errStrs = append(errStrs, "certificate is not directly trusted as required service type")
		}
	}

	// Check certificate type
	if requirements.PermitCertTypes != nil {
		found := false
		for _, t := range requirements.PermitCertTypes {
			if t == result.Status.QcType {
				found = true
				break
			}
		}
		if !found {
			errStrs = append(errStrs, "certificate type not permitted by requirements")
		}
	}

	// Check key management type
	if requirements.PermitKeyMgmtTypes != nil {
		found := false
		for _, t := range requirements.PermitKeyMgmtTypes {
			if t == result.Status.QcKeySecurity {
				found = true
				break
			}
		}
		if !found {
			errStrs = append(errStrs, "key management type not permitted by requirements")
		}
	}

	if len(errStrs) > 0 {
		return NewQualificationPolicyError(
			errStrs[0], // Return first error
			"SIG_CONSTRAINTS_FAILURE",
		)
	}

	return nil
}

// ValidateQualifiedSignature validates a qualified signature.
func ValidateQualifiedSignature(
	assessor *QualificationAssessor,
	signerCert *x509.Certificate,
	chain []*x509.Certificate,
	signatureTime *time.Time,
	requirements *QualificationRequirements,
) (*QualificationResult, error) {
	if assessor == nil {
		return nil, errors.New("assessor is required")
	}
	if signerCert == nil {
		return nil, errors.New("signer certificate is required")
	}

	result := assessor.CheckEntityCertQualified(signerCert, chain, signatureTime)

	if requirements != nil {
		if err := EnforceRequirements(requirements, result, signerCert); err != nil {
			return &result, err
		}
	}

	return &result, nil
}
