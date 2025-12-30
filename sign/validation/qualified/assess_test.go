package qualified

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestQualificationPolicyError(t *testing.T) {
	err := NewQualificationPolicyError("test message", "SUB_IND")
	if err.Error() != "test message" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test message")
	}
	if err.SubIndication != "SUB_IND" {
		t.Errorf("SubIndication = %q, want %q", err.SubIndication, "SUB_IND")
	}
}

func TestNewQualificationAssessor(t *testing.T) {
	registry := NewTSPRegistry()
	assessor := NewQualificationAssessor(registry)
	if assessor == nil {
		t.Error("NewQualificationAssessor returned nil")
	}
	if assessor.registry != registry {
		t.Error("Registry not set correctly")
	}
}

func TestComputeFinalStatus_NotQualified(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtQSCD,
	}

	qualifiers := map[Qualifier]bool{
		QualifierNotQualified: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.Qualified {
		t.Error("Expected not qualified when QualifierNotQualified is set")
	}
	if result.QcKeySecurity != QcKeyMgmtUnknown {
		t.Error("Expected key security unknown when not qualified")
	}
}

func TestComputeFinalStatus_LegalPerson(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtQSCD,
	}

	qualifiers := map[Qualifier]bool{
		QualifierLegalPerson: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.Qualified {
		t.Error("Expected not qualified when QualifierLegalPerson is set")
	}
}

func TestComputeFinalStatus_QCStatement(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     false,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtUnknown,
	}

	qualifiers := map[Qualifier]bool{
		QualifierQCStatement: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if !result.Qualified {
		t.Error("Expected qualified when QualifierQCStatement is set")
	}
}

func TestComputeFinalStatus_ForWSA(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtQSCD,
	}

	qualifiers := map[Qualifier]bool{
		QualifierForWSA: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.QcType != QcCertTypeWeb {
		t.Errorf("Expected QcType = Web, got %v", result.QcType)
	}
}

func TestComputeFinalStatus_ForESeal(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtQSCD,
	}

	qualifiers := map[Qualifier]bool{
		QualifierForESeal: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.QcType != QcCertTypeEseal {
		t.Errorf("Expected QcType = ESeal, got %v", result.QcType)
	}
}

func TestComputeFinalStatus_NoSSCD(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtQSCD,
	}

	qualifiers := map[Qualifier]bool{
		QualifierNoSSCD: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.QcKeySecurity != QcKeyMgmtUnknown {
		t.Errorf("Expected QcKeySecurity = Unknown, got %v", result.QcKeySecurity)
	}
}

func TestComputeFinalStatus_QSCDManagedOnBehalf(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtUnknown,
	}

	qualifiers := map[Qualifier]bool{
		QualifierQSCDManagedOnBehalf: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.QcKeySecurity != QcKeyMgmtQSCDDelegated {
		t.Errorf("Expected QcKeySecurity = QSCDDelegated, got %v", result.QcKeySecurity)
	}
}

func TestComputeFinalStatus_WithQSCD(t *testing.T) {
	prelim := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtUnknown,
	}

	qualifiers := map[Qualifier]bool{
		QualifierWithQSCD: true,
	}

	result := computeFinalStatus(prelim, qualifiers)
	if result.QcKeySecurity != QcKeyMgmtQSCD {
		t.Errorf("Expected QcKeySecurity = QSCD, got %v", result.QcKeySecurity)
	}
}

func TestCheckSDApplicable_NoRestriction(t *testing.T) {
	sd := BaseServiceInformation{
		ServiceType:                   CAQCUri,
		AdditionalInfoCertificateType: nil,
	}
	status := QualifiedStatusInfo{
		QcType: QcCertTypeEsign,
	}

	if !checkSDApplicable(sd, status) {
		t.Error("Expected service to be applicable when no restrictions")
	}
}

func TestCheckSDApplicable_TypeMatches(t *testing.T) {
	sd := BaseServiceInformation{
		ServiceType: CAQCUri,
		AdditionalInfoCertificateType: map[QcCertType]bool{
			QcCertTypeEsign: true,
		},
	}
	status := QualifiedStatusInfo{
		QcType: QcCertTypeEsign,
	}

	if !checkSDApplicable(sd, status) {
		t.Error("Expected service to be applicable when type matches")
	}
}

func TestCheckSDApplicable_TypeDoesNotMatch(t *testing.T) {
	sd := BaseServiceInformation{
		ServiceType: CAQCUri,
		AdditionalInfoCertificateType: map[QcCertType]bool{
			QcCertTypeEseal: true,
		},
	}
	status := QualifiedStatusInfo{
		QcType: QcCertTypeEsign,
	}

	if checkSDApplicable(sd, status) {
		t.Error("Expected service not applicable when type does not match")
	}
}

func TestEnforceRequirements_NilRequirements(t *testing.T) {
	result := QualificationResult{
		Status: UnqualifiedStatus(),
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(nil, result, cert)
	if err != nil {
		t.Errorf("Expected nil error for nil requirements, got %v", err)
	}
}

func TestEnforceRequirements_NotQualified(t *testing.T) {
	req := NewQualificationRequirements()
	result := QualificationResult{
		Status: UnqualifiedStatus(),
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(req, result, cert)
	if err == nil {
		t.Error("Expected error for unqualified certificate")
	}
	if pErr, ok := err.(*QualificationPolicyError); ok {
		if pErr.SubIndication != "SIG_CONSTRAINTS_FAILURE" {
			t.Errorf("Expected SubIndication = SIG_CONSTRAINTS_FAILURE, got %s", pErr.SubIndication)
		}
	} else {
		t.Error("Expected QualificationPolicyError")
	}
}

func TestEnforceRequirements_CertTypeNotPermitted(t *testing.T) {
	req := NewQualificationRequirements().WithCertTypes(QcCertTypeEseal)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified: true,
			QcType:    QcCertTypeEsign,
		},
		ServiceDefinition: sd,
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(req, result, cert)
	if err == nil {
		t.Error("Expected error for unpermitted certificate type")
	}
}

func TestEnforceRequirements_KeyMgmtTypeNotPermitted(t *testing.T) {
	req := NewQualificationRequirements().WithKeyMgmtTypes(QcKeyMgmtQSCD)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified:     true,
			QcType:        QcCertTypeEsign,
			QcKeySecurity: QcKeyMgmtUnknown,
		},
		ServiceDefinition: sd,
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(req, result, cert)
	if err == nil {
		t.Error("Expected error for unpermitted key management type")
	}
}

func TestEnforceRequirements_ServiceTypeString(t *testing.T) {
	req := NewQualificationRequirements().WithServiceType(QTSTUri)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified: true,
			QcType:    QcCertTypeEsign,
		},
		ServiceDefinition: sd,
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(req, result, cert)
	if err == nil {
		t.Error("Expected error for mismatched service type")
	}
}

func TestEnforceRequirements_ServiceTypeEnum(t *testing.T) {
	req := NewQualificationRequirements().WithServiceType(TrustedServiceTypeTimeStampingAuthority)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified: true,
			QcType:    QcCertTypeEsign,
		},
		ServiceDefinition: sd,
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(req, result, cert)
	if err == nil {
		t.Error("Expected error for mismatched service type enum")
	}
}

func TestEnforceRequirements_AllPassing(t *testing.T) {
	req := NewQualificationRequirements().
		WithCertTypes(QcCertTypeEsign).
		WithKeyMgmtTypes(QcKeyMgmtQSCD).
		WithServiceType(TrustedServiceTypeCertificateAuthority)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified:     true,
			QcType:        QcCertTypeEsign,
			QcKeySecurity: QcKeyMgmtQSCD,
		},
		ServiceDefinition: sd,
	}
	cert := &x509.Certificate{}

	err := EnforceRequirements(req, result, cert)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestValidateQualifiedSignature_NilAssessor(t *testing.T) {
	cert := &x509.Certificate{}
	_, err := ValidateQualifiedSignature(nil, cert, nil, nil, nil)
	if err == nil {
		t.Error("Expected error for nil assessor")
	}
}

func TestValidateQualifiedSignature_NilCert(t *testing.T) {
	registry := NewTSPRegistry()
	assessor := NewQualificationAssessor(registry)
	_, err := ValidateQualifiedSignature(assessor, nil, nil, nil, nil)
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestValidateQualifiedSignature_Basic(t *testing.T) {
	registry := NewTSPRegistry()
	assessor := NewQualificationAssessor(registry)
	cert := &x509.Certificate{}

	result, err := ValidateQualifiedSignature(assessor, cert, nil, nil, nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Expected result to be non-nil")
	}
}

func TestValidateQualifiedSignature_WithRequirements(t *testing.T) {
	registry := NewTSPRegistry()
	assessor := NewQualificationAssessor(registry)
	cert := &x509.Certificate{}
	req := NewQualificationRequirements()

	result, err := ValidateQualifiedSignature(assessor, cert, nil, nil, req)
	// Should fail because certificate is not qualified
	if err == nil {
		t.Error("Expected error for unqualified certificate")
	}
	if result == nil {
		t.Error("Expected result to be non-nil even with error")
	}
}

func TestQualificationAssessor_Assess(t *testing.T) {
	registry := NewTSPRegistry()
	assessor := NewQualificationAssessor(registry)
	cert := &x509.Certificate{}

	result := assessor.Assess(cert)
	if result.IsQualified() {
		t.Error("Expected certificate without QC statements to be unqualified")
	}
}

func TestQualificationAssessor_AssessChain(t *testing.T) {
	registry := NewTSPRegistry()
	assessor := NewQualificationAssessor(registry)

	chain := []*x509.Certificate{
		{},
		{},
		{},
	}

	results := assessor.AssessChain(chain)
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}
}

func TestEIDASStartDate(t *testing.T) {
	expected := time.Date(2016, 7, 1, 0, 0, 0, 0, time.FixedZone("CET", 1*60*60))
	if !EIDASStartDate.Equal(expected) {
		t.Errorf("EIDASStartDate = %v, expected %v", EIDASStartDate, expected)
	}
}

func TestPreEIDASPolicies(t *testing.T) {
	if PreEIDASQCPPolicy != "0.4.0.1456.1.1" {
		t.Errorf("PreEIDASQCPPolicy = %s, expected 0.4.0.1456.1.1", PreEIDASQCPPolicy)
	}
	if PreEIDASQCPPlusPolicy != "0.4.0.1456.1.2" {
		t.Errorf("PreEIDASQCPPlusPolicy = %s, expected 0.4.0.1456.1.2", PreEIDASQCPPlusPolicy)
	}
}
