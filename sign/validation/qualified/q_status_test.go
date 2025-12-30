package qualified

import (
	"testing"
)

func TestQcPrivateKeyManagementType_String(t *testing.T) {
	tests := []struct {
		t    QcPrivateKeyManagementType
		want string
	}{
		{QcKeyMgmtUnknown, "UNKNOWN"},
		{QcKeyMgmtQSCD, "QSCD"},
		{QcKeyMgmtQSCDDelegated, "QSCD_DELEGATED"},
		{QcKeyMgmtQSCDByPolicy, "QSCD_BY_POLICY"},
	}

	for _, tt := range tests {
		if got := tt.t.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.t, got, tt.want)
		}
	}
}

func TestQcPrivateKeyManagementType_IsQSCD(t *testing.T) {
	tests := []struct {
		t    QcPrivateKeyManagementType
		want bool
	}{
		{QcKeyMgmtUnknown, false},
		{QcKeyMgmtQSCD, true},
		{QcKeyMgmtQSCDDelegated, true},
		{QcKeyMgmtQSCDByPolicy, true},
	}

	for _, tt := range tests {
		if got := tt.t.IsQSCD(); got != tt.want {
			t.Errorf("%d.IsQSCD() = %v, want %v", tt.t, got, tt.want)
		}
	}
}

func TestNewQualifiedStatusInfo(t *testing.T) {
	status := NewQualifiedStatusInfo(true, QcCertTypeEseal, QcKeyMgmtQSCD)
	if !status.Qualified {
		t.Error("Expected Qualified to be true")
	}
	if status.QcType != QcCertTypeEseal {
		t.Errorf("Expected QcType = ESeal, got %v", status.QcType)
	}
	if status.QcKeySecurity != QcKeyMgmtQSCD {
		t.Errorf("Expected QcKeySecurity = QSCD, got %v", status.QcKeySecurity)
	}
}

func TestUnqualifiedStatus(t *testing.T) {
	status := UnqualifiedStatus()
	if status.Qualified {
		t.Error("Expected Qualified to be false")
	}
	if status.QcType != QcCertTypeEsign {
		t.Errorf("Expected QcType = ESign (default), got %v", status.QcType)
	}
	if status.QcKeySecurity != QcKeyMgmtUnknown {
		t.Errorf("Expected QcKeySecurity = Unknown, got %v", status.QcKeySecurity)
	}
}

func TestNewQualificationResult(t *testing.T) {
	status := QualifiedStatusInfo{
		Qualified:     true,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtQSCD,
	}
	sd := &QualifiedServiceInformation{}
	result := NewQualificationResult(status, sd)

	if result.Status != status {
		t.Error("Status not set correctly")
	}
	if result.ServiceDefinition != sd {
		t.Error("ServiceDefinition not set correctly")
	}
}

func TestQualificationResult_IsQualified(t *testing.T) {
	tests := []struct {
		status QualifiedStatusInfo
		want   bool
	}{
		{QualifiedStatusInfo{Qualified: true}, true},
		{QualifiedStatusInfo{Qualified: false}, false},
	}

	for i, tt := range tests {
		result := QualificationResult{Status: tt.status}
		if got := result.IsQualified(); got != tt.want {
			t.Errorf("Test %d: IsQualified() = %v, want %v", i, got, tt.want)
		}
	}
}

func TestQualificationResult_HasServiceDefinition(t *testing.T) {
	resultWithSD := QualificationResult{
		ServiceDefinition: &QualifiedServiceInformation{},
	}
	if !resultWithSD.HasServiceDefinition() {
		t.Error("Expected HasServiceDefinition() = true")
	}

	resultWithoutSD := QualificationResult{
		ServiceDefinition: nil,
	}
	if resultWithoutSD.HasServiceDefinition() {
		t.Error("Expected HasServiceDefinition() = false")
	}
}

func TestQualificationResult_HasQSCD(t *testing.T) {
	tests := []struct {
		keySecurity QcPrivateKeyManagementType
		want        bool
	}{
		{QcKeyMgmtUnknown, false},
		{QcKeyMgmtQSCD, true},
		{QcKeyMgmtQSCDDelegated, true},
		{QcKeyMgmtQSCDByPolicy, true},
	}

	for _, tt := range tests {
		result := QualificationResult{
			Status: QualifiedStatusInfo{QcKeySecurity: tt.keySecurity},
		}
		if got := result.HasQSCD(); got != tt.want {
			t.Errorf("HasQSCD() with %v = %v, want %v", tt.keySecurity, got, tt.want)
		}
	}
}

func TestNewQualificationRequirements(t *testing.T) {
	req := NewQualificationRequirements()
	if req == nil {
		t.Error("NewQualificationRequirements returned nil")
	}
	if req.RequireServiceType != nil {
		t.Error("Expected RequireServiceType to be nil")
	}
	if req.PermitCertTypes != nil {
		t.Error("Expected PermitCertTypes to be nil")
	}
	if req.PermitKeyMgmtTypes != nil {
		t.Error("Expected PermitKeyMgmtTypes to be nil")
	}
}

func TestQualificationRequirements_WithServiceType(t *testing.T) {
	req := NewQualificationRequirements().WithServiceType(CAQCUri)
	if req.RequireServiceType != CAQCUri {
		t.Error("RequireServiceType not set correctly")
	}
}

func TestQualificationRequirements_WithCertTypes(t *testing.T) {
	req := NewQualificationRequirements().WithCertTypes(QcCertTypeEsign, QcCertTypeEseal)
	if len(req.PermitCertTypes) != 2 {
		t.Errorf("Expected 2 cert types, got %d", len(req.PermitCertTypes))
	}
}

func TestQualificationRequirements_WithKeyMgmtTypes(t *testing.T) {
	req := NewQualificationRequirements().WithKeyMgmtTypes(QcKeyMgmtQSCD, QcKeyMgmtQSCDDelegated)
	if len(req.PermitKeyMgmtTypes) != 2 {
		t.Errorf("Expected 2 key mgmt types, got %d", len(req.PermitKeyMgmtTypes))
	}
}

func TestQualificationRequirements_Validate_NotQualified(t *testing.T) {
	req := NewQualificationRequirements()
	result := QualificationResult{
		Status: UnqualifiedStatus(),
	}

	err := req.Validate(result)
	if err != ErrNotQualified {
		t.Errorf("Expected ErrNotQualified, got %v", err)
	}
}

func TestQualificationRequirements_Validate_CertTypeNotPermitted(t *testing.T) {
	req := NewQualificationRequirements().WithCertTypes(QcCertTypeEseal)
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified: true,
			QcType:    QcCertTypeEsign,
		},
	}

	err := req.Validate(result)
	if err != ErrAssessmentFailed {
		t.Errorf("Expected ErrAssessmentFailed, got %v", err)
	}
}

func TestQualificationRequirements_Validate_KeyMgmtNotPermitted(t *testing.T) {
	req := NewQualificationRequirements().WithKeyMgmtTypes(QcKeyMgmtQSCD)
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified:     true,
			QcType:        QcCertTypeEsign,
			QcKeySecurity: QcKeyMgmtUnknown,
		},
	}

	err := req.Validate(result)
	if err != ErrAssessmentFailed {
		t.Errorf("Expected ErrAssessmentFailed, got %v", err)
	}
}

func TestQualificationRequirements_Validate_ServiceTypeString(t *testing.T) {
	req := NewQualificationRequirements().WithServiceType(QTSTUri)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified: true,
		},
		ServiceDefinition: sd,
	}

	err := req.Validate(result)
	if err != ErrAssessmentFailed {
		t.Errorf("Expected ErrAssessmentFailed, got %v", err)
	}
}

func TestQualificationRequirements_Validate_ServiceTypeEnum(t *testing.T) {
	req := NewQualificationRequirements().WithServiceType(TrustedServiceTypeTimeStampingAuthority)
	sd := &QualifiedServiceInformation{
		BaseInfo: BaseServiceInformation{
			ServiceType: CAQCUri,
		},
	}
	result := QualificationResult{
		Status: QualifiedStatusInfo{
			Qualified: true,
		},
		ServiceDefinition: sd,
	}

	err := req.Validate(result)
	if err != ErrAssessmentFailed {
		t.Errorf("Expected ErrAssessmentFailed, got %v", err)
	}
}

func TestQualificationRequirements_Validate_AllPassing(t *testing.T) {
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

	err := req.Validate(result)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestQualificationRequirements_Chaining(t *testing.T) {
	req := NewQualificationRequirements().
		WithServiceType(CAQCUri).
		WithCertTypes(QcCertTypeEsign, QcCertTypeEseal).
		WithKeyMgmtTypes(QcKeyMgmtQSCD)

	if req.RequireServiceType != CAQCUri {
		t.Error("Service type not set through chaining")
	}
	if len(req.PermitCertTypes) != 2 {
		t.Error("Cert types not set through chaining")
	}
	if len(req.PermitKeyMgmtTypes) != 1 {
		t.Error("Key mgmt types not set through chaining")
	}
}
