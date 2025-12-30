// Package qualified provides qualification status types for qualified electronic
// signature validation according to EU eIDAS regulation.
package qualified

// QcPrivateKeyManagementType describes the private key management methodology.
type QcPrivateKeyManagementType int

const (
	// QcKeyMgmtUnknown indicates private key management methodology is unknown/unspecified.
	QcKeyMgmtUnknown QcPrivateKeyManagementType = iota

	// QcKeyMgmtQSCD indicates the private key resides in a qualified
	// signature creation device (QSCD).
	QcKeyMgmtQSCD

	// QcKeyMgmtQSCDDelegated indicates the private key resides in a QSCD managed
	// on behalf of the subject by another party.
	QcKeyMgmtQSCDDelegated

	// QcKeyMgmtQSCDByPolicy indicates QSCD declaration by pre-eIDAS certificate policy.
	QcKeyMgmtQSCDByPolicy
)

// String returns the string representation of the key management type.
func (t QcPrivateKeyManagementType) String() string {
	switch t {
	case QcKeyMgmtQSCD:
		return "QSCD"
	case QcKeyMgmtQSCDDelegated:
		return "QSCD_DELEGATED"
	case QcKeyMgmtQSCDByPolicy:
		return "QSCD_BY_POLICY"
	default:
		return "UNKNOWN"
	}
}

// IsQSCD returns true if the key management type indicates a QSCD.
func (t QcPrivateKeyManagementType) IsQSCD() bool {
	return t != QcKeyMgmtUnknown
}

// QualifiedStatusInfo represents the qualified status of a certificate.
type QualifiedStatusInfo struct {
	// Qualified indicates whether the certificate is to be considered qualified.
	Qualified bool

	// QcType is the type of qualified certificate.
	QcType QcCertType

	// QcKeySecurity indicates whether the CA declares that the private key
	// corresponding to this certificate resides in a qualified
	// signature creation device (QSCD) or secure signature creation device (SSCD).
	// It also indicates whether the QSCD is managed on behalf of the signer,
	// if applicable.
	//
	// Note: These terms are functionally interchangeable; the only difference is
	// that "SSCD" is pre-eIDAS terminology.
	QcKeySecurity QcPrivateKeyManagementType
}

// NewQualifiedStatusInfo creates a new QualifiedStatusInfo.
func NewQualifiedStatusInfo(qualified bool, qcType QcCertType, keySecurity QcPrivateKeyManagementType) QualifiedStatusInfo {
	return QualifiedStatusInfo{
		Qualified:     qualified,
		QcType:        qcType,
		QcKeySecurity: keySecurity,
	}
}

// UnqualifiedStatus returns an unqualified status with default values.
func UnqualifiedStatus() QualifiedStatusInfo {
	return QualifiedStatusInfo{
		Qualified:     false,
		QcType:        QcCertTypeEsign,
		QcKeySecurity: QcKeyMgmtUnknown,
	}
}

// QualificationResult represents the result of a qualification evaluation.
type QualificationResult struct {
	// Status is the qualification status.
	Status QualifiedStatusInfo

	// ServiceDefinition is the service definition under which the tested object
	// was considered qualified. May be nil if not qualified.
	ServiceDefinition *QualifiedServiceInformation
}

// NewQualificationResult creates a new QualificationResult.
func NewQualificationResult(status QualifiedStatusInfo, sd *QualifiedServiceInformation) QualificationResult {
	return QualificationResult{
		Status:            status,
		ServiceDefinition: sd,
	}
}

// IsQualified returns true if the result indicates a qualified certificate.
func (r *QualificationResult) IsQualified() bool {
	return r.Status.Qualified
}

// HasServiceDefinition returns true if a service definition was found.
func (r *QualificationResult) HasServiceDefinition() bool {
	return r.ServiceDefinition != nil
}

// HasQSCD returns true if the certificate has QSCD status.
func (r *QualificationResult) HasQSCD() bool {
	return r.Status.QcKeySecurity.IsQSCD()
}

// QualificationRequirements defines requirements for qualification validation.
type QualificationRequirements struct {
	// RequireServiceType specifies that the certificate must be directly trusted
	// as a service of this type. Can be a string (URI) or TrustedServiceType.
	RequireServiceType interface{}

	// PermitCertTypes specifies which QC certificate types are permitted.
	// If nil, all types are permitted.
	PermitCertTypes []QcCertType

	// PermitKeyMgmtTypes specifies which key management types are permitted.
	// If nil, all types are permitted.
	PermitKeyMgmtTypes []QcPrivateKeyManagementType
}

// NewQualificationRequirements creates new qualification requirements.
func NewQualificationRequirements() *QualificationRequirements {
	return &QualificationRequirements{}
}

// WithServiceType sets the required service type.
func (r *QualificationRequirements) WithServiceType(st interface{}) *QualificationRequirements {
	r.RequireServiceType = st
	return r
}

// WithCertTypes sets the permitted certificate types.
func (r *QualificationRequirements) WithCertTypes(types ...QcCertType) *QualificationRequirements {
	r.PermitCertTypes = types
	return r
}

// WithKeyMgmtTypes sets the permitted key management types.
func (r *QualificationRequirements) WithKeyMgmtTypes(types ...QcPrivateKeyManagementType) *QualificationRequirements {
	r.PermitKeyMgmtTypes = types
	return r
}

// Validates checks if the qualification result meets these requirements.
func (r *QualificationRequirements) Validate(result QualificationResult) error {
	if !result.IsQualified() {
		return ErrNotQualified
	}

	// Check certificate type
	if r.PermitCertTypes != nil {
		found := false
		for _, t := range r.PermitCertTypes {
			if t == result.Status.QcType {
				found = true
				break
			}
		}
		if !found {
			return ErrAssessmentFailed
		}
	}

	// Check key management type
	if r.PermitKeyMgmtTypes != nil {
		found := false
		for _, t := range r.PermitKeyMgmtTypes {
			if t == result.Status.QcKeySecurity {
				found = true
				break
			}
		}
		if !found {
			return ErrAssessmentFailed
		}
	}

	// Check service type
	if r.RequireServiceType != nil && result.ServiceDefinition != nil {
		switch st := r.RequireServiceType.(type) {
		case string:
			if result.ServiceDefinition.BaseInfo.ServiceType != st {
				return ErrAssessmentFailed
			}
		case TrustedServiceType:
			actualType := TrustedServiceTypeUnsupported
			switch result.ServiceDefinition.BaseInfo.ServiceType {
			case CAQCUri:
				actualType = TrustedServiceTypeCertificateAuthority
			case QTSTUri:
				actualType = TrustedServiceTypeTimeStampingAuthority
			}
			if actualType != st {
				return ErrAssessmentFailed
			}
		}
	}

	return nil
}
