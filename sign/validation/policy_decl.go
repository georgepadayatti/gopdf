// Package validation provides PDF signature validation.
// This file contains validation policy declarations.
package validation

import (
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/georgepadayatti/gopdf/certvalidator"
)

// RevinfoOnlineFetchingRule describes the revocation info online fetching behaviour.
type RevinfoOnlineFetchingRule int

const (
	// RevinfoOnlineFetchNever never fetches revocation info online.
	RevinfoOnlineFetchNever RevinfoOnlineFetchingRule = iota
	// RevinfoOnlineFetchIfConvenient fetches revocation info online if convenient.
	RevinfoOnlineFetchIfConvenient
	// RevinfoOnlineFetchAlways always fetches revocation info online.
	RevinfoOnlineFetchAlways
)

// String returns the string representation of the online fetching rule.
func (r RevinfoOnlineFetchingRule) String() string {
	switch r {
	case RevinfoOnlineFetchNever:
		return "never"
	case RevinfoOnlineFetchIfConvenient:
		return "if-convenient"
	case RevinfoOnlineFetchAlways:
		return "always"
	default:
		return "unknown"
	}
}

// RevocationInfoGatheringSpec specifies how to gather revocation info.
type RevocationInfoGatheringSpec struct {
	// OnlineFetching controls online fetching behavior.
	OnlineFetching RevinfoOnlineFetchingRule

	// AllowFetchers restricts which fetchers can be used (nil means all).
	AllowFetchers []string

	// HTTPTimeout is the timeout for HTTP requests.
	HTTPTimeout time.Duration

	// UseAIA controls whether to use Authority Information Access extension.
	UseAIA bool
}

// NewRevocationInfoGatheringSpec creates a new spec with defaults.
func NewRevocationInfoGatheringSpec() *RevocationInfoGatheringSpec {
	return &RevocationInfoGatheringSpec{
		OnlineFetching: RevinfoOnlineFetchIfConvenient,
		HTTPTimeout:    30 * time.Second,
		UseAIA:         true,
	}
}

// NewOfflineRevocationInfoGatheringSpec creates a spec for offline validation.
func NewOfflineRevocationInfoGatheringSpec() *RevocationInfoGatheringSpec {
	return &RevocationInfoGatheringSpec{
		OnlineFetching: RevinfoOnlineFetchNever,
		HTTPTimeout:    30 * time.Second,
		UseAIA:         false,
	}
}

// LocalKnowledge represents locally available validation material.
type LocalKnowledge struct {
	// Certs are additional certificates.
	Certs []*x509.Certificate

	// CRLs are CRL data.
	CRLs [][]byte

	// OCSPs are OCSP response data.
	OCSPs [][]byte

	// OtherRevInfo is other revocation information (e.g., from AdES signatures).
	// Key is OID string representation.
	OtherRevInfo map[string][][]byte

	// NonRevokedAssertions are pre-verified non-revoked assertions.
	NonRevokedAssertions []*certvalidator.NonRevokedStatusAssertion
}

// NewLocalKnowledge creates an empty LocalKnowledge instance.
func NewLocalKnowledge() *LocalKnowledge {
	return &LocalKnowledge{
		OtherRevInfo: make(map[string][][]byte),
	}
}

// AddOtherRevInfo adds other revocation info by OID.
func (lk *LocalKnowledge) AddOtherRevInfo(oid asn1.ObjectIdentifier, data []byte) {
	key := oid.String()
	lk.OtherRevInfo[key] = append(lk.OtherRevInfo[key], data)
}

// GetOtherRevInfo retrieves other revocation info by OID.
func (lk *LocalKnowledge) GetOtherRevInfo(oid asn1.ObjectIdentifier) [][]byte {
	return lk.OtherRevInfo[oid.String()]
}

// Merge combines this LocalKnowledge with another.
func (lk *LocalKnowledge) Merge(other *LocalKnowledge) *LocalKnowledge {
	if other == nil {
		return lk
	}

	result := &LocalKnowledge{
		Certs:                append(lk.Certs, other.Certs...),
		CRLs:                 append(lk.CRLs, other.CRLs...),
		OCSPs:                append(lk.OCSPs, other.OCSPs...),
		NonRevokedAssertions: append(lk.NonRevokedAssertions, other.NonRevokedAssertions...),
		OtherRevInfo:         make(map[string][][]byte),
	}

	// Merge OtherRevInfo maps
	for oid, data := range lk.OtherRevInfo {
		result.OtherRevInfo[oid] = append(result.OtherRevInfo[oid], data...)
	}
	for oid, data := range other.OtherRevInfo {
		result.OtherRevInfo[oid] = append(result.OtherRevInfo[oid], data...)
	}

	return result
}

// IsEmpty returns true if no local knowledge is present.
func (lk *LocalKnowledge) IsEmpty() bool {
	return len(lk.Certs) == 0 && len(lk.CRLs) == 0 &&
		len(lk.OCSPs) == 0 && len(lk.OtherRevInfo) == 0 &&
		len(lk.NonRevokedAssertions) == 0
}

// QualificationRequirements specifies signature qualification requirements.
type QualificationRequirements struct {
	// RequireQualifiedSignature requires a qualified electronic signature (QES).
	RequireQualifiedSignature bool

	// RequireQualifiedTimestamp requires a qualified timestamp.
	RequireQualifiedTimestamp bool

	// RequireQSCD requires a Qualified Signature Creation Device.
	RequireQSCD bool

	// AcceptedTrustServices lists acceptable trust service providers.
	// If nil, any qualified trust service is accepted.
	AcceptedTrustServices []string

	// EidasCompliance requires eIDAS compliance.
	EidasCompliance bool
}

// NewQualificationRequirements creates requirements with defaults.
func NewQualificationRequirements() *QualificationRequirements {
	return &QualificationRequirements{}
}

// SignatureValidationSpec specifies how to validate a signature.
type SignatureValidationSpec struct {
	// TrustManager provides trust anchors for certificate validation.
	TrustManager certvalidator.TrustManager

	// CertRegistry provides certificate storage and retrieval.
	CertRegistry *certvalidator.CertificateRegistry

	// ValidationTime is the time to use for validation.
	// If zero, the current time or signature time is used.
	ValidationTime time.Time

	// PKIXParams are PKIX path validation parameters.
	PKIXParams *certvalidator.PKIXValidationParams

	// RevocationPolicy controls revocation checking.
	RevocationPolicy *certvalidator.CertRevTrustPolicy

	// RevocationGathering controls how revocation info is gathered.
	RevocationGathering *RevocationInfoGatheringSpec

	// AlgorithmPolicy controls algorithm acceptance.
	AlgorithmPolicy certvalidator.AlgorithmUsagePolicy

	// LocalKnowledge provides additional validation material.
	LocalKnowledge *LocalKnowledge

	// Qualifications specifies qualification requirements.
	Qualifications *QualificationRequirements

	// KeyUsage specifies required key usage bits.
	KeyUsage x509.KeyUsage

	// ExtKeyUsage specifies required extended key usage OIDs.
	ExtKeyUsage []x509.ExtKeyUsage

	// AllowSHA1 allows SHA-1 signatures if the policy otherwise forbids them.
	AllowSHA1 bool

	// AllowExpiredCerts allows validation with expired certificates.
	AllowExpiredCerts bool
}

// NewSignatureValidationSpec creates a new spec with defaults.
func NewSignatureValidationSpec(trustManager certvalidator.TrustManager) *SignatureValidationSpec {
	return &SignatureValidationSpec{
		TrustManager:        trustManager,
		PKIXParams:          certvalidator.DefaultPKIXValidationParams(),
		RevocationPolicy:    certvalidator.NewCertRevTrustPolicy(certvalidator.RequireRevInfo),
		RevocationGathering: NewRevocationInfoGatheringSpec(),
		AlgorithmPolicy:     certvalidator.NewDisallowWeakAlgorithmsPolicy(),
		LocalKnowledge:      NewLocalKnowledge(),
	}
}

// WithValidationTime sets the validation time.
func (s *SignatureValidationSpec) WithValidationTime(t time.Time) *SignatureValidationSpec {
	s.ValidationTime = t
	return s
}

// WithRevocationPolicy sets the revocation policy.
func (s *SignatureValidationSpec) WithRevocationPolicy(policy *certvalidator.CertRevTrustPolicy) *SignatureValidationSpec {
	s.RevocationPolicy = policy
	return s
}

// WithAlgorithmPolicy sets the algorithm policy.
func (s *SignatureValidationSpec) WithAlgorithmPolicy(policy certvalidator.AlgorithmUsagePolicy) *SignatureValidationSpec {
	s.AlgorithmPolicy = policy
	return s
}

// WithLocalKnowledge sets additional validation material.
func (s *SignatureValidationSpec) WithLocalKnowledge(lk *LocalKnowledge) *SignatureValidationSpec {
	s.LocalKnowledge = lk
	return s
}

// SignatureType indicates the type of signature.
type SignatureType int

const (
	// SignatureTypeUnknown is an unknown signature type.
	SignatureTypeUnknown SignatureType = iota
	// SignatureTypeApproval is an approval signature.
	SignatureTypeApproval
	// SignatureTypeCertification is a certification/author signature.
	SignatureTypeCertification
	// SignatureTypeDocTimestamp is a document timestamp.
	SignatureTypeDocTimestamp
	// SignatureTypeUsageRights is a usage rights signature.
	SignatureTypeUsageRights
)

// String returns the string representation of the signature type.
func (t SignatureType) String() string {
	switch t {
	case SignatureTypeApproval:
		return "approval"
	case SignatureTypeCertification:
		return "certification"
	case SignatureTypeDocTimestamp:
		return "doc_timestamp"
	case SignatureTypeUsageRights:
		return "usage_rights"
	default:
		return "unknown"
	}
}

// PdfSignatureValidationSpec specifies PDF-specific signature validation.
type PdfSignatureValidationSpec struct {
	// SignatureValidationSpec contains the base validation spec.
	*SignatureValidationSpec

	// ExpectedSignatureType is the expected signature type (or zero for any).
	ExpectedSignatureType SignatureType

	// AllowMultipleSignatures allows multiple signatures in the document.
	AllowMultipleSignatures bool

	// DiffPolicy controls modification detection between revisions.
	DiffPolicy *DiffPolicy

	// RequireDocMDP requires a specific DocMDP permission level.
	RequireDocMDP DocMDPLevel

	// TimestampValidationSpec specifies how to validate document timestamps.
	TimestampValidationSpec *SignatureValidationSpec

	// EmbeddedTimestampValidationSpec specifies how to validate embedded timestamps.
	EmbeddedTimestampValidationSpec *SignatureValidationSpec

	// LTVRequired requires LTV (Long-Term Validation) material.
	LTVRequired bool

	// DSSRequired requires a Document Security Store.
	DSSRequired bool

	// RequireExactByteRanges requires exact byte range coverage.
	RequireExactByteRanges bool

	// RequireContiguous requires contiguous signature coverage.
	RequireContiguous bool
}

// DocMDPLevel represents document modification permission levels.
type DocMDPLevel int

const (
	// DocMDPNone has no DocMDP requirement.
	DocMDPNone DocMDPLevel = 0
	// DocMDPNoChanges allows no changes.
	DocMDPNoChanges DocMDPLevel = 1
	// DocMDPFormFilling allows form filling and signing.
	DocMDPFormFilling DocMDPLevel = 2
	// DocMDPAnnotations allows annotations, form filling, and signing.
	DocMDPAnnotations DocMDPLevel = 3
)

// String returns the string representation of the DocMDP level.
func (l DocMDPLevel) String() string {
	switch l {
	case DocMDPNoChanges:
		return "no_changes"
	case DocMDPFormFilling:
		return "form_filling"
	case DocMDPAnnotations:
		return "annotations"
	default:
		return "none"
	}
}

// DiffPolicy controls how modifications are detected between revisions.
type DiffPolicy struct {
	// GlobalPolicy applies to all revision comparisons.
	GlobalPolicy ModificationPolicy

	// FormFillingPolicy applies to form field modifications.
	FormFillingPolicy ModificationPolicy

	// AnnotationPolicy applies to annotation modifications.
	AnnotationPolicy ModificationPolicy
}

// ModificationPolicy controls how specific modifications are handled.
type ModificationPolicy int

const (
	// ModificationPolicyAllow allows modifications.
	ModificationPolicyAllow ModificationPolicy = iota
	// ModificationPolicyWarn warns about modifications.
	ModificationPolicyWarn
	// ModificationPolicyForbid forbids modifications.
	ModificationPolicyForbid
)

// NewDiffPolicy creates a default diff policy.
func NewDiffPolicy() *DiffPolicy {
	return &DiffPolicy{
		GlobalPolicy:      ModificationPolicyForbid,
		FormFillingPolicy: ModificationPolicyAllow,
		AnnotationPolicy:  ModificationPolicyWarn,
	}
}

// NewPdfSignatureValidationSpec creates a new PDF signature validation spec.
func NewPdfSignatureValidationSpec(trustManager certvalidator.TrustManager) *PdfSignatureValidationSpec {
	return &PdfSignatureValidationSpec{
		SignatureValidationSpec: NewSignatureValidationSpec(trustManager),
		DiffPolicy:              NewDiffPolicy(),
		AllowMultipleSignatures: true,
		RequireContiguous:       true,
	}
}

// WithExpectedSignatureType sets the expected signature type.
func (s *PdfSignatureValidationSpec) WithExpectedSignatureType(t SignatureType) *PdfSignatureValidationSpec {
	s.ExpectedSignatureType = t
	return s
}

// WithDocMDPRequirement sets the required DocMDP level.
func (s *PdfSignatureValidationSpec) WithDocMDPRequirement(level DocMDPLevel) *PdfSignatureValidationSpec {
	s.RequireDocMDP = level
	return s
}

// WithLTVRequired sets whether LTV material is required.
func (s *PdfSignatureValidationSpec) WithLTVRequired(required bool) *PdfSignatureValidationSpec {
	s.LTVRequired = required
	return s
}

// ValidationDataHandler handles validation data collection.
type ValidationDataHandler interface {
	// CollectCertificates collects certificates from a source.
	CollectCertificates(source interface{}) ([]*x509.Certificate, error)

	// CollectCRLs collects CRLs from a source.
	CollectCRLs(source interface{}) ([][]byte, error)

	// CollectOCSPs collects OCSP responses from a source.
	CollectOCSPs(source interface{}) ([][]byte, error)
}

// ValidationDataHandlers is a collection of validation data handlers.
type ValidationDataHandlers struct {
	handlers map[string]ValidationDataHandler
}

// NewValidationDataHandlers creates a new handler collection.
func NewValidationDataHandlers() *ValidationDataHandlers {
	return &ValidationDataHandlers{
		handlers: make(map[string]ValidationDataHandler),
	}
}

// Register adds a handler for a specific type.
func (h *ValidationDataHandlers) Register(typeName string, handler ValidationDataHandler) {
	h.handlers[typeName] = handler
}

// Get returns the handler for a specific type.
func (h *ValidationDataHandlers) Get(typeName string) (ValidationDataHandler, bool) {
	handler, ok := h.handlers[typeName]
	return handler, ok
}

// BootstrapValidationDataHandlers creates handlers with default configuration.
func BootstrapValidationDataHandlers() *ValidationDataHandlers {
	handlers := NewValidationDataHandlers()
	// Register default handlers
	handlers.Register("dss", &DSSValidationDataHandler{})
	handlers.Register("cms", &CMSValidationDataHandler{})
	return handlers
}

// DSSValidationDataHandler handles DSS (Document Security Store) data.
type DSSValidationDataHandler struct{}

// CollectCertificates extracts certificates from DSS.
func (h *DSSValidationDataHandler) CollectCertificates(source interface{}) ([]*x509.Certificate, error) {
	dss, ok := source.(*DocumentSecurityStore)
	if !ok {
		return nil, nil
	}
	return dss.Certs, nil
}

// CollectCRLs extracts CRLs from DSS.
func (h *DSSValidationDataHandler) CollectCRLs(source interface{}) ([][]byte, error) {
	dss, ok := source.(*DocumentSecurityStore)
	if !ok {
		return nil, nil
	}
	return dss.CRLs, nil
}

// CollectOCSPs extracts OCSP responses from DSS.
func (h *DSSValidationDataHandler) CollectOCSPs(source interface{}) ([][]byte, error) {
	dss, ok := source.(*DocumentSecurityStore)
	if !ok {
		return nil, nil
	}
	return dss.OCSPs, nil
}

// CMSValidationDataHandler handles CMS signature data.
type CMSValidationDataHandler struct{}

// CollectCertificates extracts certificates from CMS data.
func (h *CMSValidationDataHandler) CollectCertificates(source interface{}) ([]*x509.Certificate, error) {
	// Implementation depends on CMS package
	return nil, nil
}

// CollectCRLs extracts CRLs from CMS data.
func (h *CMSValidationDataHandler) CollectCRLs(source interface{}) ([][]byte, error) {
	return nil, nil
}

// CollectOCSPs extracts OCSP responses from CMS data.
func (h *CMSValidationDataHandler) CollectOCSPs(source interface{}) ([][]byte, error) {
	return nil, nil
}

// ValidationSpecPresets contains preset validation specifications.
var ValidationSpecPresets = map[string]func(certvalidator.TrustManager) *PdfSignatureValidationSpec{
	"strict": func(tm certvalidator.TrustManager) *PdfSignatureValidationSpec {
		spec := NewPdfSignatureValidationSpec(tm)
		spec.RevocationPolicy = certvalidator.NewCertRevTrustPolicy(certvalidator.RequireRevInfo)
		spec.LTVRequired = true
		spec.DSSRequired = true
		spec.RequireExactByteRanges = true
		return spec
	},
	"relaxed": func(tm certvalidator.TrustManager) *PdfSignatureValidationSpec {
		spec := NewPdfSignatureValidationSpec(tm)
		spec.RevocationPolicy = certvalidator.NewCertRevTrustPolicy(certvalidator.NoRevocation)
		spec.AllowExpiredCerts = true
		spec.DiffPolicy.GlobalPolicy = ModificationPolicyWarn
		return spec
	},
	"offline": func(tm certvalidator.TrustManager) *PdfSignatureValidationSpec {
		spec := NewPdfSignatureValidationSpec(tm)
		spec.RevocationGathering = NewOfflineRevocationInfoGatheringSpec()
		spec.RevocationPolicy = certvalidator.NewCertRevTrustPolicy(
			certvalidator.NewRevocationCheckingPolicy(
				certvalidator.RevocationRuleCheckIfDeclaredSoft,
				certvalidator.RevocationRuleCheckIfDeclaredSoft,
			),
		)
		return spec
	},
}

// GetValidationSpecPreset returns a preset validation spec by name.
func GetValidationSpecPreset(name string, trustManager certvalidator.TrustManager) *PdfSignatureValidationSpec {
	if preset, ok := ValidationSpecPresets[name]; ok {
		return preset(trustManager)
	}
	return NewPdfSignatureValidationSpec(trustManager)
}
