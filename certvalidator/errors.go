// Package certvalidator provides X.509 certificate path validation.
// This file contains error types for certificate validation.
package certvalidator

import (
	"fmt"
	"time"
)

// CRLReason represents the reason for certificate revocation.
type CRLReason int

const (
	CRLReasonUnspecified          CRLReason = 0
	CRLReasonKeyCompromise        CRLReason = 1
	CRLReasonCACompromise         CRLReason = 2
	CRLReasonAffiliationChanged   CRLReason = 3
	CRLReasonSuperseded           CRLReason = 4
	CRLReasonCessationOfOperation CRLReason = 5
	CRLReasonCertificateHold      CRLReason = 6
	CRLReasonRemoveFromCRL        CRLReason = 8
	CRLReasonPrivilegeWithdrawn   CRLReason = 9
	CRLReasonAACompromise         CRLReason = 10
)

// String returns a human-readable representation of the CRL reason.
func (r CRLReason) String() string {
	switch r {
	case CRLReasonUnspecified:
		return "unspecified"
	case CRLReasonKeyCompromise:
		return "key compromise"
	case CRLReasonCACompromise:
		return "CA compromise"
	case CRLReasonAffiliationChanged:
		return "affiliation changed"
	case CRLReasonSuperseded:
		return "superseded"
	case CRLReasonCessationOfOperation:
		return "cessation of operation"
	case CRLReasonCertificateHold:
		return "certificate hold"
	case CRLReasonRemoveFromCRL:
		return "remove from CRL"
	case CRLReasonPrivilegeWithdrawn:
		return "privilege withdrawn"
	case CRLReasonAACompromise:
		return "AA compromise"
	default:
		return fmt.Sprintf("unknown reason (%d)", r)
	}
}

// PathError is the base error type for path-related errors.
type PathError struct {
	Message string
}

func (e *PathError) Error() string {
	return e.Message
}

// NewPathError creates a new PathError.
func NewPathError(message string) *PathError {
	return &PathError{Message: message}
}

// PathBuildingError occurs when a certificate path cannot be built.
type PathBuildingError struct {
	PathError
}

// NewPathBuildingError creates a new PathBuildingError.
func NewPathBuildingError(message string) *PathBuildingError {
	return &PathBuildingError{PathError: PathError{Message: message}}
}

// CertificateFetchError occurs when a certificate cannot be fetched.
type CertificateFetchError struct {
	PathBuildingError
}

// NewCertificateFetchError creates a new CertificateFetchError.
func NewCertificateFetchError(message string) *CertificateFetchError {
	return &CertificateFetchError{PathBuildingError: PathBuildingError{PathError: PathError{Message: message}}}
}

// CRLValidationError is the base error type for CRL validation errors.
type CRLValidationError struct {
	Message string
}

func (e *CRLValidationError) Error() string {
	return e.Message
}

// NewCRLValidationError creates a new CRLValidationError.
func NewCRLValidationError(message string) *CRLValidationError {
	return &CRLValidationError{Message: message}
}

// CRLNoMatchesError occurs when no matching CRL is found.
type CRLNoMatchesError struct {
	CRLValidationError
}

// NewCRLNoMatchesError creates a new CRLNoMatchesError.
func NewCRLNoMatchesError(message string) *CRLNoMatchesError {
	return &CRLNoMatchesError{CRLValidationError: CRLValidationError{Message: message}}
}

// CRLFetchError occurs when a CRL cannot be fetched.
type CRLFetchError struct {
	CRLValidationError
}

// NewCRLFetchError creates a new CRLFetchError.
func NewCRLFetchError(message string) *CRLFetchError {
	return &CRLFetchError{CRLValidationError: CRLValidationError{Message: message}}
}

// CRLValidationIndeterminateError occurs when CRL validation cannot be completed.
type CRLValidationIndeterminateError struct {
	CRLValidationError
	Failures     []string
	SuspectStale *time.Time
}

// NewCRLValidationIndeterminateError creates a new CRLValidationIndeterminateError.
func NewCRLValidationIndeterminateError(message string, failures []string, suspectStale *time.Time) *CRLValidationIndeterminateError {
	return &CRLValidationIndeterminateError{
		CRLValidationError: CRLValidationError{Message: message},
		Failures:           failures,
		SuspectStale:       suspectStale,
	}
}

// OCSPValidationError is the base error type for OCSP validation errors.
type OCSPValidationError struct {
	Message string
}

func (e *OCSPValidationError) Error() string {
	return e.Message
}

// NewOCSPValidationError creates a new OCSPValidationError.
func NewOCSPValidationError(message string) *OCSPValidationError {
	return &OCSPValidationError{Message: message}
}

// OCSPNoMatchesError occurs when no matching OCSP response is found.
type OCSPNoMatchesError struct {
	OCSPValidationError
}

// NewOCSPNoMatchesError creates a new OCSPNoMatchesError.
func NewOCSPNoMatchesError(message string) *OCSPNoMatchesError {
	return &OCSPNoMatchesError{OCSPValidationError: OCSPValidationError{Message: message}}
}

// OCSPValidationIndeterminateError occurs when OCSP validation cannot be completed.
type OCSPValidationIndeterminateError struct {
	OCSPValidationError
	Failures     []string
	SuspectStale *time.Time
}

// NewOCSPValidationIndeterminateError creates a new OCSPValidationIndeterminateError.
func NewOCSPValidationIndeterminateError(message string, failures []string, suspectStale *time.Time) *OCSPValidationIndeterminateError {
	return &OCSPValidationIndeterminateError{
		OCSPValidationError: OCSPValidationError{Message: message},
		Failures:            failures,
		SuspectStale:        suspectStale,
	}
}

// OCSPFetchError occurs when an OCSP response cannot be fetched.
type OCSPFetchError struct {
	OCSPValidationError
}

// NewOCSPFetchError creates a new OCSPFetchError.
func NewOCSPFetchError(message string) *OCSPFetchError {
	return &OCSPFetchError{OCSPValidationError: OCSPValidationError{Message: message}}
}

// ValidationError is the base error type for validation errors.
type ValidationError struct {
	FailureMsg string
}

func (e *ValidationError) Error() string {
	return e.FailureMsg
}

// NewValidationError creates a new ValidationError.
func NewValidationError(message string) *ValidationError {
	return &ValidationError{FailureMsg: message}
}

// PathValidationError occurs when path validation fails.
type PathValidationError struct {
	ValidationError
	IsEECert         bool
	IsSideValidation bool
	CurrentPath      *ValidationPath
	OriginalPath     *ValidationPath
}

// NewPathValidationError creates a new PathValidationError from validation state.
func NewPathValidationError(message string, procState *ValProcState) *PathValidationError {
	var currentPath, originalPath *ValidationPath

	if procState != nil && procState.CertPathStack != nil {
		currentPath = procState.CertPathStack.Head

		// Find the original (last) path in the stack
		for curr := procState.CertPathStack; curr != nil; curr = curr.Tail {
			originalPath = curr.Head
		}
	}

	isEECert := false
	isSideValidation := false
	if procState != nil {
		isEECert = procState.IsEECert()
		isSideValidation = procState.IsSideValidation
	}

	return &PathValidationError{
		ValidationError:  ValidationError{FailureMsg: message},
		IsEECert:         isEECert,
		IsSideValidation: isSideValidation,
		CurrentPath:      currentPath,
		OriginalPath:     originalPath,
	}
}

// FromState creates a PathValidationError from a validation state.
func (e *PathValidationError) FromState(msg string, procState *ValProcState) *PathValidationError {
	return NewPathValidationError(msg, procState)
}

// RevokedError indicates a certificate has been revoked.
type RevokedError struct {
	PathValidationError
	Reason       CRLReason
	RevocationDt time.Time
}

// NewRevokedError creates a new RevokedError.
func NewRevokedError(message string, reason CRLReason, revocationDt time.Time, procState *ValProcState) *RevokedError {
	return &RevokedError{
		PathValidationError: *NewPathValidationError(message, procState),
		Reason:              reason,
		RevocationDt:        revocationDt,
	}
}

// FormatRevokedError creates a formatted RevokedError.
func FormatRevokedError(reason CRLReason, revocationDt time.Time, revinfoType string, procState *ValProcState) *RevokedError {
	date := revocationDt.Format("2006-01-02")
	timeStr := revocationDt.Format("15:04:05")
	certDesc := "the certificate"
	if procState != nil {
		certDesc = procState.DescribeCert(true, false)
	}
	msg := fmt.Sprintf("%s indicates %s was revoked at %s on %s, due to %s.",
		revinfoType, certDesc, timeStr, date, reason.String())
	return NewRevokedError(msg, reason, revocationDt, procState)
}

// InsufficientRevinfoError indicates insufficient revocation information.
type InsufficientRevinfoError struct {
	PathValidationError
}

// NewInsufficientRevinfoError creates a new InsufficientRevinfoError.
func NewInsufficientRevinfoError(message string, procState *ValProcState) *InsufficientRevinfoError {
	return &InsufficientRevinfoError{
		PathValidationError: *NewPathValidationError(message, procState),
	}
}

// StaleRevinfoError indicates stale revocation information.
type StaleRevinfoError struct {
	InsufficientRevinfoError
	TimeCutoff time.Time
}

// NewStaleRevinfoError creates a new StaleRevinfoError.
func NewStaleRevinfoError(message string, timeCutoff time.Time, procState *ValProcState) *StaleRevinfoError {
	return &StaleRevinfoError{
		InsufficientRevinfoError: *NewInsufficientRevinfoError(message, procState),
		TimeCutoff:               timeCutoff,
	}
}

// FormatStaleRevinfoError creates a formatted StaleRevinfoError.
func FormatStaleRevinfoError(message string, timeCutoff time.Time, procState *ValProcState) *StaleRevinfoError {
	return NewStaleRevinfoError(message, timeCutoff, procState)
}

// InsufficientPOEError indicates insufficient proof of existence.
type InsufficientPOEError struct {
	PathValidationError
}

// NewInsufficientPOEError creates a new InsufficientPOEError.
func NewInsufficientPOEError(message string, procState *ValProcState) *InsufficientPOEError {
	return &InsufficientPOEError{
		PathValidationError: *NewPathValidationError(message, procState),
	}
}

// ExpiredError indicates a certificate has expired.
type ExpiredError struct {
	PathValidationError
	ExpiredDt time.Time
}

// NewExpiredError creates a new ExpiredError.
func NewExpiredError(message string, expiredDt time.Time, procState *ValProcState) *ExpiredError {
	return &ExpiredError{
		PathValidationError: *NewPathValidationError(message, procState),
		ExpiredDt:           expiredDt,
	}
}

// FormatExpiredError creates a formatted ExpiredError.
func FormatExpiredError(expiredDt time.Time, procState *ValProcState) *ExpiredError {
	certDesc := "the certificate"
	if procState != nil {
		certDesc = procState.DescribeCert(true, false)
	}
	msg := fmt.Sprintf("The path could not be validated because %s expired %s",
		certDesc, expiredDt.Format("2006-01-02 15:04:05Z"))
	return NewExpiredError(msg, expiredDt, procState)
}

// NotYetValidError indicates a certificate is not yet valid.
type NotYetValidError struct {
	PathValidationError
	ValidFrom time.Time
}

// NewNotYetValidError creates a new NotYetValidError.
func NewNotYetValidError(message string, validFrom time.Time, procState *ValProcState) *NotYetValidError {
	return &NotYetValidError{
		PathValidationError: *NewPathValidationError(message, procState),
		ValidFrom:           validFrom,
	}
}

// FormatNotYetValidError creates a formatted NotYetValidError.
func FormatNotYetValidError(validFrom time.Time, procState *ValProcState) *NotYetValidError {
	certDesc := "the certificate"
	if procState != nil {
		certDesc = procState.DescribeCert(true, false)
	}
	msg := fmt.Sprintf("The path could not be validated because %s is not valid until %s",
		certDesc, validFrom.Format("2006-01-02 15:04:05Z"))
	return NewNotYetValidError(msg, validFrom, procState)
}

// InvalidCertificateError indicates an invalid certificate.
type InvalidCertificateError struct {
	ValidationError
}

// NewInvalidCertificateError creates a new InvalidCertificateError.
func NewInvalidCertificateError(message string) *InvalidCertificateError {
	return &InvalidCertificateError{
		ValidationError: ValidationError{FailureMsg: message},
	}
}

// DisallowedAlgorithmError indicates a disallowed algorithm was used.
type DisallowedAlgorithmError struct {
	PathValidationError
	BannedSince *time.Time
}

// NewDisallowedAlgorithmError creates a new DisallowedAlgorithmError.
func NewDisallowedAlgorithmError(message string, procState *ValProcState, bannedSince *time.Time) *DisallowedAlgorithmError {
	return &DisallowedAlgorithmError{
		PathValidationError: *NewPathValidationError(message, procState),
		BannedSince:         bannedSince,
	}
}

// FromState creates a DisallowedAlgorithmError from a validation state.
func (e *DisallowedAlgorithmError) FromState(msg string, procState *ValProcState, bannedSince *time.Time) *DisallowedAlgorithmError {
	return NewDisallowedAlgorithmError(msg, procState, bannedSince)
}

// InvalidAttrCertificateError indicates an invalid attribute certificate.
type InvalidAttrCertificateError struct {
	InvalidCertificateError
}

// NewInvalidAttrCertificateError creates a new InvalidAttrCertificateError.
func NewInvalidAttrCertificateError(message string) *InvalidAttrCertificateError {
	return &InvalidAttrCertificateError{
		InvalidCertificateError: *NewInvalidCertificateError(message),
	}
}

// PSSParameterMismatch indicates PSS parameters don't match.
type PSSParameterMismatch struct {
	Message string
}

func (e *PSSParameterMismatch) Error() string {
	return e.Message
}

// NewPSSParameterMismatch creates a new PSSParameterMismatch error.
func NewPSSParameterMismatch(message string) *PSSParameterMismatch {
	return &PSSParameterMismatch{Message: message}
}

// DSAParametersUnavailable indicates DSA parameters are not available.
type DSAParametersUnavailable struct {
	Message string
}

func (e *DSAParametersUnavailable) Error() string {
	return e.Message
}

// NewDSAParametersUnavailable creates a new DSAParametersUnavailable error.
func NewDSAParametersUnavailable(message string) *DSAParametersUnavailable {
	return &DSAParametersUnavailable{Message: message}
}

// AlgorithmNotSupported indicates an algorithm is not supported.
type AlgorithmNotSupported struct {
	Message string
}

func (e *AlgorithmNotSupported) Error() string {
	return e.Message
}

// NewAlgorithmNotSupported creates a new AlgorithmNotSupported error.
func NewAlgorithmNotSupported(message string) *AlgorithmNotSupported {
	return &AlgorithmNotSupported{Message: message}
}

// NameConstraintError indicates a name constraint violation.
type NameConstraintError struct {
	Message string
}

func (e *NameConstraintError) Error() string {
	return e.Message
}

// NewNameConstraintError creates a new NameConstraintError.
func NewNameConstraintError(message string) *NameConstraintError {
	return &NameConstraintError{Message: message}
}

// UnsupportedNameTypeError indicates an unsupported general name type.
type UnsupportedNameTypeError struct {
	Message  string
	NameType int
}

func (e *UnsupportedNameTypeError) Error() string {
	return e.Message
}

// NewUnsupportedNameTypeError creates a new UnsupportedNameTypeError.
func NewUnsupportedNameTypeError(nameType int) *UnsupportedNameTypeError {
	return &UnsupportedNameTypeError{
		Message:  fmt.Sprintf("unsupported general name type: %d", nameType),
		NameType: nameType,
	}
}

// Errors is a utility for collecting multiple errors during validation.
type Errors struct {
	errors []error
}

// NewErrors creates a new Errors collector.
func NewErrors() *Errors {
	return &Errors{
		errors: make([]error, 0),
	}
}

// Add adds an error to the collection.
func (e *Errors) Add(err error) {
	if err != nil {
		e.errors = append(e.errors, err)
	}
}

// HasErrors returns true if any errors have been collected.
func (e *Errors) HasErrors() bool {
	return len(e.errors) > 0
}

// Count returns the number of errors collected.
func (e *Errors) Count() int {
	return len(e.errors)
}

// All returns all collected errors.
func (e *Errors) All() []error {
	return e.errors
}

// First returns the first error, or nil if none.
func (e *Errors) First() error {
	if len(e.errors) == 0 {
		return nil
	}
	return e.errors[0]
}

// Combined returns a single error combining all collected errors.
func (e *Errors) Combined() error {
	if len(e.errors) == 0 {
		return nil
	}
	if len(e.errors) == 1 {
		return e.errors[0]
	}

	msg := fmt.Sprintf("%d validation errors:", len(e.errors))
	for i, err := range e.errors {
		msg += fmt.Sprintf("\n  %d. %s", i+1, err.Error())
	}
	return fmt.Errorf("%s", msg)
}

// Clear removes all collected errors.
func (e *Errors) Clear() {
	e.errors = e.errors[:0]
}
