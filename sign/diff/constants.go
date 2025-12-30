// Package diff provides difference analysis for PDF document validation.
// This file contains internal constants for the difference analysis sub-package.
package diff

import (
	"regexp"
)

// FormFieldAlwaysModifiable contains keys in form fields that can always be modified.
// - /Type: dictionary type (can always be added if correct)
// - /Ff: Form field flags
var FormFieldAlwaysModifiable = map[string]bool{
	"/Ff":   true,
	"/Type": true,
}

// ValueUpdateKeys contains keys that may change when updating a field value.
// This includes FormFieldAlwaysModifiable plus:
// - /AP: appearance dictionary
// - /AS: current appearance state
// - /V: field value
// - /F: (widget) annotation flags
// - /DA: default appearance
// - /Q: quadding
var ValueUpdateKeys = map[string]bool{
	// From FormFieldAlwaysModifiable
	"/Ff":   true,
	"/Type": true,
	// Additional value update keys
	"/AP": true,
	"/AS": true,
	"/V":  true,
	"/F":  true,
	"/DA": true,
	"/Q":  true,
}

// VRIKeyPattern matches VRI dictionary keys (40-character uppercase hex strings).
// Pattern: /[A-Z0-9]{40}
var VRIKeyPattern = regexp.MustCompile(`^/[A-Z0-9]{40}$`)

// AcroFormExemptStrictComparison contains keys in AcroForm that may change between revisions.
var AcroFormExemptStrictComparison = map[string]bool{
	"/Fields":          true,
	"/DR":              true,
	"/DA":              true,
	"/Q":               true,
	"/NeedAppearances": true,
}

// Note: ROOT_EXEMPT_STRICT_COMPARISON is already defined in file_structure_rules.go
// as RootExemptStrictComparison

// SignatureFieldKeys contains keys specific to signature fields.
var SignatureFieldKeys = map[string]bool{
	"/Lock": true,
	"/SV":   true,
}

// DSSStreamKeys contains keys in DSS dictionary that should contain stream arrays.
var DSSStreamKeys = map[string]bool{
	"/Certs": true,
	"/CRLs":  true,
	"/OCSPs": true,
}

// DSSExpectedKeys contains all expected keys in a DSS dictionary.
var DSSExpectedKeys = map[string]bool{
	"/Type":  true,
	"/VRI":   true,
	"/Certs": true,
	"/CRLs":  true,
	"/OCSPs": true,
}

// VRIStreamKeys contains keys in VRI dictionary entries that should contain stream arrays.
var VRIStreamKeys = map[string]bool{
	"/Cert": true,
	"/CRL":  true,
	"/OCSP": true,
}

// VRIExpectedKeys contains all expected keys in a VRI dictionary entry.
var VRIExpectedKeys = map[string]bool{
	"/Type": true,
	"/TU":   true,
	"/TS":   true,
	"/Cert": true,
	"/CRL":  true,
	"/OCSP": true,
}

// AppearanceKeys contains keys used in appearance dictionaries.
var AppearanceKeys = map[string]bool{
	"/N": true, // Normal appearance
	"/R": true, // Rollover appearance
	"/D": true, // Down appearance
}

// AnnotationFlagBits defines bit positions for annotation flags.
type AnnotationFlagBits int

const (
	// AnnotFlagInvisible - annotation is invisible
	AnnotFlagInvisible AnnotationFlagBits = 1 << 0
	// AnnotFlagHidden - annotation is hidden
	AnnotFlagHidden AnnotationFlagBits = 1 << 1
	// AnnotFlagPrint - annotation should be printed
	AnnotFlagPrint AnnotationFlagBits = 1 << 2
	// AnnotFlagNoZoom - annotation should not scale with page
	AnnotFlagNoZoom AnnotationFlagBits = 1 << 3
	// AnnotFlagNoRotate - annotation should not rotate with page
	AnnotFlagNoRotate AnnotationFlagBits = 1 << 4
	// AnnotFlagNoView - annotation should not be displayed on screen
	AnnotFlagNoView AnnotationFlagBits = 1 << 5
	// AnnotFlagReadOnly - annotation should not be interactive
	AnnotFlagReadOnly AnnotationFlagBits = 1 << 6
	// AnnotFlagLocked - annotation should not be deleted or modified
	AnnotFlagLocked AnnotationFlagBits = 1 << 7
	// AnnotFlagToggleNoView - toggle NoView flag
	AnnotFlagToggleNoView AnnotationFlagBits = 1 << 8
	// AnnotFlagLockedContents - contents should not be modified
	AnnotFlagLockedContents AnnotationFlagBits = 1 << 9
)

// FormFieldFlagBits defines bit positions for form field flags.
type FormFieldFlagBits int

const (
	// FieldFlagReadOnly - field is read-only
	FieldFlagReadOnly FormFieldFlagBits = 1 << 0
	// FieldFlagRequired - field is required
	FieldFlagRequired FormFieldFlagBits = 1 << 1
	// FieldFlagNoExport - field should not be exported
	FieldFlagNoExport FormFieldFlagBits = 1 << 2
)

// SignatureFieldType constants.
const (
	// SigFieldTypeSignature indicates a regular signature field
	SigFieldTypeSignature = "/Sig"
	// SigFieldTypeDocTimeStamp indicates a document timestamp field
	SigFieldTypeDocTimeStamp = "/DocTimeStamp"
)

// IsVRIKey checks if a key matches the VRI key pattern.
func IsVRIKey(key string) bool {
	return VRIKeyPattern.MatchString(key)
}

// IsFormFieldAlwaysModifiable checks if a key can always be modified in form fields.
func IsFormFieldAlwaysModifiable(key string) bool {
	return FormFieldAlwaysModifiable[key]
}

// IsValueUpdateKey checks if a key is a value update key.
func IsValueUpdateKey(key string) bool {
	return ValueUpdateKeys[key]
}

// IsAcroFormExempt checks if a key is exempt from strict comparison in AcroForm.
func IsAcroFormExempt(key string) bool {
	return AcroFormExemptStrictComparison[key]
}

// IsDSSExpectedKey checks if a key is expected in a DSS dictionary.
func IsDSSExpectedKey(key string) bool {
	return DSSExpectedKeys[key]
}

// IsVRIExpectedKey checks if a key is expected in a VRI dictionary entry.
func IsVRIExpectedKey(key string) bool {
	return VRIExpectedKeys[key]
}
