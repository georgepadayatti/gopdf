// Package diff provides difference analysis for PDF document validation.
package diff

import (
	"errors"
	"fmt"
	"strings"

	"github.com/georgepadayatti/gopdf/pdf/form"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors
var (
	ErrSuspiciousModification = errors.New("suspicious modification detected")
	ErrUnexpectedStream       = errors.New("unexpected stream object")
	ErrKeyDeleted             = errors.New("key was deleted from dictionary")
	ErrDictKeysDiffer         = errors.New("dictionary keys differ")
	ErrValuesDiffer           = errors.New("values differ")
)

// SuspiciousModification represents a detected suspicious change.
type SuspiciousModification struct {
	Message string
}

func (s *SuspiciousModification) Error() string {
	return s.Message
}

// ModificationLevel represents the semantic modification level of a document.
type ModificationLevel int

const (
	// ModificationNone - document not modified at all
	ModificationNone ModificationLevel = iota
	// ModificationLTAUpdates - only LTA-type updates (DSS, timestamps)
	ModificationLTAUpdates
	// ModificationFormFilling - form filling and signatures
	ModificationFormFilling
	// ModificationAnnotations - annotation modifications allowed
	ModificationAnnotations
	// ModificationOther - other modifications not on whitelist
	ModificationOther
)

// String returns string representation of ModificationLevel.
func (m ModificationLevel) String() string {
	switch m {
	case ModificationNone:
		return "None"
	case ModificationLTAUpdates:
		return "LTA Updates"
	case ModificationFormFilling:
		return "Form Filling"
	case ModificationAnnotations:
		return "Annotations"
	case ModificationOther:
		return "Other"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

// IsAllowed returns true if the modification level is allowed by the given MDP permission.
func (m ModificationLevel) IsAllowed(mdpPerm form.MDPPerm) bool {
	switch mdpPerm {
	case form.MDPPermNoChanges:
		return m == ModificationNone || m == ModificationLTAUpdates
	case form.MDPPermFillForms:
		return m <= ModificationFormFilling
	case form.MDPPermAnnotate:
		return m <= ModificationAnnotations
	default:
		return m <= ModificationFormFilling
	}
}

// DiffResult encodes the result of a difference analysis.
type DiffResult struct {
	// ModificationLevel is the strictest level at which all changes pass.
	ModificationLevel ModificationLevel

	// ChangedFormFields contains names of all changed form fields.
	ChangedFormFields []string

	// Suspicious indicates if suspicious modifications were detected.
	Suspicious bool

	// Details provides additional information about detected changes.
	Details []string
}

// ReferenceUpdate represents an update to a PDF object reference.
type ReferenceUpdate struct {
	Reference       *generic.Reference
	OldValue        generic.PdfObject
	NewValue        generic.PdfObject
	Level           ModificationLevel
	ValidWhenLocked bool
}

// FormUpdate represents an update to a form field.
type FormUpdate struct {
	FieldName       string
	Update          *ReferenceUpdate
	ValidWhenLocked bool
}

// DiffPolicy defines the interface for difference analysis policies.
type DiffPolicy interface {
	// Apply analyzes differences between two revisions.
	Apply(old, new *RevisionState, fieldMDP *FieldMDPSpec, docMDP *form.MDPPerm) (*DiffResult, error)
}

// FieldMDPSpec specifies field modification detection policy.
type FieldMDPSpec struct {
	Action FieldMDPAction
	Fields []string
}

// FieldMDPAction specifies the action type.
type FieldMDPAction string

const (
	FieldMDPActionAll     FieldMDPAction = "All"
	FieldMDPActionInclude FieldMDPAction = "Include"
	FieldMDPActionExclude FieldMDPAction = "Exclude"
)

// IsFieldLocked returns true if the field should be locked according to this spec.
func (f *FieldMDPSpec) IsFieldLocked(fieldName string) bool {
	if f == nil {
		return false
	}

	switch f.Action {
	case FieldMDPActionAll:
		return true
	case FieldMDPActionInclude:
		for _, name := range f.Fields {
			if name == fieldName {
				return true
			}
		}
		return false
	case FieldMDPActionExclude:
		for _, name := range f.Fields {
			if name == fieldName {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// RevisionState represents the state of a PDF at a particular revision.
type RevisionState struct {
	Revision  int
	Objects   map[int]generic.PdfObject
	XRefTable map[int]int64 // Object number to offset
	Trailer   *generic.DictionaryObject
	Root      *generic.DictionaryObject
	AcroForm  *generic.DictionaryObject
	DSS       *generic.DictionaryObject
}

// GetObject retrieves an object by number.
func (r *RevisionState) GetObject(objNum int) generic.PdfObject {
	return r.Objects[objNum]
}

// HasObject returns true if the object exists in this revision.
func (r *RevisionState) HasObject(objNum int) bool {
	_, ok := r.Objects[objNum]
	return ok
}

// StandardDiffPolicy implements the standard difference analysis policy.
type StandardDiffPolicy struct {
	// AllowFormFilling allows form field value changes.
	AllowFormFilling bool

	// AllowSignatures allows new signatures.
	AllowSignatures bool

	// AllowDSSUpdates allows DSS (Document Security Store) updates.
	AllowDSSUpdates bool

	// AllowTimestamps allows document timestamps.
	AllowTimestamps bool

	// StrictMode enables stricter checking.
	StrictMode bool
}

// NewStandardDiffPolicy creates a new standard policy with default settings.
func NewStandardDiffPolicy() *StandardDiffPolicy {
	return &StandardDiffPolicy{
		AllowFormFilling: true,
		AllowSignatures:  true,
		AllowDSSUpdates:  true,
		AllowTimestamps:  true,
		StrictMode:       false,
	}
}

// Apply implements DiffPolicy.
func (p *StandardDiffPolicy) Apply(old, new *RevisionState, fieldMDP *FieldMDPSpec, docMDP *form.MDPPerm) (*DiffResult, error) {
	result := &DiffResult{
		ModificationLevel: ModificationNone,
		ChangedFormFields: []string{},
		Details:           []string{},
	}

	// Check for new or modified objects
	for objNum, newObj := range new.Objects {
		oldObj, exists := old.Objects[objNum]

		if !exists {
			// New object added
			if err := p.checkNewObject(objNum, newObj, new, result); err != nil {
				return nil, err
			}
		} else {
			// Object modified
			if err := p.checkModifiedObject(objNum, oldObj, newObj, old, new, fieldMDP, result); err != nil {
				return nil, err
			}
		}
	}

	// Check for deleted objects
	for objNum := range old.Objects {
		if _, exists := new.Objects[objNum]; !exists {
			// Object was deleted
			result.Details = append(result.Details, fmt.Sprintf("Object %d was deleted", objNum))
			if result.ModificationLevel < ModificationOther {
				result.ModificationLevel = ModificationOther
			}
		}
	}

	// Apply DocMDP constraints
	if docMDP != nil {
		if !result.ModificationLevel.IsAllowed(*docMDP) {
			return nil, &SuspiciousModification{
				Message: fmt.Sprintf("Modifications exceed DocMDP permission level %v", *docMDP),
			}
		}
	}

	return result, nil
}

func (p *StandardDiffPolicy) checkNewObject(objNum int, obj generic.PdfObject, state *RevisionState, result *DiffResult) error {
	// Check what type of object was added
	switch v := obj.(type) {
	case *generic.DictionaryObject:
		objType := v.GetName("Type")
		switch objType {
		case "Sig":
			// New signature
			if p.AllowSignatures {
				if result.ModificationLevel < ModificationFormFilling {
					result.ModificationLevel = ModificationFormFilling
				}
				result.Details = append(result.Details, fmt.Sprintf("New signature object %d", objNum))
			} else {
				return &SuspiciousModification{Message: "New signature not allowed"}
			}
		case "DocTimeStamp":
			// Document timestamp
			if p.AllowTimestamps {
				if result.ModificationLevel < ModificationLTAUpdates {
					result.ModificationLevel = ModificationLTAUpdates
				}
				result.Details = append(result.Details, fmt.Sprintf("New document timestamp %d", objNum))
			} else {
				return &SuspiciousModification{Message: "New timestamp not allowed"}
			}
		case "DSS":
			// Document Security Store
			if p.AllowDSSUpdates {
				if result.ModificationLevel < ModificationLTAUpdates {
					result.ModificationLevel = ModificationLTAUpdates
				}
				result.Details = append(result.Details, fmt.Sprintf("DSS update %d", objNum))
			} else {
				return &SuspiciousModification{Message: "DSS update not allowed"}
			}
		default:
			// Other new objects - could be form field values, appearances, etc.
			if result.ModificationLevel < ModificationFormFilling {
				result.ModificationLevel = ModificationFormFilling
			}
		}
	case *generic.StreamObject:
		// New stream - could be appearance stream
		if result.ModificationLevel < ModificationFormFilling {
			result.ModificationLevel = ModificationFormFilling
		}
	}

	return nil
}

func (p *StandardDiffPolicy) checkModifiedObject(objNum int, oldObj, newObj generic.PdfObject, old, new *RevisionState, fieldMDP *FieldMDPSpec, result *DiffResult) error {
	// Compare objects
	switch oldDict := oldObj.(type) {
	case *generic.DictionaryObject:
		newDict, ok := newObj.(*generic.DictionaryObject)
		if !ok {
			return &SuspiciousModification{
				Message: fmt.Sprintf("Object %d type changed from dictionary to %T", objNum, newObj),
			}
		}

		// Check what type of dictionary was modified
		objType := oldDict.GetName("Type")
		switch objType {
		case "Annot", "Widget":
			// Annotation/widget modification - check if it's form-related
			if err := p.checkAnnotationModification(objNum, oldDict, newDict, fieldMDP, result); err != nil {
				return err
			}
		case "AcroForm":
			// AcroForm modification
			if err := p.checkAcroFormModification(oldDict, newDict, result); err != nil {
				return err
			}
		case "Catalog":
			// Catalog modification
			if err := p.checkCatalogModification(oldDict, newDict, result); err != nil {
				return err
			}
		default:
			// Other dictionary modifications
			if !p.compareDicts(oldDict, newDict, nil) {
				if result.ModificationLevel < ModificationFormFilling {
					result.ModificationLevel = ModificationFormFilling
				}
			}
		}
	case *generic.StreamObject:
		// Stream modification
		if result.ModificationLevel < ModificationFormFilling {
			result.ModificationLevel = ModificationFormFilling
		}
	}

	return nil
}

func (p *StandardDiffPolicy) checkAnnotationModification(objNum int, oldDict, newDict *generic.DictionaryObject, fieldMDP *FieldMDPSpec, result *DiffResult) error {
	// Get field name if this is a form field
	fieldName := ""
	if nameObj := oldDict.Get("T"); nameObj != nil {
		if strObj, ok := nameObj.(*generic.StringObject); ok {
			fieldName = string(strObj.Value)
		}
	}

	// Check if field is locked
	if fieldMDP != nil && fieldName != "" && fieldMDP.IsFieldLocked(fieldName) {
		// Field is locked - check what changed
		ignored := map[string]bool{"V": true, "AP": true, "AS": true}
		if !p.compareDictsWithIgnored(oldDict, newDict, ignored) {
			return &SuspiciousModification{
				Message: fmt.Sprintf("Locked field %s was modified", fieldName),
			}
		}
	}

	// Track changed form fields
	if fieldName != "" {
		// Check if value changed
		oldV := oldDict.Get("V")
		newV := newDict.Get("V")
		if !p.compareObjects(oldV, newV) {
			result.ChangedFormFields = append(result.ChangedFormFields, fieldName)
			if result.ModificationLevel < ModificationFormFilling {
				result.ModificationLevel = ModificationFormFilling
			}
		}
	}

	return nil
}

func (p *StandardDiffPolicy) checkAcroFormModification(oldDict, newDict *generic.DictionaryObject, result *DiffResult) error {
	// AcroForm modifications - check what changed
	// Allow changes to SigFlags, Fields (for new signatures)
	allowedChanges := map[string]bool{
		"SigFlags": true,
		"Fields":   true,
	}

	if !p.compareDictsWithIgnored(oldDict, newDict, allowedChanges) {
		if result.ModificationLevel < ModificationFormFilling {
			result.ModificationLevel = ModificationFormFilling
		}
	}

	return nil
}

func (p *StandardDiffPolicy) checkCatalogModification(oldDict, newDict *generic.DictionaryObject, result *DiffResult) error {
	// Catalog modifications - check what changed
	// Allow changes for DSS, AcroForm
	allowedChanges := map[string]bool{
		"DSS":      true,
		"AcroForm": true,
	}

	if !p.compareDictsWithIgnored(oldDict, newDict, allowedChanges) {
		return &SuspiciousModification{
			Message: "Catalog modified in unexpected way",
		}
	}

	return nil
}

func (p *StandardDiffPolicy) compareDicts(old, new *generic.DictionaryObject, ignored map[string]bool) bool {
	return p.compareDictsWithIgnored(old, new, ignored)
}

func (p *StandardDiffPolicy) compareDictsWithIgnored(old, new *generic.DictionaryObject, ignored map[string]bool) bool {
	if ignored == nil {
		ignored = map[string]bool{}
	}

	// Get keys from both dictionaries
	oldKeys := old.Keys()
	newKeys := new.Keys()

	// Filter out ignored keys
	filteredOld := []string{}
	filteredNew := []string{}
	for _, k := range oldKeys {
		if !ignored[k] {
			filteredOld = append(filteredOld, k)
		}
	}
	for _, k := range newKeys {
		if !ignored[k] {
			filteredNew = append(filteredNew, k)
		}
	}

	// Compare key sets
	if len(filteredOld) != len(filteredNew) {
		return false
	}

	// Compare values
	for _, k := range filteredOld {
		oldVal := old.Get(k)
		newVal := new.Get(k)
		if !p.compareObjects(oldVal, newVal) {
			return false
		}
	}

	return true
}

func (p *StandardDiffPolicy) compareObjects(old, new generic.PdfObject) bool {
	if old == nil && new == nil {
		return true
	}
	if old == nil || new == nil {
		return false
	}

	// Type comparison
	switch oldVal := old.(type) {
	case generic.BooleanObject:
		if newVal, ok := new.(generic.BooleanObject); ok {
			return oldVal == newVal
		}
	case generic.IntegerObject:
		if newVal, ok := new.(generic.IntegerObject); ok {
			return oldVal == newVal
		}
	case generic.RealObject:
		if newVal, ok := new.(generic.RealObject); ok {
			return oldVal == newVal
		}
	case generic.NameObject:
		if newVal, ok := new.(generic.NameObject); ok {
			return oldVal == newVal
		}
	case *generic.StringObject:
		if newVal, ok := new.(*generic.StringObject); ok {
			return string(oldVal.Value) == string(newVal.Value)
		}
	case generic.ArrayObject:
		if newVal, ok := new.(generic.ArrayObject); ok {
			if len(oldVal) != len(newVal) {
				return false
			}
			for i := range oldVal {
				if !p.compareObjects(oldVal[i], newVal[i]) {
					return false
				}
			}
			return true
		}
	case *generic.DictionaryObject:
		if newVal, ok := new.(*generic.DictionaryObject); ok {
			return p.compareDicts(oldVal, newVal, nil)
		}
	case *generic.Reference:
		if newVal, ok := new.(*generic.Reference); ok {
			return oldVal.ObjectNumber == newVal.ObjectNumber
		}
		if newVal, ok := new.(generic.Reference); ok {
			return oldVal.ObjectNumber == newVal.ObjectNumber
		}
	case generic.Reference:
		if newVal, ok := new.(*generic.Reference); ok {
			return oldVal.ObjectNumber == newVal.ObjectNumber
		}
		if newVal, ok := new.(generic.Reference); ok {
			return oldVal.ObjectNumber == newVal.ObjectNumber
		}
	}

	return false
}

// AssertNotStream checks if an object is a stream and returns an error if so.
func AssertNotStream(obj generic.PdfObject) error {
	if _, ok := obj.(*generic.StreamObject); ok {
		return &SuspiciousModification{
			Message: "Unexpected stream object encountered",
		}
	}
	return nil
}

// CompareDicts compares two dictionaries with optional ignored keys.
func CompareDicts(old, new *generic.DictionaryObject, ignored []string) (bool, error) {
	if old == nil {
		return false, errors.New("old dictionary is nil")
	}
	if new == nil {
		return false, &SuspiciousModification{
			Message: "Dictionary overridden by nil",
		}
	}

	if err := AssertNotStream(old); err != nil {
		return false, err
	}
	if err := AssertNotStream(new); err != nil {
		return false, err
	}

	ignoredSet := make(map[string]bool)
	for _, k := range ignored {
		ignoredSet[k] = true
	}

	oldKeys := filterKeys(old.Keys(), ignoredSet)
	newKeys := filterKeys(new.Keys(), ignoredSet)

	if !equalKeysets(oldKeys, newKeys) {
		return false, nil
	}

	policy := &StandardDiffPolicy{}
	for _, k := range oldKeys {
		oldVal := old.Get(k)
		newVal := new.Get(k)
		if !policy.compareObjects(oldVal, newVal) {
			return false, nil
		}
	}

	return true, nil
}

func filterKeys(keys []string, ignored map[string]bool) []string {
	result := []string{}
	for _, k := range keys {
		if !ignored[k] {
			result = append(result, k)
		}
	}
	return result
}

func equalKeysets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aSet := make(map[string]bool)
	for _, k := range a {
		aSet[k] = true
	}
	for _, k := range b {
		if !aSet[k] {
			return false
		}
	}
	return true
}

// DiffAnalyzer performs comprehensive difference analysis.
type DiffAnalyzer struct {
	Policy   DiffPolicy
	OldState *RevisionState
	NewState *RevisionState
	FieldMDP *FieldMDPSpec
	DocMDP   *form.MDPPerm
}

// NewDiffAnalyzer creates a new analyzer.
func NewDiffAnalyzer(old, new *RevisionState) *DiffAnalyzer {
	return &DiffAnalyzer{
		Policy:   NewStandardDiffPolicy(),
		OldState: old,
		NewState: new,
	}
}

// WithFieldMDP sets the field MDP spec.
func (a *DiffAnalyzer) WithFieldMDP(spec *FieldMDPSpec) *DiffAnalyzer {
	a.FieldMDP = spec
	return a
}

// WithDocMDP sets the document MDP permission.
func (a *DiffAnalyzer) WithDocMDP(perm form.MDPPerm) *DiffAnalyzer {
	a.DocMDP = &perm
	return a
}

// Analyze performs the difference analysis.
func (a *DiffAnalyzer) Analyze() (*DiffResult, error) {
	return a.Policy.Apply(a.OldState, a.NewState, a.FieldMDP, a.DocMDP)
}

// SummarizeChanges returns a human-readable summary of changes.
func (r *DiffResult) SummarizeChanges() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Modification Level: %s\n", r.ModificationLevel))

	if len(r.ChangedFormFields) > 0 {
		sb.WriteString(fmt.Sprintf("Changed Form Fields: %s\n", strings.Join(r.ChangedFormFields, ", ")))
	}

	if len(r.Details) > 0 {
		sb.WriteString("Details:\n")
		for _, detail := range r.Details {
			sb.WriteString(fmt.Sprintf("  - %s\n", detail))
		}
	}

	if r.Suspicious {
		sb.WriteString("WARNING: Suspicious modifications detected!\n")
	}

	return sb.String()
}
