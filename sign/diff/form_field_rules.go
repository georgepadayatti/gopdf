// Package diff provides difference analysis for PDF document validation.
// This file contains form field modification rules.
package diff

import (
	"fmt"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// FieldMDPRule is the interface for field modification detection policy rules.
type FieldMDPRule interface {
	// Apply applies this rule to the given field comparison context.
	Apply(ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error)
}

// Note: WhitelistRule is defined in metadata_rules.go

// FieldComparisonContext provides context for comparing form fields.
type FieldComparisonContext struct {
	// Old is the old revision state.
	Old *RevisionState
	// New is the new revision state.
	New *RevisionState
	// FieldSpecs maps field names to their comparison specs.
	FieldSpecs map[string]*FieldComparisonSpec
	// FieldMDP is the field modification detection policy (optional).
	FieldMDP *FieldMDPSpec
}

// FieldComparisonSpec describes the comparison state of a form field.
type FieldComparisonSpec struct {
	// FieldType is the type of the field (e.g., "/Sig", "/Tx", "/Btn").
	FieldType string
	// OldFieldRef is the reference to the old field (nil if newly created).
	OldFieldRef *generic.Reference
	// NewFieldRef is the reference to the new field (nil if deleted).
	NewFieldRef *generic.Reference
	// OldField is the resolved old field dictionary.
	OldField *generic.DictionaryObject
	// NewField is the resolved new field dictionary.
	NewField *generic.DictionaryObject
}

// DSSCompareRule allows changes to the document security store (DSS).
// It validates the structure of the DSS and allows adding new revocation info.
type DSSCompareRule struct{}

// NewDSSCompareRule creates a new DSS comparison rule.
func NewDSSCompareRule() *DSSCompareRule {
	return &DSSCompareRule{}
}

// Apply implements WhitelistRule.
func (r *DSSCompareRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	var updates []ReferenceUpdate

	// Compare DSS dictionaries
	if new.DSS == nil {
		// No DSS in new revision - nothing to check
		return updates, nil
	}

	// Validate DSS structure
	if err := r.validateDSSStructure(new.DSS); err != nil {
		return nil, err
	}

	// Check for newly added DSS entries
	newDSSKeys := new.DSS.Keys()
	for _, key := range newDSSKeys {
		if !IsDSSExpectedKey(key) {
			return nil, &SuspiciousModification{
				Message: fmt.Sprintf("Unexpected key in DSS: %s", key),
			}
		}
	}

	// Validate VRI if present
	if vriObj := new.DSS.Get("/VRI"); vriObj != nil {
		if err := r.validateVRI(old, new, vriObj); err != nil {
			return nil, err
		}
	}

	return updates, nil
}

// validateDSSStructure validates the structure of a DSS dictionary.
func (r *DSSCompareRule) validateDSSStructure(dss *generic.DictionaryObject) error {
	if dss == nil {
		return nil
	}

	// Check /Certs, /CRLs, /OCSPs are arrays of stream references
	for _, key := range []string{"/Certs", "/CRLs", "/OCSPs"} {
		if obj := dss.Get(key); obj != nil {
			if err := assertStreamRefs(obj, key, false); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateVRI validates the VRI (Validation Related Information) dictionary.
func (r *DSSCompareRule) validateVRI(old, new *RevisionState, vriObj generic.PdfObject) error {
	// Dereference if needed
	vriDict, ok := vriObj.(*generic.DictionaryObject)
	if !ok {
		return &SuspiciousModification{
			Message: "/VRI is not a dictionary",
		}
	}

	// Check each VRI entry
	for _, key := range vriDict.Keys() {
		// Verify key format (should be 40-char hex string)
		if !IsVRIKey(key) {
			return &SuspiciousModification{
				Message: fmt.Sprintf("VRI key %s is not formatted correctly", key),
			}
		}

		// Validate VRI entry structure
		entry := vriDict.Get(key)
		if err := r.validateVRIEntry(entry); err != nil {
			return err
		}
	}

	return nil
}

// validateVRIEntry validates a single VRI dictionary entry.
func (r *DSSCompareRule) validateVRIEntry(entry generic.PdfObject) error {
	entryDict, ok := entry.(*generic.DictionaryObject)
	if !ok {
		return &SuspiciousModification{
			Message: "VRI entries should be dictionaries",
		}
	}

	// Check for unexpected keys
	for _, key := range entryDict.Keys() {
		if !IsVRIExpectedKey(key) {
			return &SuspiciousModification{
				Message: fmt.Sprintf("Unexpected key in VRI dictionary: %s", key),
			}
		}
	}

	// Validate stream array entries
	for _, key := range []string{"/Cert", "/CRL", "/OCSP"} {
		if obj := entryDict.Get(key); obj != nil {
			if err := assertStreamRefs(obj, key, true); err != nil {
				return err
			}
		}
	}

	return nil
}

// assertStreamRefs verifies that an object is an array of stream references.
func assertStreamRefs(obj generic.PdfObject, keyName string, isVRI bool) error {
	arr, ok := obj.(generic.ArrayObject)
	if !ok {
		location := "DSS"
		if isVRI {
			location = "VRI"
		}
		return &SuspiciousModification{
			Message: fmt.Sprintf("Expected contents of '%s' in %s to be an array of stream references", keyName, location),
		}
	}

	for _, item := range arr {
		// Each item should be an indirect reference to a stream
		if _, ok := item.(*generic.Reference); !ok {
			if _, ok := item.(generic.Reference); !ok {
				location := "DSS"
				if isVRI {
					location = "VRI"
				}
				return &SuspiciousModification{
					Message: fmt.Sprintf("Expected contents of '%s' in %s to be an array of stream references", keyName, location),
				}
			}
		}
	}

	return nil
}

// SigFieldCreationRule allows signature fields to be created at the root
// of the form hierarchy, but disallows creation of other field types.
type SigFieldCreationRule struct {
	// ApproveWidgetBindings allows new widget annotation registrations.
	ApproveWidgetBindings bool
	// AllowNewVisibleAfterCertify allows visible fields after certification.
	AllowNewVisibleAfterCertify bool
}

// NewSigFieldCreationRule creates a new signature field creation rule.
func NewSigFieldCreationRule() *SigFieldCreationRule {
	return &SigFieldCreationRule{
		ApproveWidgetBindings:       true,
		AllowNewVisibleAfterCertify: false,
	}
}

// Apply implements FieldMDPRule.
func (r *SigFieldCreationRule) Apply(ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error) {
	var updates []QualifiedFormUpdate

	// Check for deleted fields
	for fqName, spec := range ctx.FieldSpecs {
		if spec.OldFieldRef != nil && spec.NewFieldRef == nil {
			return nil, &SuspiciousModification{
				Message: fmt.Sprintf("Field %s was deleted after signing", fqName),
			}
		}
	}

	// Collect newly created signature fields
	newSigFields := make(map[string]*generic.Reference)
	for fqName, spec := range ctx.FieldSpecs {
		if spec.FieldType == "/Sig" && spec.OldFieldRef == nil && spec.NewFieldRef != nil {
			newSigFields[fqName] = spec.NewFieldRef
		}
	}

	// Verify that all new fields are signature fields
	for fqName, spec := range ctx.FieldSpecs {
		if spec.OldFieldRef == nil && spec.NewFieldRef != nil {
			if spec.FieldType != "/Sig" {
				return nil, &SuspiciousModification{
					Message: fmt.Sprintf("Only signature fields can be created; found non-signature field %s", fqName),
				}
			}
		}
	}

	// Process new signature fields
	for fqName, sigFieldRef := range newSigFields {
		spec := ctx.FieldSpecs[fqName]
		if spec == nil || spec.NewField == nil {
			continue
		}

		visible := IsFieldVisible(spec.NewField)

		// Determine modification level
		level := ModificationLTAUpdates
		if visible {
			level = ModificationFormFilling
		}

		// Check visibility after certification
		validWhenCertifying := !visible || r.AllowNewVisibleAfterCertify

		updates = append(updates, QualifiedFormUpdate{
			Level: level,
			Update: &FormUpdate{
				FieldName:       fqName,
				ValidWhenLocked: !visible,
				Update: &ReferenceUpdate{
					Reference:       sigFieldRef,
					Level:           level,
					ValidWhenLocked: !visible && validWhenCertifying,
				},
			},
		})
	}

	return updates, nil
}

// BaseFieldModificationRule implements boilerplate for validating field modifications.
type BaseFieldModificationRule struct {
	// AllowInPlaceAppearanceStreamChanges allows updating appearance streams in-place.
	AllowInPlaceAppearanceStreamChanges bool
	// AlwaysModifiable contains keys that can always be modified.
	AlwaysModifiable map[string]bool
	// ValueUpdateKeys contains keys that may change when updating a value.
	ValueUpdateKeys map[string]bool
}

// NewBaseFieldModificationRule creates a new base field modification rule.
func NewBaseFieldModificationRule() *BaseFieldModificationRule {
	return &BaseFieldModificationRule{
		AllowInPlaceAppearanceStreamChanges: true,
		AlwaysModifiable:                    FormFieldAlwaysModifiable,
		ValueUpdateKeys:                     ValueUpdateKeys,
	}
}

// CompareFields compares field dictionaries and returns whether modifications
// are permissible even when the field is locked.
func (r *BaseFieldModificationRule) CompareFields(spec *FieldComparisonSpec) (bool, error) {
	oldField := spec.OldField
	newField := spec.NewField

	if oldField == nil || newField == nil {
		return false, nil
	}

	// First comparison: ignore value update keys
	_, err := CompareDictsStrict(oldField, newField, r.ValueUpdateKeys, true)
	if err != nil {
		return false, err
	}

	// Check /Type handling
	if err := r.checkTypeField(oldField, newField); err != nil {
		return false, err
	}

	// Second comparison: check if valid when locked (only always-modifiable keys changed)
	validWhenLocked, err := CompareDictsStrict(oldField, newField, r.AlwaysModifiable, false)
	if err != nil {
		return false, err
	}

	return validWhenLocked, nil
}

// checkTypeField validates /Type field changes.
func (r *BaseFieldModificationRule) checkTypeField(oldField, newField *generic.DictionaryObject) error {
	hadType := oldField.Get("/Type") != nil
	hasType := newField.Get("/Type") != nil

	if hasType {
		typeVal := newField.Get("/Type")
		if !hadType {
			// Type was added - should be /Annot
			if name, ok := typeVal.(generic.NameObject); ok {
				if string(name) != "/Annot" && string(name) != "Annot" {
					return &SuspiciousModification{
						Message: "/Type of form field set to something other than /Annot",
					}
				}
			}
		} else {
			// Type existed - should not change
			oldTypeVal := oldField.Get("/Type")
			if oldTypeVal != typeVal {
				return &SuspiciousModification{
					Message: "/Type of form field altered",
				}
			}
		}
	}

	if hadType && !hasType {
		return &SuspiciousModification{
			Message: "/Type of form field deleted",
		}
	}

	return nil
}

// SigFieldModificationRule allows signature fields to be filled in
// and set an appearance if desired.
type SigFieldModificationRule struct {
	*BaseFieldModificationRule
}

// NewSigFieldModificationRule creates a new signature field modification rule.
func NewSigFieldModificationRule() *SigFieldModificationRule {
	return &SigFieldModificationRule{
		BaseFieldModificationRule: NewBaseFieldModificationRule(),
	}
}

// Apply implements FieldMDPRule.
func (r *SigFieldModificationRule) Apply(ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error) {
	var updates []QualifiedFormUpdate

	for fqName, spec := range ctx.FieldSpecs {
		fieldUpdates, err := r.checkFormField(fqName, spec, ctx)
		if err != nil {
			return nil, err
		}
		updates = append(updates, fieldUpdates...)
	}

	return updates, nil
}

// checkFormField investigates updates to a particular signature field.
func (r *SigFieldModificationRule) checkFormField(fqName string, spec *FieldComparisonSpec, ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error) {
	var updates []QualifiedFormUpdate

	// Only process signature fields
	if spec.FieldType != "/Sig" || spec.NewFieldRef == nil {
		return updates, nil
	}

	oldField := spec.OldField
	newField := spec.NewField

	if newField == nil {
		return updates, nil
	}

	previouslySigned := oldField != nil && oldField.Get("/V") != nil
	nowSigned := newField.Get("/V") != nil

	if oldField != nil {
		// Check field changes
		validWhenLocked, err := r.CompareFields(spec)
		if err != nil {
			return nil, err
		}

		if !previouslySigned && nowSigned {
			// Field was just signed
			updates = append(updates, QualifiedFormUpdate{
				Level: ModificationLTAUpdates,
				Update: &FormUpdate{
					FieldName:       fqName,
					ValidWhenLocked: validWhenLocked,
					Update: &ReferenceUpdate{
						Reference:       spec.NewFieldRef,
						Level:           ModificationLTAUpdates,
						ValidWhenLocked: validWhenLocked,
					},
				},
			})
		} else if validWhenLocked {
			// Changes are valid even when locked
			updates = append(updates, QualifiedFormUpdate{
				Level: ModificationLTAUpdates,
				Update: &FormUpdate{
					FieldName:       fqName,
					ValidWhenLocked: true,
					Update: &ReferenceUpdate{
						Reference:       spec.NewFieldRef,
						Level:           ModificationLTAUpdates,
						ValidWhenLocked: true,
					},
				},
			})
		}

		if previouslySigned || !nowSigned {
			return updates, nil
		}
	}

	if !nowSigned {
		return updates, nil
	}

	// Get signature value reference
	valueObj := newField.Get("/V")
	if valueObj == nil {
		return updates, nil
	}

	// Determine if this is a document timestamp
	valueRef, isRef := valueObj.(*generic.Reference)
	if !isRef {
		if ref, ok := valueObj.(generic.Reference); ok {
			valueRef = &ref
			isRef = true
		}
	}

	if !isRef {
		return nil, &SuspiciousModification{
			Message: fmt.Sprintf("Value of signature field %s should be an indirect reference", fqName),
		}
	}

	visible := IsFieldVisible(newField)

	// Check if it's a document timestamp
	isDocTimestamp := false
	// We would need to resolve the reference to check /Type = /DocTimeStamp
	// For now, use visibility as a heuristic

	var sigLevel ModificationLevel
	var sigValidWhenLocked bool

	if isDocTimestamp && !visible {
		sigLevel = ModificationLTAUpdates
		sigValidWhenLocked = true
	} else {
		sigLevel = ModificationFormFilling
		sigValidWhenLocked = false
	}

	updates = append(updates, QualifiedFormUpdate{
		Level: sigLevel,
		Update: &FormUpdate{
			FieldName:       fqName,
			ValidWhenLocked: sigValidWhenLocked,
			Update: &ReferenceUpdate{
				Reference:       valueRef,
				Level:           sigLevel,
				ValidWhenLocked: sigValidWhenLocked,
			},
		},
	})

	return updates, nil
}

// GenericFieldModificationRule allows non-signature form fields to be modified.
type GenericFieldModificationRule struct {
	*BaseFieldModificationRule
}

// NewGenericFieldModificationRule creates a new generic field modification rule.
func NewGenericFieldModificationRule() *GenericFieldModificationRule {
	return &GenericFieldModificationRule{
		BaseFieldModificationRule: NewBaseFieldModificationRule(),
	}
}

// Apply implements FieldMDPRule.
func (r *GenericFieldModificationRule) Apply(ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error) {
	var updates []QualifiedFormUpdate

	for fqName, spec := range ctx.FieldSpecs {
		fieldUpdates, err := r.checkFormField(fqName, spec, ctx)
		if err != nil {
			return nil, err
		}
		updates = append(updates, fieldUpdates...)
	}

	return updates, nil
}

// checkFormField investigates updates to a non-signature form field.
func (r *GenericFieldModificationRule) checkFormField(fqName string, spec *FieldComparisonSpec, ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error) {
	var updates []QualifiedFormUpdate

	// Skip signature fields, new fields, and deleted fields
	if spec.FieldType == "/Sig" || spec.NewFieldRef == nil || spec.OldFieldRef == nil {
		return updates, nil
	}

	validWhenLocked, err := r.CompareFields(spec)
	if err != nil {
		return nil, err
	}

	updates = append(updates, QualifiedFormUpdate{
		Level: ModificationFormFilling,
		Update: &FormUpdate{
			FieldName:       fqName,
			ValidWhenLocked: validWhenLocked,
			Update: &ReferenceUpdate{
				Reference:       spec.NewFieldRef,
				Level:           ModificationFormFilling,
				ValidWhenLocked: validWhenLocked,
			},
		},
	})

	return updates, nil
}

// FormFieldRuleSet combines multiple field modification rules.
type FormFieldRuleSet struct {
	Rules []FieldMDPRule
}

// NewFormFieldRuleSet creates a new rule set with default rules.
func NewFormFieldRuleSet() *FormFieldRuleSet {
	return &FormFieldRuleSet{
		Rules: []FieldMDPRule{
			NewSigFieldCreationRule(),
			NewSigFieldModificationRule(),
			NewGenericFieldModificationRule(),
		},
	}
}

// Apply applies all rules to the field comparison context.
func (s *FormFieldRuleSet) Apply(ctx *FieldComparisonContext) ([]QualifiedFormUpdate, error) {
	var allUpdates []QualifiedFormUpdate

	for _, rule := range s.Rules {
		updates, err := rule.Apply(ctx)
		if err != nil {
			return nil, err
		}
		allUpdates = append(allUpdates, updates...)
	}

	return allUpdates, nil
}

// NewFieldComparisonContext creates a new field comparison context.
func NewFieldComparisonContext(old, new *RevisionState) *FieldComparisonContext {
	return &FieldComparisonContext{
		Old:        old,
		New:        new,
		FieldSpecs: make(map[string]*FieldComparisonSpec),
	}
}

// WithFieldMDP sets the field MDP spec.
func (ctx *FieldComparisonContext) WithFieldMDP(spec *FieldMDPSpec) *FieldComparisonContext {
	ctx.FieldMDP = spec
	return ctx
}

// AddFieldSpec adds a field comparison spec to the context.
func (ctx *FieldComparisonContext) AddFieldSpec(name string, spec *FieldComparisonSpec) {
	ctx.FieldSpecs[name] = spec
}

// IsFieldLocked checks if a field is locked according to the FieldMDP spec.
func (ctx *FieldComparisonContext) IsFieldLocked(fieldName string) bool {
	if ctx.FieldMDP == nil {
		return false
	}
	return ctx.FieldMDP.IsFieldLocked(fieldName)
}
