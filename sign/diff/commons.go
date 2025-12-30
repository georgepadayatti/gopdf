// Package diff provides difference analysis for PDF document validation.
// This file contains common helpers for use by rules and policies.
package diff

import (
	"fmt"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// TwoVersions represents optional old and new values from a comparison.
type TwoVersions struct {
	Old generic.PdfObject
	New generic.PdfObject
}

// AssertNotStreamObject throws SuspiciousModification if the object is a stream.
func AssertNotStreamObject(obj generic.PdfObject) error {
	if obj == nil {
		return nil
	}
	if _, ok := obj.(*generic.StreamObject); ok {
		return &SuspiciousModification{
			Message: "Unexpected stream object encountered",
		}
	}
	return nil
}

// SafeWhitelist checks whether an indirect reference in a PDF structure
// can be updated without clobbering an older object in a way that causes
// ramifications at the PDF syntax level.
//
// The following are verified:
//   - Does the old reference point to a non-stream object?
//   - If the new reference is equal to the old one, does the new reference
//     point to a non-stream object?
//   - If the new reference is not equal to the old one, is the new reference
//     a newly defined object?
func SafeWhitelist(old *RevisionState, oldRef, newRef *generic.Reference) ([]*generic.Reference, error) {
	var results []*generic.Reference

	if oldRef != nil {
		oldObj := old.GetObject(oldRef.ObjectNumber)
		if err := AssertNotStreamObject(oldObj); err != nil {
			return nil, err
		}
	}

	if oldRef != nil && newRef != nil && oldRef.ObjectNumber == newRef.ObjectNumber {
		// Same reference - verify it's not a stream
		newObj := old.GetObject(newRef.ObjectNumber)
		if err := AssertNotStreamObject(newObj); err != nil {
			return nil, err
		}
		results = append(results, newRef)
	} else if newRef != nil {
		// Different reference - check if available
		if !old.HasObject(newRef.ObjectNumber) {
			// New object - allowed
			results = append(results, newRef)
		} else {
			return nil, &SuspiciousModification{
				Message: fmt.Sprintf("Update clobbers or reuses object %d in an unexpected way", newRef.ObjectNumber),
			}
		}
	}

	return results, nil
}

// CompareKeyRefs ensures that updating a key in a dictionary has no undesirable
// side effects. The following scenarios are allowed:
//
//  0. replacing a direct value with another direct value
//  1. adding a key in new_dict
//  2. replacing a direct value in old_dict with a reference in new_dict
//  3. the reverse (allowed by default)
//  4. replacing a reference with another reference (that doesn't override
//     anything else)
//
// Returns the whitelist of references and the old/new values.
func CompareKeyRefs(key string, old *RevisionState, oldDict, newDict *generic.DictionaryObject) ([]*generic.Reference, *TwoVersions, error) {
	var refs []*generic.Reference
	var oldValueRef, newValueRef *generic.Reference
	var oldValue, newValue generic.PdfObject

	// Get old value
	if oldDict != nil {
		rawOldValue := oldDict.Get(key)
		if rawOldValue != nil {
			if ref, ok := rawOldValue.(*generic.Reference); ok {
				oldValueRef = ref
				oldValue = old.GetObject(ref.ObjectNumber)
			} else if ref, ok := rawOldValue.(generic.Reference); ok {
				oldValueRef = &ref
				oldValue = old.GetObject(ref.ObjectNumber)
			} else {
				oldValue = rawOldValue
			}
		}
	}

	// Get new value
	if newDict != nil {
		rawNewValue := newDict.Get(key)
		if rawNewValue != nil {
			if ref, ok := rawNewValue.(*generic.Reference); ok {
				newValueRef = ref
				newValue = rawNewValue // Keep the reference for now
			} else if ref, ok := rawNewValue.(generic.Reference); ok {
				newValueRef = &ref
				newValue = rawNewValue
			} else {
				newValue = rawNewValue
			}
		}
	}

	// Check if key was deleted
	if newValue == nil && oldValue != nil {
		return nil, nil, &SuspiciousModification{
			Message: fmt.Sprintf("Key '%s' was deleted from dictionary", key),
		}
	}

	// Nothing to do if both are nil
	if newValue == nil && oldValue == nil {
		return refs, &TwoVersions{Old: nil, New: nil}, nil
	}

	// If new value is a reference, whitelist it
	if newValueRef != nil {
		whitelistRefs, err := SafeWhitelist(old, oldValueRef, newValueRef)
		if err != nil {
			return nil, nil, err
		}
		refs = append(refs, whitelistRefs...)
	}

	return refs, &TwoVersions{Old: oldValue, New: newValue}, nil
}

// QualifiedUpdate represents a reference update with a modification level.
type QualifiedUpdate struct {
	Level  ModificationLevel
	Update *ReferenceUpdate
}

// QualifiedFormUpdate represents a form update with a modification level.
type QualifiedFormUpdate struct {
	Level  ModificationLevel
	Update *FormUpdate
}

// Qualify attaches a fixed modification level to reference updates.
func Qualify(level ModificationLevel, updates []ReferenceUpdate) []QualifiedUpdate {
	result := make([]QualifiedUpdate, 0, len(updates))
	for i := range updates {
		result = append(result, QualifiedUpdate{
			Level:  level,
			Update: &updates[i],
		})
	}
	return result
}

// QualifyRefs attaches a modification level to reference pointers.
func QualifyRefs(level ModificationLevel, refs []*generic.Reference) []QualifiedUpdate {
	result := make([]QualifiedUpdate, 0, len(refs))
	for _, ref := range refs {
		result = append(result, QualifiedUpdate{
			Level: level,
			Update: &ReferenceUpdate{
				Reference: ref,
				Level:     level,
			},
		})
	}
	return result
}

// CompareDictsStrict compares two dictionaries strictly, optionally ignoring certain keys.
// Returns true if dictionaries are equal (ignoring specified keys), false otherwise.
// If raiseError is true, returns an error on difference.
func CompareDictsStrict(oldDict, newDict *generic.DictionaryObject, ignored map[string]bool, raiseError bool) (bool, error) {
	if oldDict == nil {
		return false, fmt.Errorf("old dictionary is nil")
	}
	if newDict == nil {
		if raiseError {
			return false, &SuspiciousModification{
				Message: "Dict is overridden by non-dict in new revision",
			}
		}
		return false, nil
	}

	// Check for streams
	if err := AssertNotStreamObject(oldDict); err != nil {
		return false, err
	}
	if err := AssertNotStreamObject(newDict); err != nil {
		return false, err
	}

	// Get keys excluding ignored ones
	oldKeys := make(map[string]bool)
	newKeys := make(map[string]bool)

	for _, k := range oldDict.Keys() {
		if !ignored[k] {
			oldKeys[k] = true
		}
	}
	for _, k := range newDict.Keys() {
		if !ignored[k] {
			newKeys[k] = true
		}
	}

	// Compare key sets
	if len(oldKeys) != len(newKeys) {
		if raiseError {
			return false, &SuspiciousModification{
				Message: fmt.Sprintf("Dict keys differ in count: %d vs %d", len(oldKeys), len(newKeys)),
			}
		}
		return false, nil
	}

	for k := range oldKeys {
		if !newKeys[k] {
			if raiseError {
				return false, &SuspiciousModification{
					Message: fmt.Sprintf("Key '%s' was removed from dictionary", k),
				}
			}
			return false, nil
		}
	}

	for k := range newKeys {
		if !oldKeys[k] {
			if raiseError {
				return false, &SuspiciousModification{
					Message: fmt.Sprintf("Key '%s' was added to dictionary", k),
				}
			}
			return false, nil
		}
	}

	// Compare values
	policy := &StandardDiffPolicy{}
	for k := range newKeys {
		newVal := newDict.Get(k)
		oldVal := oldDict.Get(k)

		if !policy.compareObjects(oldVal, newVal) {
			if raiseError {
				return false, &SuspiciousModification{
					Message: fmt.Sprintf("Values for dict key '%s' differ", k),
				}
			}
			return false, nil
		}
	}

	return true, nil
}

// IsAnnotVisible checks if an annotation has a visible rectangle.
func IsAnnotVisible(annotDict *generic.DictionaryObject) bool {
	if annotDict == nil {
		return false
	}

	rectObj := annotDict.Get("Rect")
	if rectObj == nil {
		return false
	}

	rect, ok := rectObj.(generic.ArrayObject)
	if !ok || len(rect) != 4 {
		return false
	}

	// Extract coordinates
	x1, y1, x2, y2, err := extractRectCoords(rect)
	if err != nil {
		return false
	}

	// Calculate area
	area := abs(x1-x2) * abs(y1-y2)
	return area > 0
}

// IsFieldVisible checks if a form field is visible.
func IsFieldVisible(fieldDict *generic.DictionaryObject) bool {
	if fieldDict == nil {
		return false
	}

	// Check if field has Kids
	kidsObj := fieldDict.Get("Kids")
	if kidsObj == nil {
		// No kids - check if field itself is visible
		return IsAnnotVisible(fieldDict)
	}

	// Has kids - check if field or any kid is visible
	if IsAnnotVisible(fieldDict) {
		return true
	}

	// Check kids
	kids, ok := kidsObj.(generic.ArrayObject)
	if !ok {
		return false
	}

	for _, kidObj := range kids {
		// Dereference if needed
		var kidDict *generic.DictionaryObject
		if ref, ok := kidObj.(*generic.Reference); ok {
			_ = ref // Would need to resolve this
			// For now, assume not visible if we can't resolve
			continue
		} else if ref, ok := kidObj.(generic.Reference); ok {
			_ = ref
			continue
		} else if dict, ok := kidObj.(*generic.DictionaryObject); ok {
			kidDict = dict
		} else {
			continue
		}

		if IsAnnotVisible(kidDict) {
			return true
		}
	}

	return false
}

// Helper functions

func extractRectCoords(rect generic.ArrayObject) (x1, y1, x2, y2 float64, err error) {
	if len(rect) != 4 {
		return 0, 0, 0, 0, fmt.Errorf("rect must have 4 elements")
	}

	x1, err = toFloat64(rect[0])
	if err != nil {
		return
	}
	y1, err = toFloat64(rect[1])
	if err != nil {
		return
	}
	x2, err = toFloat64(rect[2])
	if err != nil {
		return
	}
	y2, err = toFloat64(rect[3])
	return
}

func toFloat64(obj generic.PdfObject) (float64, error) {
	switch v := obj.(type) {
	case generic.IntegerObject:
		return float64(v), nil
	case generic.RealObject:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", obj)
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
