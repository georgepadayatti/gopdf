// Package diff provides difference analysis for PDF document validation.
// This file contains rules for file structure modifications.
package diff

import (
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// RootExemptStrictComparison contains keys in the document catalog that
// may change between revisions.
var RootExemptStrictComparison = map[string]bool{
	"AcroForm":   true,
	"DSS":        true,
	"Extensions": true,
	"Metadata":   true,
	"MarkInfo":   true,
	"Version":    true,
}

// CatalogModificationRule adjudicates modifications to the document catalog.
// Checking for /AcroForm, /DSS and /Metadata is delegated to FormUpdatingRule,
// DSSCompareRule and MetadataUpdateRule, respectively.
type CatalogModificationRule struct {
	// IgnoredKeys contains values in the document catalog that may change
	// between revisions.
	IgnoredKeys map[string]bool
}

// NewCatalogModificationRule creates a new CatalogModificationRule with default settings.
func NewCatalogModificationRule() *CatalogModificationRule {
	return &CatalogModificationRule{
		IgnoredKeys: RootExemptStrictComparison,
	}
}

// Apply implements WhitelistRule for CatalogModificationRule.
func (r *CatalogModificationRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	updates := []ReferenceUpdate{}

	oldRoot := old.Root
	newRoot := new.Root

	if oldRoot == nil || newRoot == nil {
		return updates, nil
	}

	// First, check if the keys in the document catalog are unchanged
	if err := r.compareCatalogs(oldRoot, newRoot); err != nil {
		return nil, err
	}

	// Handle allowed changes: /Extensions and /MarkInfo
	for _, key := range []string{"Extensions", "MarkInfo"} {
		refUpdates, err := r.compareKeyRefs(key, old, oldRoot, newRoot)
		if err != nil {
			return nil, err
		}
		for _, ref := range refUpdates {
			updates = append(updates, ReferenceUpdate{
				Reference: ref,
				Level:     ModificationLTAUpdates,
			})
		}
	}

	// Approve the root reference itself at LTA level
	if newRoot != nil {
		// Find the root reference
		rootRef := getRootRef(new)
		if rootRef != nil {
			updates = append(updates, ReferenceUpdate{
				Reference: rootRef,
				Level:     ModificationLTAUpdates,
			})
		}
	}

	return updates, nil
}

// compareCatalogs compares two catalog dictionaries, ignoring allowed keys.
func (r *CatalogModificationRule) compareCatalogs(old, new *generic.DictionaryObject) error {
	// Get keys from both catalogs
	oldKeys := make(map[string]bool)
	newKeys := make(map[string]bool)

	for _, k := range old.Keys() {
		if !r.IgnoredKeys[k] {
			oldKeys[k] = true
		}
	}
	for _, k := range new.Keys() {
		if !r.IgnoredKeys[k] {
			newKeys[k] = true
		}
	}

	// Check for added or removed keys
	for k := range oldKeys {
		if !newKeys[k] {
			return &SuspiciousModification{
				Message: "Key '" + k + "' was removed from document catalog",
			}
		}
	}
	for k := range newKeys {
		if !oldKeys[k] {
			return &SuspiciousModification{
				Message: "Key '" + k + "' was added to document catalog",
			}
		}
	}

	// Compare values for non-ignored keys
	policy := &StandardDiffPolicy{}
	for k := range oldKeys {
		oldVal := old.Get(k)
		newVal := new.Get(k)
		if !policy.compareObjects(oldVal, newVal) {
			return &SuspiciousModification{
				Message: "Value for key '" + k + "' changed in document catalog",
			}
		}
	}

	return nil
}

// compareKeyRefs compares references for a key between old and new dictionaries.
func (r *CatalogModificationRule) compareKeyRefs(key string, old *RevisionState, oldDict, newDict *generic.DictionaryObject) ([]*generic.Reference, error) {
	var refs []*generic.Reference

	oldVal := oldDict.Get(key)
	newVal := newDict.Get(key)

	// If new value is nil, nothing to do
	if newVal == nil {
		return refs, nil
	}

	// Check if new value is an indirect reference
	if newRef, ok := getReference(newVal); ok {
		// Check if this is a new reference or changed reference
		if oldVal == nil {
			// New reference added
			if !old.HasObject(newRef.ObjectNumber) {
				refs = append(refs, newRef)
			}
		} else if oldRef, ok := getReference(oldVal); ok {
			if oldRef.ObjectNumber != newRef.ObjectNumber {
				// Reference changed
				if !old.HasObject(newRef.ObjectNumber) {
					refs = append(refs, newRef)
				}
			}
		}
	}

	return refs, nil
}

// getRootRef gets the reference to the root dictionary from the trailer.
func getRootRef(state *RevisionState) *generic.Reference {
	if state.Trailer == nil {
		return nil
	}

	rootObj := state.Trailer.Get("Root")
	if ref, ok := getReference(rootObj); ok {
		return ref
	}
	return nil
}

// getReference extracts a Reference from a PdfObject.
func getReference(obj generic.PdfObject) (*generic.Reference, bool) {
	if obj == nil {
		return nil, false
	}
	switch v := obj.(type) {
	case *generic.Reference:
		return v, true
	case generic.Reference:
		return &v, true
	}
	return nil, false
}

// ObjectStreamRule allows object streams to be added.
// This rule only whitelists the object streams themselves (provided they do not
// override any existing objects), not the objects in them.
type ObjectStreamRule struct{}

// NewObjectStreamRule creates a new ObjectStreamRule.
func NewObjectStreamRule() *ObjectStreamRule {
	return &ObjectStreamRule{}
}

// Apply implements WhitelistRule for ObjectStreamRule.
func (r *ObjectStreamRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	updates := []ReferenceUpdate{}

	// Get object stream references from the new revision
	objStreamRefs := getObjectStreamRefs(new)

	for _, ref := range objStreamRefs {
		// Object streams are OK, but overriding object streams is not
		if !old.HasObject(ref.ObjectNumber) {
			updates = append(updates, ReferenceUpdate{
				Reference: ref,
				Level:     ModificationLTAUpdates,
			})
		}
	}

	return updates, nil
}

// getObjectStreamRefs returns references to object streams in the revision.
func getObjectStreamRefs(state *RevisionState) []*generic.Reference {
	var refs []*generic.Reference

	for objNum, obj := range state.Objects {
		if stream, ok := obj.(*generic.StreamObject); ok {
			if stream.Dictionary.GetName("Type") == "ObjStm" {
				refs = append(refs, &generic.Reference{
					ObjectNumber:     objNum,
					GenerationNumber: 0,
				})
			}
		}
	}

	return refs
}

// XrefStreamRule allows new cross-reference streams to be defined.
type XrefStreamRule struct{}

// NewXrefStreamRule creates a new XrefStreamRule.
func NewXrefStreamRule() *XrefStreamRule {
	return &XrefStreamRule{}
}

// Apply implements WhitelistRule for XrefStreamRule.
func (r *XrefStreamRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	updates := []ReferenceUpdate{}

	// Get xref stream references from the new revision
	xrefStreamRef := getXrefStreamRef(new)

	if xrefStreamRef != nil && !old.HasObject(xrefStreamRef.ObjectNumber) {
		updates = append(updates, ReferenceUpdate{
			Reference: xrefStreamRef,
			Level:     ModificationLTAUpdates,
		})
	}

	return updates, nil
}

// getXrefStreamRef returns the reference to the xref stream if present.
func getXrefStreamRef(state *RevisionState) *generic.Reference {
	for objNum, obj := range state.Objects {
		if stream, ok := obj.(*generic.StreamObject); ok {
			if stream.Dictionary.GetName("Type") == "XRef" {
				return &generic.Reference{
					ObjectNumber:     objNum,
					GenerationNumber: 0,
				}
			}
		}
	}
	return nil
}

// FileStructureRuleSet combines all file structure rules.
type FileStructureRuleSet struct {
	CatalogRule      *CatalogModificationRule
	ObjectStreamRule *ObjectStreamRule
	XrefStreamRule   *XrefStreamRule
}

// NewFileStructureRuleSet creates a new file structure rule set with default settings.
func NewFileStructureRuleSet() *FileStructureRuleSet {
	return &FileStructureRuleSet{
		CatalogRule:      NewCatalogModificationRule(),
		ObjectStreamRule: NewObjectStreamRule(),
		XrefStreamRule:   NewXrefStreamRule(),
	}
}

// Apply applies all file structure rules and returns combined updates.
func (rs *FileStructureRuleSet) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	allUpdates := []ReferenceUpdate{}

	// Apply catalog modification rule
	catalogUpdates, err := rs.CatalogRule.Apply(old, new)
	if err != nil {
		return nil, err
	}
	allUpdates = append(allUpdates, catalogUpdates...)

	// Apply object stream rule
	objStreamUpdates, err := rs.ObjectStreamRule.Apply(old, new)
	if err != nil {
		return nil, err
	}
	allUpdates = append(allUpdates, objStreamUpdates...)

	// Apply xref stream rule
	xrefUpdates, err := rs.XrefStreamRule.Apply(old, new)
	if err != nil {
		return nil, err
	}
	allUpdates = append(allUpdates, xrefUpdates...)

	return allUpdates, nil
}
