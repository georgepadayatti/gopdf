package diff

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestNewCatalogModificationRule(t *testing.T) {
	rule := NewCatalogModificationRule()

	if rule.IgnoredKeys == nil {
		t.Error("IgnoredKeys should not be nil")
	}

	// Check that default ignored keys are set
	expectedKeys := []string{"AcroForm", "DSS", "Extensions", "Metadata", "MarkInfo", "Version"}
	for _, key := range expectedKeys {
		if !rule.IgnoredKeys[key] {
			t.Errorf("Expected '%s' to be in IgnoredKeys", key)
		}
	}
}

func TestCatalogModificationRuleNoChanges(t *testing.T) {
	rule := NewCatalogModificationRule()

	// Create identical catalogs
	oldRoot := generic.NewDictionary()
	oldRoot.Set("Type", generic.NameObject("Catalog"))
	oldRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	newRoot := generic.NewDictionary()
	newRoot.Set("Type", generic.NameObject("Catalog"))
	newRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	oldState := &RevisionState{
		Root:    oldRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: oldRoot},
	}

	newState := &RevisionState{
		Root:    newRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: newRoot},
	}

	_, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("Expected no error for unchanged catalog, got: %v", err)
	}
}

func TestCatalogModificationRuleIgnoredKeyChange(t *testing.T) {
	rule := NewCatalogModificationRule()

	// Create catalogs with changes to ignored keys
	oldRoot := generic.NewDictionary()
	oldRoot.Set("Type", generic.NameObject("Catalog"))
	oldRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	newRoot := generic.NewDictionary()
	newRoot.Set("Type", generic.NameObject("Catalog"))
	newRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})
	newRoot.Set("DSS", generic.Reference{ObjectNumber: 5, GenerationNumber: 0}) // Ignored key

	oldState := &RevisionState{
		Root:    oldRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: oldRoot},
	}

	newState := &RevisionState{
		Root:    newRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: newRoot},
	}

	_, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("Expected no error for ignored key change, got: %v", err)
	}
}

func TestCatalogModificationRuleSuspiciousChange(t *testing.T) {
	rule := NewCatalogModificationRule()

	// Create catalogs with changes to non-ignored keys
	oldRoot := generic.NewDictionary()
	oldRoot.Set("Type", generic.NameObject("Catalog"))
	oldRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	newRoot := generic.NewDictionary()
	newRoot.Set("Type", generic.NameObject("Catalog"))
	newRoot.Set("Pages", generic.Reference{ObjectNumber: 99, GenerationNumber: 0}) // Changed!

	oldState := &RevisionState{
		Root:    oldRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: oldRoot},
	}

	newState := &RevisionState{
		Root:    newRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: newRoot},
	}

	_, err := rule.Apply(oldState, newState)
	if err == nil {
		t.Error("Expected error for suspicious catalog change")
	}
}

func TestCatalogModificationRuleKeyRemoved(t *testing.T) {
	rule := NewCatalogModificationRule()

	oldRoot := generic.NewDictionary()
	oldRoot.Set("Type", generic.NameObject("Catalog"))
	oldRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})
	oldRoot.Set("Outlines", generic.Reference{ObjectNumber: 3, GenerationNumber: 0})

	newRoot := generic.NewDictionary()
	newRoot.Set("Type", generic.NameObject("Catalog"))
	newRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})
	// Outlines removed!

	oldState := &RevisionState{
		Root:    oldRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: oldRoot},
	}

	newState := &RevisionState{
		Root:    newRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: newRoot},
	}

	_, err := rule.Apply(oldState, newState)
	if err == nil {
		t.Error("Expected error for removed catalog key")
	}
}

func TestCatalogModificationRuleExtensionsAdded(t *testing.T) {
	rule := NewCatalogModificationRule()

	oldRoot := generic.NewDictionary()
	oldRoot.Set("Type", generic.NameObject("Catalog"))
	oldRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	newRoot := generic.NewDictionary()
	newRoot.Set("Type", generic.NameObject("Catalog"))
	newRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})
	newRoot.Set("Extensions", generic.Reference{ObjectNumber: 10, GenerationNumber: 0})

	oldState := &RevisionState{
		Root:    oldRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: oldRoot},
	}

	newState := &RevisionState{
		Root:    newRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: newRoot},
	}

	updates, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("Expected no error for Extensions addition, got: %v", err)
	}

	// Should have updates for the new Extensions reference
	foundExtensionsUpdate := false
	for _, u := range updates {
		if u.Reference != nil && u.Reference.ObjectNumber == 10 {
			foundExtensionsUpdate = true
			if u.Level != ModificationLTAUpdates {
				t.Error("Extensions update should be LTA level")
			}
		}
	}
	if !foundExtensionsUpdate {
		t.Error("Expected update for Extensions reference")
	}
}

func TestObjectStreamRule(t *testing.T) {
	rule := NewObjectStreamRule()

	// Create object stream
	objStreamDict := generic.NewDictionary()
	objStreamDict.Set("Type", generic.NameObject("ObjStm"))
	objStream := generic.NewStream(objStreamDict, []byte{})

	oldState := &RevisionState{
		Objects: map[int]generic.PdfObject{},
	}

	newState := &RevisionState{
		Objects: map[int]generic.PdfObject{
			5: objStream,
		},
	}

	updates, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("ObjectStreamRule.Apply returned error: %v", err)
	}

	if len(updates) != 1 {
		t.Errorf("Expected 1 update, got %d", len(updates))
	}

	if updates[0].Reference.ObjectNumber != 5 {
		t.Errorf("Expected object number 5, got %d", updates[0].Reference.ObjectNumber)
	}

	if updates[0].Level != ModificationLTAUpdates {
		t.Error("Object stream update should be LTA level")
	}
}

func TestObjectStreamRuleExisting(t *testing.T) {
	rule := NewObjectStreamRule()

	objStreamDict := generic.NewDictionary()
	objStreamDict.Set("Type", generic.NameObject("ObjStm"))
	objStream := generic.NewStream(objStreamDict, []byte{})

	// Object stream exists in old revision
	oldState := &RevisionState{
		Objects: map[int]generic.PdfObject{
			5: objStream,
		},
	}

	newState := &RevisionState{
		Objects: map[int]generic.PdfObject{
			5: objStream,
		},
	}

	updates, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("ObjectStreamRule.Apply returned error: %v", err)
	}

	// Should not whitelist existing object stream
	if len(updates) != 0 {
		t.Errorf("Expected 0 updates for existing object stream, got %d", len(updates))
	}
}

func TestXrefStreamRule(t *testing.T) {
	rule := NewXrefStreamRule()

	// Create xref stream
	xrefStreamDict := generic.NewDictionary()
	xrefStreamDict.Set("Type", generic.NameObject("XRef"))
	xrefStream := generic.NewStream(xrefStreamDict, []byte{})

	oldState := &RevisionState{
		Objects: map[int]generic.PdfObject{},
	}

	newState := &RevisionState{
		Objects: map[int]generic.PdfObject{
			10: xrefStream,
		},
	}

	updates, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("XrefStreamRule.Apply returned error: %v", err)
	}

	if len(updates) != 1 {
		t.Errorf("Expected 1 update, got %d", len(updates))
	}

	if updates[0].Reference.ObjectNumber != 10 {
		t.Errorf("Expected object number 10, got %d", updates[0].Reference.ObjectNumber)
	}

	if updates[0].Level != ModificationLTAUpdates {
		t.Error("Xref stream update should be LTA level")
	}
}

func TestXrefStreamRuleNoXrefStream(t *testing.T) {
	rule := NewXrefStreamRule()

	oldState := &RevisionState{
		Objects: map[int]generic.PdfObject{},
	}

	newState := &RevisionState{
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(), // Regular object, not xref stream
		},
	}

	updates, err := rule.Apply(oldState, newState)
	if err != nil {
		t.Errorf("XrefStreamRule.Apply returned error: %v", err)
	}

	if len(updates) != 0 {
		t.Errorf("Expected 0 updates for no xref stream, got %d", len(updates))
	}
}

func TestFileStructureRuleSet(t *testing.T) {
	ruleSet := NewFileStructureRuleSet()

	if ruleSet.CatalogRule == nil {
		t.Error("CatalogRule should not be nil")
	}

	if ruleSet.ObjectStreamRule == nil {
		t.Error("ObjectStreamRule should not be nil")
	}

	if ruleSet.XrefStreamRule == nil {
		t.Error("XrefStreamRule should not be nil")
	}
}

func TestFileStructureRuleSetApply(t *testing.T) {
	ruleSet := NewFileStructureRuleSet()

	// Create object stream and xref stream
	objStreamDict := generic.NewDictionary()
	objStreamDict.Set("Type", generic.NameObject("ObjStm"))
	objStream := generic.NewStream(objStreamDict, []byte{})

	xrefStreamDict := generic.NewDictionary()
	xrefStreamDict.Set("Type", generic.NameObject("XRef"))
	xrefStream := generic.NewStream(xrefStreamDict, []byte{})

	oldRoot := generic.NewDictionary()
	oldRoot.Set("Type", generic.NameObject("Catalog"))
	oldRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	newRoot := generic.NewDictionary()
	newRoot.Set("Type", generic.NameObject("Catalog"))
	newRoot.Set("Pages", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	oldState := &RevisionState{
		Root:    oldRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{2: oldRoot},
	}

	newState := &RevisionState{
		Root:    newRoot,
		Trailer: createTrailerWithRoot(2),
		Objects: map[int]generic.PdfObject{
			2:  newRoot,
			5:  objStream,
			10: xrefStream,
		},
	}

	updates, err := ruleSet.Apply(oldState, newState)
	if err != nil {
		t.Errorf("FileStructureRuleSet.Apply returned error: %v", err)
	}

	// Should have updates for object stream and xref stream
	if len(updates) < 2 {
		t.Errorf("Expected at least 2 updates, got %d", len(updates))
	}
}

func TestGetReference(t *testing.T) {
	tests := []struct {
		name     string
		obj      generic.PdfObject
		wantRef  bool
		wantNum  int
	}{
		{
			name:    "nil object",
			obj:     nil,
			wantRef: false,
		},
		{
			name:     "Reference pointer",
			obj:      &generic.Reference{ObjectNumber: 5},
			wantRef:  true,
			wantNum:  5,
		},
		{
			name:     "Reference value",
			obj:      generic.Reference{ObjectNumber: 10},
			wantRef:  true,
			wantNum:  10,
		},
		{
			name:    "Dictionary",
			obj:     generic.NewDictionary(),
			wantRef: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, ok := getReference(tt.obj)
			if ok != tt.wantRef {
				t.Errorf("getReference() ok = %v, want %v", ok, tt.wantRef)
			}
			if ok && ref.ObjectNumber != tt.wantNum {
				t.Errorf("getReference() ObjectNumber = %d, want %d", ref.ObjectNumber, tt.wantNum)
			}
		})
	}
}

func TestGetObjectStreamRefs(t *testing.T) {
	objStreamDict := generic.NewDictionary()
	objStreamDict.Set("Type", generic.NameObject("ObjStm"))
	objStream := generic.NewStream(objStreamDict, []byte{})

	regularDict := generic.NewDictionary()
	regularDict.Set("Type", generic.NameObject("Page"))
	regularStream := generic.NewStream(regularDict, []byte{})

	state := &RevisionState{
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(),
			5: objStream,
			8: regularStream,
		},
	}

	refs := getObjectStreamRefs(state)

	if len(refs) != 1 {
		t.Errorf("Expected 1 object stream ref, got %d", len(refs))
	}

	if refs[0].ObjectNumber != 5 {
		t.Errorf("Expected object number 5, got %d", refs[0].ObjectNumber)
	}
}

func TestGetXrefStreamRef(t *testing.T) {
	xrefStreamDict := generic.NewDictionary()
	xrefStreamDict.Set("Type", generic.NameObject("XRef"))
	xrefStream := generic.NewStream(xrefStreamDict, []byte{})

	state := &RevisionState{
		Objects: map[int]generic.PdfObject{
			1:  generic.NewDictionary(),
			10: xrefStream,
		},
	}

	ref := getXrefStreamRef(state)

	if ref == nil {
		t.Fatal("Expected xref stream ref, got nil")
	}

	if ref.ObjectNumber != 10 {
		t.Errorf("Expected object number 10, got %d", ref.ObjectNumber)
	}
}

func TestGetXrefStreamRefNone(t *testing.T) {
	state := &RevisionState{
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(),
		},
	}

	ref := getXrefStreamRef(state)

	if ref != nil {
		t.Errorf("Expected nil for no xref stream, got %v", ref)
	}
}

func TestRootExemptStrictComparison(t *testing.T) {
	expectedKeys := []string{"AcroForm", "DSS", "Extensions", "Metadata", "MarkInfo", "Version"}

	for _, key := range expectedKeys {
		if !RootExemptStrictComparison[key] {
			t.Errorf("Expected '%s' to be in RootExemptStrictComparison", key)
		}
	}

	// Check that other keys are not in the set
	unexpectedKeys := []string{"Pages", "Type", "Outlines", "Names"}
	for _, key := range unexpectedKeys {
		if RootExemptStrictComparison[key] {
			t.Errorf("Did not expect '%s' to be in RootExemptStrictComparison", key)
		}
	}
}

// Helper function to create a trailer with a Root reference
func createTrailerWithRoot(rootObjNum int) *generic.DictionaryObject {
	trailer := generic.NewDictionary()
	trailer.Set("Root", generic.Reference{ObjectNumber: rootObjNum, GenerationNumber: 0})
	return trailer
}
