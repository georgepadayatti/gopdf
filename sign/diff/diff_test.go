package diff

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/form"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestModificationLevelString(t *testing.T) {
	tests := []struct {
		level    ModificationLevel
		expected string
	}{
		{ModificationNone, "None"},
		{ModificationLTAUpdates, "LTA Updates"},
		{ModificationFormFilling, "Form Filling"},
		{ModificationAnnotations, "Annotations"},
		{ModificationOther, "Other"},
	}

	for _, tt := range tests {
		if tt.level.String() != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, tt.level.String())
		}
	}
}

func TestModificationLevelIsAllowed(t *testing.T) {
	tests := []struct {
		level   ModificationLevel
		perm    form.MDPPerm
		allowed bool
	}{
		{ModificationNone, form.MDPPermNoChanges, true},
		{ModificationLTAUpdates, form.MDPPermNoChanges, true},
		{ModificationFormFilling, form.MDPPermNoChanges, false},
		{ModificationNone, form.MDPPermFillForms, true},
		{ModificationFormFilling, form.MDPPermFillForms, true},
		{ModificationAnnotations, form.MDPPermFillForms, false},
		{ModificationAnnotations, form.MDPPermAnnotate, true},
		{ModificationOther, form.MDPPermAnnotate, false},
	}

	for _, tt := range tests {
		result := tt.level.IsAllowed(tt.perm)
		if result != tt.allowed {
			t.Errorf("Level %v with perm %v: expected %v, got %v",
				tt.level, tt.perm, tt.allowed, result)
		}
	}
}

func TestFieldMDPSpecIsFieldLocked(t *testing.T) {
	// Test with nil spec
	var spec *FieldMDPSpec = nil
	if spec.IsFieldLocked("Field1") {
		t.Error("Nil spec should not lock any field")
	}

	// Test All action
	specAll := &FieldMDPSpec{Action: FieldMDPActionAll}
	if !specAll.IsFieldLocked("Field1") {
		t.Error("All action should lock all fields")
	}
	if !specAll.IsFieldLocked("AnyField") {
		t.Error("All action should lock all fields")
	}

	// Test Include action
	specInclude := &FieldMDPSpec{
		Action: FieldMDPActionInclude,
		Fields: []string{"Field1", "Field2"},
	}
	if !specInclude.IsFieldLocked("Field1") {
		t.Error("Include should lock Field1")
	}
	if !specInclude.IsFieldLocked("Field2") {
		t.Error("Include should lock Field2")
	}
	if specInclude.IsFieldLocked("Field3") {
		t.Error("Include should not lock Field3")
	}

	// Test Exclude action
	specExclude := &FieldMDPSpec{
		Action: FieldMDPActionExclude,
		Fields: []string{"Field1"},
	}
	if specExclude.IsFieldLocked("Field1") {
		t.Error("Exclude should not lock Field1")
	}
	if !specExclude.IsFieldLocked("Field2") {
		t.Error("Exclude should lock Field2")
	}
}

func TestRevisionStateGetObject(t *testing.T) {
	state := &RevisionState{
		Revision: 1,
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(),
			2: generic.IntegerObject(42),
		},
	}

	if state.GetObject(1) == nil {
		t.Error("Object 1 should exist")
	}
	if state.GetObject(2) == nil {
		t.Error("Object 2 should exist")
	}
	if state.GetObject(3) != nil {
		t.Error("Object 3 should not exist")
	}

	if !state.HasObject(1) {
		t.Error("HasObject(1) should return true")
	}
	if state.HasObject(3) {
		t.Error("HasObject(3) should return false")
	}
}

func TestNewStandardDiffPolicy(t *testing.T) {
	policy := NewStandardDiffPolicy()

	if !policy.AllowFormFilling {
		t.Error("AllowFormFilling should be true by default")
	}
	if !policy.AllowSignatures {
		t.Error("AllowSignatures should be true by default")
	}
	if !policy.AllowDSSUpdates {
		t.Error("AllowDSSUpdates should be true by default")
	}
	if !policy.AllowTimestamps {
		t.Error("AllowTimestamps should be true by default")
	}
	if policy.StrictMode {
		t.Error("StrictMode should be false by default")
	}
}

func TestStandardDiffPolicyApplyNoChanges(t *testing.T) {
	oldState := &RevisionState{
		Revision: 0,
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(),
		},
	}
	newState := &RevisionState{
		Revision: 1,
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(),
		},
	}

	policy := NewStandardDiffPolicy()
	result, err := policy.Apply(oldState, newState, nil, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if result.ModificationLevel != ModificationNone {
		t.Errorf("Expected ModificationNone, got %v", result.ModificationLevel)
	}
}

func TestStandardDiffPolicyApplyNewSignature(t *testing.T) {
	oldState := &RevisionState{
		Revision: 0,
		Objects:  map[int]generic.PdfObject{},
	}

	sigDict := generic.NewDictionary()
	sigDict.Set("Type", generic.NameObject("Sig"))

	newState := &RevisionState{
		Revision: 1,
		Objects: map[int]generic.PdfObject{
			1: sigDict,
		},
	}

	policy := NewStandardDiffPolicy()
	result, err := policy.Apply(oldState, newState, nil, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if result.ModificationLevel != ModificationFormFilling {
		t.Errorf("Expected ModificationFormFilling, got %v", result.ModificationLevel)
	}
}

func TestStandardDiffPolicyApplyDSSUpdate(t *testing.T) {
	oldState := &RevisionState{
		Revision: 0,
		Objects:  map[int]generic.PdfObject{},
	}

	dssDict := generic.NewDictionary()
	dssDict.Set("Type", generic.NameObject("DSS"))

	newState := &RevisionState{
		Revision: 1,
		Objects: map[int]generic.PdfObject{
			1: dssDict,
		},
	}

	policy := NewStandardDiffPolicy()
	result, err := policy.Apply(oldState, newState, nil, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if result.ModificationLevel != ModificationLTAUpdates {
		t.Errorf("Expected ModificationLTAUpdates, got %v", result.ModificationLevel)
	}
}

func TestStandardDiffPolicyApplyObjectDeleted(t *testing.T) {
	oldState := &RevisionState{
		Revision: 0,
		Objects: map[int]generic.PdfObject{
			1: generic.NewDictionary(),
		},
	}
	newState := &RevisionState{
		Revision: 1,
		Objects:  map[int]generic.PdfObject{},
	}

	policy := NewStandardDiffPolicy()
	result, err := policy.Apply(oldState, newState, nil, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if result.ModificationLevel != ModificationOther {
		t.Errorf("Expected ModificationOther for deletion, got %v", result.ModificationLevel)
	}
}

func TestStandardDiffPolicyApplyWithDocMDP(t *testing.T) {
	oldState := &RevisionState{
		Revision: 0,
		Objects:  map[int]generic.PdfObject{},
	}

	sigDict := generic.NewDictionary()
	sigDict.Set("Type", generic.NameObject("Sig"))

	newState := &RevisionState{
		Revision: 1,
		Objects: map[int]generic.PdfObject{
			1: sigDict,
		},
	}

	policy := NewStandardDiffPolicy()

	// Should fail with NoChanges
	perm := form.MDPPermNoChanges
	_, err := policy.Apply(oldState, newState, nil, &perm)
	if err == nil {
		t.Error("Should fail with MDPPermNoChanges")
	}

	// Should succeed with FillForms
	perm = form.MDPPermFillForms
	result, err := policy.Apply(oldState, newState, nil, &perm)
	if err != nil {
		t.Fatalf("Should succeed with MDPPermFillForms: %v", err)
	}
	if result.ModificationLevel != ModificationFormFilling {
		t.Error("Expected ModificationFormFilling")
	}
}

func TestAssertNotStream(t *testing.T) {
	dict := generic.NewDictionary()
	if err := AssertNotStream(dict); err != nil {
		t.Error("Dictionary should not trigger error")
	}

	stream := &generic.StreamObject{}
	if err := AssertNotStream(stream); err == nil {
		t.Error("Stream should trigger error")
	}
}

func TestCompareDicts(t *testing.T) {
	dict1 := generic.NewDictionary()
	dict1.Set("Key1", generic.IntegerObject(1))
	dict1.Set("Key2", generic.NameObject("Value"))

	dict2 := generic.NewDictionary()
	dict2.Set("Key1", generic.IntegerObject(1))
	dict2.Set("Key2", generic.NameObject("Value"))

	equal, err := CompareDicts(dict1, dict2, nil)
	if err != nil {
		t.Fatalf("CompareDicts failed: %v", err)
	}
	if !equal {
		t.Error("Identical dicts should be equal")
	}

	// Test with different value
	dict3 := generic.NewDictionary()
	dict3.Set("Key1", generic.IntegerObject(2))
	dict3.Set("Key2", generic.NameObject("Value"))

	equal, err = CompareDicts(dict1, dict3, nil)
	if err != nil {
		t.Fatalf("CompareDicts failed: %v", err)
	}
	if equal {
		t.Error("Dicts with different values should not be equal")
	}

	// Test with ignored key
	equal, err = CompareDicts(dict1, dict3, []string{"Key1"})
	if err != nil {
		t.Fatalf("CompareDicts failed: %v", err)
	}
	if !equal {
		t.Error("Dicts should be equal when different key is ignored")
	}
}

func TestCompareDictsNil(t *testing.T) {
	dict := generic.NewDictionary()

	_, err := CompareDicts(nil, dict, nil)
	if err == nil {
		t.Error("Should fail with nil old dict")
	}

	_, err = CompareDicts(dict, nil, nil)
	if err == nil {
		t.Error("Should fail with nil new dict")
	}
}

func TestNewDiffAnalyzer(t *testing.T) {
	old := &RevisionState{Revision: 0}
	new := &RevisionState{Revision: 1}

	analyzer := NewDiffAnalyzer(old, new)

	if analyzer.OldState != old {
		t.Error("OldState not set correctly")
	}
	if analyzer.NewState != new {
		t.Error("NewState not set correctly")
	}
	if analyzer.Policy == nil {
		t.Error("Policy should be set to default")
	}
}

func TestDiffAnalyzerWithFieldMDP(t *testing.T) {
	old := &RevisionState{Revision: 0}
	new := &RevisionState{Revision: 1}

	spec := &FieldMDPSpec{Action: FieldMDPActionAll}
	analyzer := NewDiffAnalyzer(old, new).WithFieldMDP(spec)

	if analyzer.FieldMDP != spec {
		t.Error("FieldMDP not set correctly")
	}
}

func TestDiffAnalyzerWithDocMDP(t *testing.T) {
	old := &RevisionState{Revision: 0}
	new := &RevisionState{Revision: 1}

	analyzer := NewDiffAnalyzer(old, new).WithDocMDP(form.MDPPermFillForms)

	if analyzer.DocMDP == nil || *analyzer.DocMDP != form.MDPPermFillForms {
		t.Error("DocMDP not set correctly")
	}
}

func TestDiffResultSummarizeChanges(t *testing.T) {
	result := &DiffResult{
		ModificationLevel: ModificationFormFilling,
		ChangedFormFields: []string{"Field1", "Field2"},
		Details:           []string{"Added signature", "Updated value"},
	}

	summary := result.SummarizeChanges()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	// Check that key information is present
	if !containsString(summary, "Form Filling") {
		t.Error("Summary should contain modification level")
	}
	if !containsString(summary, "Field1") {
		t.Error("Summary should contain changed field names")
	}
}

func TestDiffResultSummarizeChangesWithSuspicious(t *testing.T) {
	result := &DiffResult{
		ModificationLevel: ModificationOther,
		Suspicious:        true,
	}

	summary := result.SummarizeChanges()

	if !containsString(summary, "WARNING") || !containsString(summary, "Suspicious") {
		t.Error("Summary should contain suspicious warning")
	}
}

func TestSuspiciousModificationError(t *testing.T) {
	err := &SuspiciousModification{Message: "Test error"}
	if err.Error() != "Test error" {
		t.Errorf("Expected 'Test error', got '%s'", err.Error())
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
