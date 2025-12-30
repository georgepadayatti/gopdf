// Package diff provides tests for form field rules.
package diff

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestNewDSSCompareRule(t *testing.T) {
	rule := NewDSSCompareRule()
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
}

func TestDSSCompareRuleApply(t *testing.T) {
	tests := []struct {
		name      string
		old       *RevisionState
		new       *RevisionState
		expectErr bool
	}{
		{
			name: "nil DSS in new revision",
			old:  &RevisionState{},
			new:  &RevisionState{},
		},
		{
			name: "valid empty DSS",
			old:  &RevisionState{},
			new: &RevisionState{
				DSS: &generic.DictionaryObject{},
			},
		},
		{
			name: "DSS with unexpected key",
			old:  &RevisionState{},
			new: &RevisionState{
				DSS: func() *generic.DictionaryObject {
					d := generic.NewDictionary()
					d.Set("/BadKey", generic.IntegerObject(123))
					return d
				}(),
			},
			expectErr: true,
		},
	}

	rule := NewDSSCompareRule()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rule.Apply(tc.old, tc.new)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDSSCompareRuleValidateDSSStructure(t *testing.T) {
	rule := NewDSSCompareRule()

	tests := []struct {
		name      string
		dss       *generic.DictionaryObject
		expectErr bool
	}{
		{
			name: "nil DSS",
			dss:  nil,
		},
		{
			name: "empty DSS",
			dss:  &generic.DictionaryObject{},
		},
		{
			name: "DSS with valid Certs array",
			dss: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				ref := generic.Reference{ObjectNumber: 1}
				d.Set("/Certs", generic.ArrayObject{&ref})
				return d
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.validateDSSStructure(tc.dss)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAssertStreamRefs(t *testing.T) {
	tests := []struct {
		name      string
		obj       generic.PdfObject
		keyName   string
		isVRI     bool
		expectErr bool
	}{
		{
			name:      "not an array",
			obj:       generic.IntegerObject(123),
			keyName:   "/Test",
			isVRI:     false,
			expectErr: true,
		},
		{
			name:    "empty array",
			obj:     generic.ArrayObject{},
			keyName: "/Test",
			isVRI:   false,
		},
		{
			name: "array with references",
			obj: generic.ArrayObject{
				&generic.Reference{ObjectNumber: 1},
				&generic.Reference{ObjectNumber: 2},
			},
			keyName: "/Test",
			isVRI:   false,
		},
		{
			name: "array with direct objects",
			obj: generic.ArrayObject{
				generic.IntegerObject(1),
			},
			keyName:   "/Test",
			isVRI:     true,
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := assertStreamRefs(tc.obj, tc.keyName, tc.isVRI)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNewSigFieldCreationRule(t *testing.T) {
	rule := NewSigFieldCreationRule()
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if !rule.ApproveWidgetBindings {
		t.Error("ApproveWidgetBindings should default to true")
	}
	if rule.AllowNewVisibleAfterCertify {
		t.Error("AllowNewVisibleAfterCertify should default to false")
	}
}

func TestSigFieldCreationRuleApply(t *testing.T) {
	rule := NewSigFieldCreationRule()

	tests := []struct {
		name      string
		ctx       *FieldComparisonContext
		expectErr bool
	}{
		{
			name: "empty context",
			ctx: &FieldComparisonContext{
				Old:        &RevisionState{},
				New:        &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{},
			},
		},
		{
			name: "field was deleted",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"TestField": {
						FieldType:   "/Sig",
						OldFieldRef: &generic.Reference{ObjectNumber: 1},
						NewFieldRef: nil, // deleted
					},
				},
			},
			expectErr: true,
		},
		{
			name: "new signature field created",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"NewSig": {
						FieldType:   "/Sig",
						OldFieldRef: nil,
						NewFieldRef: &generic.Reference{ObjectNumber: 2},
						NewField:    &generic.DictionaryObject{},
					},
				},
			},
		},
		{
			name: "non-sig field created",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"NewText": {
						FieldType:   "/Tx",
						OldFieldRef: nil,
						NewFieldRef: &generic.Reference{ObjectNumber: 3},
					},
				},
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rule.Apply(tc.ctx)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNewBaseFieldModificationRule(t *testing.T) {
	rule := NewBaseFieldModificationRule()
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if !rule.AllowInPlaceAppearanceStreamChanges {
		t.Error("AllowInPlaceAppearanceStreamChanges should default to true")
	}
	if rule.AlwaysModifiable == nil {
		t.Error("AlwaysModifiable should not be nil")
	}
	if rule.ValueUpdateKeys == nil {
		t.Error("ValueUpdateKeys should not be nil")
	}
}

func TestBaseFieldModificationRuleCompareFields(t *testing.T) {
	rule := NewBaseFieldModificationRule()

	tests := []struct {
		name             string
		spec             *FieldComparisonSpec
		expectValid      bool
		expectErr        bool
	}{
		{
			name: "nil old field",
			spec: &FieldComparisonSpec{
				OldField: nil,
				NewField: &generic.DictionaryObject{},
			},
			expectValid: false,
		},
		{
			name: "nil new field",
			spec: &FieldComparisonSpec{
				OldField: &generic.DictionaryObject{},
				NewField: nil,
			},
			expectValid: false,
		},
		{
			name: "identical fields",
			spec: &FieldComparisonSpec{
				OldField: &generic.DictionaryObject{},
				NewField: &generic.DictionaryObject{},
			},
			expectValid: true,
		},
		{
			name: "value changed only",
			spec: &FieldComparisonSpec{
				OldField: func() *generic.DictionaryObject {
					d := generic.NewDictionary()
					d.Set("/V", generic.IntegerObject(1))
					return d
				}(),
				NewField: func() *generic.DictionaryObject {
					d := generic.NewDictionary()
					d.Set("/V", generic.IntegerObject(2))
					return d
				}(),
			},
			// /V is not in AlwaysModifiable, so changes to /V mean not valid when locked
			expectValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := rule.CompareFields(tc.spec)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if valid != tc.expectValid {
					t.Errorf("expected valid=%v, got %v", tc.expectValid, valid)
				}
			}
		})
	}
}

func TestNewSigFieldModificationRule(t *testing.T) {
	rule := NewSigFieldModificationRule()
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if rule.BaseFieldModificationRule == nil {
		t.Error("BaseFieldModificationRule should not be nil")
	}
}

func TestSigFieldModificationRuleApply(t *testing.T) {
	rule := NewSigFieldModificationRule()

	tests := []struct {
		name      string
		ctx       *FieldComparisonContext
		expectErr bool
		expectLen int
	}{
		{
			name: "empty context",
			ctx: &FieldComparisonContext{
				Old:        &RevisionState{},
				New:        &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{},
			},
			expectLen: 0,
		},
		{
			name: "non-sig field ignored",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"TextField": {
						FieldType:   "/Tx",
						OldFieldRef: &generic.Reference{ObjectNumber: 1},
						NewFieldRef: &generic.Reference{ObjectNumber: 1},
					},
				},
			},
			expectLen: 0,
		},
		{
			name: "sig field being signed",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"SigField": {
						FieldType:   "/Sig",
						OldFieldRef: &generic.Reference{ObjectNumber: 1},
						NewFieldRef: &generic.Reference{ObjectNumber: 1},
						OldField:    &generic.DictionaryObject{},
						NewField: func() *generic.DictionaryObject {
							d := generic.NewDictionary()
							d.Set("/V", &generic.Reference{ObjectNumber: 10})
							return d
						}(),
					},
				},
			},
			expectLen: 2, // field ref update + value ref update
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updates, err := rule.Apply(tc.ctx)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(updates) != tc.expectLen {
					t.Errorf("expected %d updates, got %d", tc.expectLen, len(updates))
				}
			}
		})
	}
}

func TestNewGenericFieldModificationRule(t *testing.T) {
	rule := NewGenericFieldModificationRule()
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
}

func TestGenericFieldModificationRuleApply(t *testing.T) {
	rule := NewGenericFieldModificationRule()

	tests := []struct {
		name      string
		ctx       *FieldComparisonContext
		expectErr bool
		expectLen int
	}{
		{
			name: "empty context",
			ctx: &FieldComparisonContext{
				Old:        &RevisionState{},
				New:        &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{},
			},
			expectLen: 0,
		},
		{
			name: "sig field ignored",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"SigField": {
						FieldType:   "/Sig",
						OldFieldRef: &generic.Reference{ObjectNumber: 1},
						NewFieldRef: &generic.Reference{ObjectNumber: 1},
					},
				},
			},
			expectLen: 0,
		},
		{
			name: "text field modified",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"TextField": {
						FieldType:   "/Tx",
						OldFieldRef: &generic.Reference{ObjectNumber: 1},
						NewFieldRef: &generic.Reference{ObjectNumber: 1},
						OldField:    &generic.DictionaryObject{},
						NewField:    &generic.DictionaryObject{},
					},
				},
			},
			expectLen: 1,
		},
		{
			name: "new field skipped",
			ctx: &FieldComparisonContext{
				Old: &RevisionState{},
				New: &RevisionState{},
				FieldSpecs: map[string]*FieldComparisonSpec{
					"NewField": {
						FieldType:   "/Tx",
						OldFieldRef: nil, // new field
						NewFieldRef: &generic.Reference{ObjectNumber: 2},
					},
				},
			},
			expectLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updates, err := rule.Apply(tc.ctx)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(updates) != tc.expectLen {
					t.Errorf("expected %d updates, got %d", tc.expectLen, len(updates))
				}
			}
		})
	}
}

func TestNewFormFieldRuleSet(t *testing.T) {
	ruleSet := NewFormFieldRuleSet()
	if ruleSet == nil {
		t.Fatal("expected non-nil rule set")
	}
	if len(ruleSet.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(ruleSet.Rules))
	}
}

func TestFormFieldRuleSetApply(t *testing.T) {
	ruleSet := NewFormFieldRuleSet()

	ctx := &FieldComparisonContext{
		Old:        &RevisionState{},
		New:        &RevisionState{},
		FieldSpecs: map[string]*FieldComparisonSpec{},
	}

	updates, err := ruleSet.Apply(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Empty context results in empty updates (can be nil or empty slice)
	_ = updates
}

func TestNewFieldComparisonContext(t *testing.T) {
	old := &RevisionState{Revision: 1}
	new := &RevisionState{Revision: 2}

	ctx := NewFieldComparisonContext(old, new)

	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.Old != old {
		t.Error("Old state not set correctly")
	}
	if ctx.New != new {
		t.Error("New state not set correctly")
	}
	if ctx.FieldSpecs == nil {
		t.Error("FieldSpecs should be initialized")
	}
}

func TestFieldComparisonContextWithFieldMDP(t *testing.T) {
	ctx := NewFieldComparisonContext(&RevisionState{}, &RevisionState{})
	spec := &FieldMDPSpec{
		Action: FieldMDPActionAll,
	}

	result := ctx.WithFieldMDP(spec)

	if result != ctx {
		t.Error("WithFieldMDP should return same context")
	}
	if ctx.FieldMDP != spec {
		t.Error("FieldMDP not set correctly")
	}
}

func TestFieldComparisonContextAddFieldSpec(t *testing.T) {
	ctx := NewFieldComparisonContext(&RevisionState{}, &RevisionState{})
	spec := &FieldComparisonSpec{
		FieldType: "/Tx",
	}

	ctx.AddFieldSpec("TestField", spec)

	if ctx.FieldSpecs["TestField"] != spec {
		t.Error("FieldSpec not added correctly")
	}
}

func TestFieldComparisonContextIsFieldLocked(t *testing.T) {
	tests := []struct {
		name       string
		fieldMDP   *FieldMDPSpec
		fieldName  string
		expectLock bool
	}{
		{
			name:       "nil FieldMDP",
			fieldMDP:   nil,
			fieldName:  "AnyField",
			expectLock: false,
		},
		{
			name: "All action",
			fieldMDP: &FieldMDPSpec{
				Action: FieldMDPActionAll,
			},
			fieldName:  "AnyField",
			expectLock: true,
		},
		{
			name: "Include action - included",
			fieldMDP: &FieldMDPSpec{
				Action: FieldMDPActionInclude,
				Fields: []string{"LockedField"},
			},
			fieldName:  "LockedField",
			expectLock: true,
		},
		{
			name: "Include action - not included",
			fieldMDP: &FieldMDPSpec{
				Action: FieldMDPActionInclude,
				Fields: []string{"LockedField"},
			},
			fieldName:  "OtherField",
			expectLock: false,
		},
		{
			name: "Exclude action - excluded",
			fieldMDP: &FieldMDPSpec{
				Action: FieldMDPActionExclude,
				Fields: []string{"UnlockedField"},
			},
			fieldName:  "UnlockedField",
			expectLock: false,
		},
		{
			name: "Exclude action - not excluded",
			fieldMDP: &FieldMDPSpec{
				Action: FieldMDPActionExclude,
				Fields: []string{"UnlockedField"},
			},
			fieldName:  "OtherField",
			expectLock: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewFieldComparisonContext(&RevisionState{}, &RevisionState{})
			ctx.FieldMDP = tc.fieldMDP

			locked := ctx.IsFieldLocked(tc.fieldName)
			if locked != tc.expectLock {
				t.Errorf("expected locked=%v, got %v", tc.expectLock, locked)
			}
		})
	}
}

func TestFieldComparisonSpec(t *testing.T) {
	spec := &FieldComparisonSpec{
		FieldType:   "/Sig",
		OldFieldRef: &generic.Reference{ObjectNumber: 1},
		NewFieldRef: &generic.Reference{ObjectNumber: 2},
		OldField:    &generic.DictionaryObject{},
		NewField:    &generic.DictionaryObject{},
	}

	if spec.FieldType != "/Sig" {
		t.Error("FieldType not set correctly")
	}
	if spec.OldFieldRef.ObjectNumber != 1 {
		t.Error("OldFieldRef not set correctly")
	}
	if spec.NewFieldRef.ObjectNumber != 2 {
		t.Error("NewFieldRef not set correctly")
	}
}

func TestDSSCompareRuleValidateVRIEntry(t *testing.T) {
	rule := NewDSSCompareRule()

	tests := []struct {
		name      string
		entry     generic.PdfObject
		expectErr bool
	}{
		{
			name:      "non-dictionary entry",
			entry:     generic.IntegerObject(123),
			expectErr: true,
		},
		{
			name:  "empty dictionary",
			entry: &generic.DictionaryObject{},
		},
		{
			name: "dictionary with unexpected key",
			entry: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("/BadKey", generic.IntegerObject(1))
				return d
			}(),
			expectErr: true,
		},
		{
			name: "dictionary with valid keys",
			entry: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("/Type", generic.NameObject("VRI"))
				d.Set("/TU", generic.IntegerObject(123))
				return d
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.validateVRIEntry(tc.entry)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestBaseFieldModificationRuleCheckTypeField(t *testing.T) {
	rule := NewBaseFieldModificationRule()

	tests := []struct {
		name      string
		oldField  *generic.DictionaryObject
		newField  *generic.DictionaryObject
		expectErr bool
	}{
		{
			name:     "no type in either",
			oldField: &generic.DictionaryObject{},
			newField: &generic.DictionaryObject{},
		},
		{
			name:     "type added as Annot",
			oldField: &generic.DictionaryObject{},
			newField: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("/Type", generic.NameObject("Annot"))
				return d
			}(),
		},
		{
			name:     "type added as wrong value",
			oldField: &generic.DictionaryObject{},
			newField: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("/Type", generic.NameObject("Wrong"))
				return d
			}(),
			expectErr: true,
		},
		{
			name: "type deleted",
			oldField: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("/Type", generic.NameObject("Annot"))
				return d
			}(),
			newField:  &generic.DictionaryObject{},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.checkTypeField(tc.oldField, tc.newField)
			if tc.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
