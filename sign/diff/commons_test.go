package diff

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestAssertNotStreamObject(t *testing.T) {
	t.Run("nil object", func(t *testing.T) {
		err := AssertNotStreamObject(nil)
		if err != nil {
			t.Errorf("expected no error for nil object, got %v", err)
		}
	})

	t.Run("dictionary object", func(t *testing.T) {
		dict := generic.NewDictionary()
		err := AssertNotStreamObject(dict)
		if err != nil {
			t.Errorf("expected no error for dictionary, got %v", err)
		}
	})

	t.Run("stream object", func(t *testing.T) {
		stream := generic.NewStream(generic.NewDictionary(), []byte{})
		err := AssertNotStreamObject(stream)
		if err == nil {
			t.Error("expected error for stream object")
		}
		if _, ok := err.(*SuspiciousModification); !ok {
			t.Errorf("expected SuspiciousModification, got %T", err)
		}
	})

	t.Run("integer object", func(t *testing.T) {
		err := AssertNotStreamObject(generic.IntegerObject(42))
		if err != nil {
			t.Errorf("expected no error for integer, got %v", err)
		}
	})
}

func TestSafeWhitelist(t *testing.T) {
	t.Run("nil old ref same as nil new ref", func(t *testing.T) {
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{},
		}
		refs, err := SafeWhitelist(state, nil, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(refs) != 0 {
			t.Errorf("expected 0 refs, got %d", len(refs))
		}
	})

	t.Run("same reference non-stream", func(t *testing.T) {
		dict := generic.NewDictionary()
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{
				1: dict,
			},
		}
		oldRef := &generic.Reference{ObjectNumber: 1}
		newRef := &generic.Reference{ObjectNumber: 1}

		refs, err := SafeWhitelist(state, oldRef, newRef)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(refs) != 1 {
			t.Errorf("expected 1 ref, got %d", len(refs))
		}
	})

	t.Run("same reference stream object", func(t *testing.T) {
		stream := generic.NewStream(generic.NewDictionary(), []byte{})
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{
				1: stream,
			},
		}
		oldRef := &generic.Reference{ObjectNumber: 1}
		newRef := &generic.Reference{ObjectNumber: 1}

		_, err := SafeWhitelist(state, oldRef, newRef)
		if err == nil {
			t.Error("expected error for stream object")
		}
	})

	t.Run("different reference new object", func(t *testing.T) {
		dict := generic.NewDictionary()
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{
				1: dict,
			},
		}
		oldRef := &generic.Reference{ObjectNumber: 1}
		newRef := &generic.Reference{ObjectNumber: 2} // New object

		refs, err := SafeWhitelist(state, oldRef, newRef)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(refs) != 1 {
			t.Errorf("expected 1 ref, got %d", len(refs))
		}
		if refs[0].ObjectNumber != 2 {
			t.Errorf("expected object number 2, got %d", refs[0].ObjectNumber)
		}
	})

	t.Run("different reference clobbers existing", func(t *testing.T) {
		dict1 := generic.NewDictionary()
		dict2 := generic.NewDictionary()
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{
				1: dict1,
				2: dict2, // Already exists
			},
		}
		oldRef := &generic.Reference{ObjectNumber: 1}
		newRef := &generic.Reference{ObjectNumber: 2} // Clobbers existing

		_, err := SafeWhitelist(state, oldRef, newRef)
		if err == nil {
			t.Error("expected error for clobbering existing object")
		}
	})
}

func TestCompareKeyRefs(t *testing.T) {
	t.Run("both nil dictionaries", func(t *testing.T) {
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{},
		}
		refs, versions, err := CompareKeyRefs("Test", state, nil, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(refs) != 0 {
			t.Errorf("expected 0 refs, got %d", len(refs))
		}
		if versions.Old != nil || versions.New != nil {
			t.Error("expected nil versions")
		}
	})

	t.Run("key deleted", func(t *testing.T) {
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{},
		}
		oldDict := generic.NewDictionary()
		oldDict.Set("Test", generic.IntegerObject(42))
		newDict := generic.NewDictionary()

		_, _, err := CompareKeyRefs("Test", state, oldDict, newDict)
		if err == nil {
			t.Error("expected error for deleted key")
		}
	})

	t.Run("key added", func(t *testing.T) {
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{},
		}
		oldDict := generic.NewDictionary()
		newDict := generic.NewDictionary()
		newDict.Set("Test", generic.IntegerObject(42))

		refs, versions, err := CompareKeyRefs("Test", state, oldDict, newDict)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(refs) != 0 {
			t.Errorf("expected 0 refs, got %d", len(refs))
		}
		if versions.Old != nil {
			t.Error("expected nil old value")
		}
		if versions.New == nil {
			t.Error("expected non-nil new value")
		}
	})

	t.Run("direct value unchanged", func(t *testing.T) {
		state := &RevisionState{
			Objects: map[int]generic.PdfObject{},
		}
		oldDict := generic.NewDictionary()
		oldDict.Set("Test", generic.IntegerObject(42))
		newDict := generic.NewDictionary()
		newDict.Set("Test", generic.IntegerObject(42))

		refs, versions, err := CompareKeyRefs("Test", state, oldDict, newDict)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(refs) != 0 {
			t.Errorf("expected 0 refs, got %d", len(refs))
		}
		if versions.Old == nil || versions.New == nil {
			t.Error("expected non-nil versions")
		}
	})
}

func TestQualify(t *testing.T) {
	updates := []ReferenceUpdate{
		{Reference: &generic.Reference{ObjectNumber: 1}},
		{Reference: &generic.Reference{ObjectNumber: 2}},
	}

	qualified := Qualify(ModificationFormFilling, updates)

	if len(qualified) != 2 {
		t.Errorf("expected 2 qualified updates, got %d", len(qualified))
	}

	for _, q := range qualified {
		if q.Level != ModificationFormFilling {
			t.Errorf("expected ModificationFormFilling, got %v", q.Level)
		}
	}
}

func TestQualifyRefs(t *testing.T) {
	refs := []*generic.Reference{
		{ObjectNumber: 1},
		{ObjectNumber: 2},
		{ObjectNumber: 3},
	}

	qualified := QualifyRefs(ModificationLTAUpdates, refs)

	if len(qualified) != 3 {
		t.Errorf("expected 3 qualified updates, got %d", len(qualified))
	}

	for i, q := range qualified {
		if q.Level != ModificationLTAUpdates {
			t.Errorf("expected ModificationLTAUpdates, got %v", q.Level)
		}
		if q.Update.Reference.ObjectNumber != refs[i].ObjectNumber {
			t.Errorf("expected object number %d, got %d", refs[i].ObjectNumber, q.Update.Reference.ObjectNumber)
		}
	}
}

func TestCompareDictsStrict(t *testing.T) {
	t.Run("nil old dict", func(t *testing.T) {
		newDict := generic.NewDictionary()
		_, err := CompareDictsStrict(nil, newDict, nil, true)
		if err == nil {
			t.Error("expected error for nil old dict")
		}
	})

	t.Run("nil new dict", func(t *testing.T) {
		oldDict := generic.NewDictionary()
		eq, err := CompareDictsStrict(oldDict, nil, nil, false)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eq {
			t.Error("expected false for nil new dict")
		}
	})

	t.Run("nil new dict with error", func(t *testing.T) {
		oldDict := generic.NewDictionary()
		_, err := CompareDictsStrict(oldDict, nil, nil, true)
		if err == nil {
			t.Error("expected error for nil new dict")
		}
	})

	t.Run("equal dictionaries", func(t *testing.T) {
		oldDict := generic.NewDictionary()
		oldDict.Set("Key1", generic.IntegerObject(1))
		oldDict.Set("Key2", generic.NameObject("Value"))

		newDict := generic.NewDictionary()
		newDict.Set("Key1", generic.IntegerObject(1))
		newDict.Set("Key2", generic.NameObject("Value"))

		eq, err := CompareDictsStrict(oldDict, newDict, nil, true)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !eq {
			t.Error("expected dictionaries to be equal")
		}
	})

	t.Run("different values", func(t *testing.T) {
		oldDict := generic.NewDictionary()
		oldDict.Set("Key1", generic.IntegerObject(1))

		newDict := generic.NewDictionary()
		newDict.Set("Key1", generic.IntegerObject(2))

		eq, err := CompareDictsStrict(oldDict, newDict, nil, false)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eq {
			t.Error("expected dictionaries to not be equal")
		}
	})

	t.Run("different keys", func(t *testing.T) {
		oldDict := generic.NewDictionary()
		oldDict.Set("Key1", generic.IntegerObject(1))

		newDict := generic.NewDictionary()
		newDict.Set("Key2", generic.IntegerObject(1))

		eq, err := CompareDictsStrict(oldDict, newDict, nil, false)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eq {
			t.Error("expected dictionaries to not be equal")
		}
	})

	t.Run("with ignored keys", func(t *testing.T) {
		oldDict := generic.NewDictionary()
		oldDict.Set("Key1", generic.IntegerObject(1))
		oldDict.Set("Ignored", generic.IntegerObject(100))

		newDict := generic.NewDictionary()
		newDict.Set("Key1", generic.IntegerObject(1))
		newDict.Set("Ignored", generic.IntegerObject(999))

		ignored := map[string]bool{"Ignored": true}
		eq, err := CompareDictsStrict(oldDict, newDict, ignored, true)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !eq {
			t.Error("expected dictionaries to be equal ignoring 'Ignored' key")
		}
	})
}

func TestIsAnnotVisible(t *testing.T) {
	t.Run("nil dict", func(t *testing.T) {
		if IsAnnotVisible(nil) {
			t.Error("expected false for nil dict")
		}
	})

	t.Run("no rect", func(t *testing.T) {
		dict := generic.NewDictionary()
		if IsAnnotVisible(dict) {
			t.Error("expected false for dict without Rect")
		}
	})

	t.Run("zero area rect", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Rect", generic.ArrayObject{
			generic.RealObject(0),
			generic.RealObject(0),
			generic.RealObject(0),
			generic.RealObject(0),
		})
		if IsAnnotVisible(dict) {
			t.Error("expected false for zero area rect")
		}
	})

	t.Run("valid rect", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Rect", generic.ArrayObject{
			generic.RealObject(0),
			generic.RealObject(0),
			generic.RealObject(100),
			generic.RealObject(50),
		})
		if !IsAnnotVisible(dict) {
			t.Error("expected true for valid rect")
		}
	})

	t.Run("negative coords still visible", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Rect", generic.ArrayObject{
			generic.RealObject(-100),
			generic.RealObject(-50),
			generic.RealObject(0),
			generic.RealObject(0),
		})
		if !IsAnnotVisible(dict) {
			t.Error("expected true for rect with negative coords")
		}
	})

	t.Run("invalid rect array", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Rect", generic.ArrayObject{
			generic.RealObject(0),
			generic.RealObject(0),
		}) // Only 2 elements
		if IsAnnotVisible(dict) {
			t.Error("expected false for invalid rect array")
		}
	})
}

func TestIsFieldVisible(t *testing.T) {
	t.Run("nil dict", func(t *testing.T) {
		if IsFieldVisible(nil) {
			t.Error("expected false for nil dict")
		}
	})

	t.Run("field without kids", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Rect", generic.ArrayObject{
			generic.RealObject(0),
			generic.RealObject(0),
			generic.RealObject(100),
			generic.RealObject(50),
		})
		if !IsFieldVisible(dict) {
			t.Error("expected true for visible field without kids")
		}
	})

	t.Run("invisible field without kids", func(t *testing.T) {
		dict := generic.NewDictionary()
		if IsFieldVisible(dict) {
			t.Error("expected false for invisible field without kids")
		}
	})

	t.Run("field with visible self", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Rect", generic.ArrayObject{
			generic.RealObject(0),
			generic.RealObject(0),
			generic.RealObject(100),
			generic.RealObject(50),
		})
		dict.Set("Kids", generic.ArrayObject{}) // Empty kids
		if !IsFieldVisible(dict) {
			t.Error("expected true for field with visible self")
		}
	})
}

func TestTwoVersions(t *testing.T) {
	tv := TwoVersions{
		Old: generic.IntegerObject(1),
		New: generic.IntegerObject(2),
	}

	if tv.Old == nil || tv.New == nil {
		t.Error("expected non-nil values")
	}
}

func TestQualifiedUpdate(t *testing.T) {
	ref := &generic.Reference{ObjectNumber: 1}
	update := &ReferenceUpdate{Reference: ref}

	qu := QualifiedUpdate{
		Level:  ModificationFormFilling,
		Update: update,
	}

	if qu.Level != ModificationFormFilling {
		t.Errorf("expected ModificationFormFilling, got %v", qu.Level)
	}
	if qu.Update.Reference.ObjectNumber != 1 {
		t.Errorf("expected object number 1, got %d", qu.Update.Reference.ObjectNumber)
	}
}

func TestQualifiedFormUpdate(t *testing.T) {
	qfu := QualifiedFormUpdate{
		Level: ModificationAnnotations,
		Update: &FormUpdate{
			FieldName: "TestField",
		},
	}

	if qfu.Level != ModificationAnnotations {
		t.Errorf("expected ModificationAnnotations, got %v", qfu.Level)
	}
	if qfu.Update.FieldName != "TestField" {
		t.Errorf("expected TestField, got %s", qfu.Update.FieldName)
	}
}
