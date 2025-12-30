package reader

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestBasePdfHandler_TrailerView(t *testing.T) {
	t.Run("WithTrailer", func(t *testing.T) {
		trailer := generic.NewTrailer()
		trailer.Set("Size", generic.IntegerObject(10))
		handler := NewBasePdfHandler(trailer)

		view := handler.TrailerView()
		if view == nil {
			t.Fatal("TrailerView returned nil")
		}
	})

	t.Run("NilTrailer", func(t *testing.T) {
		handler := NewBasePdfHandler(nil)

		view := handler.TrailerView()
		if view != nil {
			t.Error("TrailerView should return nil for nil trailer")
		}
	})
}

func TestBasePdfHandler_RootRef(t *testing.T) {
	t.Run("WithRoot", func(t *testing.T) {
		trailer := generic.NewTrailer()
		rootRef := &generic.IndirectObject{
			ObjectNumber:     1,
			GenerationNumber: 0,
		}
		trailer.Set("Root", rootRef)
		handler := NewBasePdfHandler(trailer)

		ref := handler.RootRef()
		if ref.ObjectNumber != 1 {
			t.Errorf("ObjectNumber = %d, want 1", ref.ObjectNumber)
		}
		if ref.GenerationNumber != 0 {
			t.Errorf("GenerationNumber = %d, want 0", ref.GenerationNumber)
		}
	})

	t.Run("NilTrailer", func(t *testing.T) {
		handler := NewBasePdfHandler(nil)

		ref := handler.RootRef()
		if ref.ObjectNumber != 0 {
			t.Error("RootRef should return empty reference for nil trailer")
		}
	})

	t.Run("NoRoot", func(t *testing.T) {
		trailer := generic.NewTrailer()
		handler := NewBasePdfHandler(trailer)

		ref := handler.RootRef()
		if ref.ObjectNumber != 0 {
			t.Error("RootRef should return empty reference when Root is missing")
		}
	})
}

func TestBasePdfHandler_DocumentID(t *testing.T) {
	t.Run("WithID", func(t *testing.T) {
		trailer := generic.NewTrailer()
		idArray := generic.ArrayObject{
			&generic.StringObject{Value: []byte("id1")},
			&generic.StringObject{Value: []byte("id2")},
		}
		trailer.Set("ID", idArray)
		handler := NewBasePdfHandler(trailer)

		id1, id2 := handler.DocumentID()
		if string(id1) != "id1" {
			t.Errorf("ID1 = %q, want %q", id1, "id1")
		}
		if string(id2) != "id2" {
			t.Errorf("ID2 = %q, want %q", id2, "id2")
		}
	})

	t.Run("NilTrailer", func(t *testing.T) {
		handler := NewBasePdfHandler(nil)

		id1, id2 := handler.DocumentID()
		if id1 != nil || id2 != nil {
			t.Error("DocumentID should return nil for nil trailer")
		}
	})

	t.Run("NoID", func(t *testing.T) {
		trailer := generic.NewTrailer()
		handler := NewBasePdfHandler(trailer)

		id1, id2 := handler.DocumentID()
		if id1 != nil || id2 != nil {
			t.Error("DocumentID should return nil when ID is missing")
		}
	})
}

func TestPositionDict(t *testing.T) {
	pd := NewPositionDict()

	t.Run("SetAndGet", func(t *testing.T) {
		pd.Set(1, 1000)
		pd.Set(2, 2000)

		pos1, ok := pd.Get(1)
		if !ok || pos1 != 1000 {
			t.Errorf("Position for obj 1 = %d, want 1000", pos1)
		}

		pos2, ok := pd.Get(2)
		if !ok || pos2 != 2000 {
			t.Errorf("Position for obj 2 = %d, want 2000", pos2)
		}
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		_, ok := pd.Get(999)
		if ok {
			t.Error("Expected ok=false for non-existent object")
		}
	})

	t.Run("All", func(t *testing.T) {
		all := pd.All()
		if len(all) < 2 {
			t.Errorf("All should return at least 2 entries, got %d", len(all))
		}
	})
}

func TestObjectHeaderReadError(t *testing.T) {
	err := &ObjectHeaderReadError{
		Message:  "test error",
		Position: 100,
	}

	if err.Error() != "test error" {
		t.Errorf("Error() = %q, want %q", err.Error(), "test error")
	}
}

func TestReadObjectHeader(t *testing.T) {
	t.Run("ValidHeader", func(t *testing.T) {
		data := []byte("1 0 obj\n<< /Type /Catalog >>")
		objNum, genNum, pos, err := ReadObjectHeader(data, 0)
		if err != nil {
			t.Fatalf("ReadObjectHeader failed: %v", err)
		}
		if objNum != 1 {
			t.Errorf("ObjectNumber = %d, want 1", objNum)
		}
		if genNum != 0 {
			t.Errorf("GenerationNumber = %d, want 0", genNum)
		}
		if pos <= 0 {
			t.Errorf("Position should be > 0, got %d", pos)
		}
	})

	t.Run("InvalidHeader", func(t *testing.T) {
		data := []byte("not an object header\n")
		_, _, _, err := ReadObjectHeader(data, 0)
		if err == nil {
			t.Error("Expected error for invalid header")
		}
		if _, ok := err.(*ObjectHeaderReadError); !ok {
			t.Error("Expected ObjectHeaderReadError")
		}
	})

	t.Run("UnexpectedEOF", func(t *testing.T) {
		data := []byte("1 0 obj")
		_, _, _, err := ReadObjectHeader(data, 0)
		if err == nil {
			t.Error("Expected error for unexpected EOF")
		}
	})
}

func TestPageTreeWalker(t *testing.T) {
	// Create a minimal mock handler
	t.Run("NilRoot", func(t *testing.T) {
		handler := &mockPdfHandler{root: nil}
		walker := NewPageTreeWalker(handler)

		_, err := walker.GetPage(0)
		if err != ErrObjectNotFound {
			t.Errorf("Expected ErrObjectNotFound, got %v", err)
		}
	})
}

// mockPdfHandler is a minimal implementation for testing
type mockPdfHandler struct {
	root    *generic.DictionaryObject
	objects map[int]generic.PdfObject
}

func (m *mockPdfHandler) GetObject(ref generic.Reference) (generic.PdfObject, error) {
	if obj, ok := m.objects[ref.ObjectNumber]; ok {
		return obj, nil
	}
	return nil, ErrObjectNotFound
}

func (m *mockPdfHandler) TrailerView() *generic.DictionaryObject {
	return nil
}

func (m *mockPdfHandler) RootRef() generic.Reference {
	return generic.Reference{}
}

func (m *mockPdfHandler) Root() *generic.DictionaryObject {
	return m.root
}

func (m *mockPdfHandler) DocumentID() ([]byte, []byte) {
	return nil, nil
}
