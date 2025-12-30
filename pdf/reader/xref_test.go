package reader

import (
	"bytes"
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestXRefType_String(t *testing.T) {
	testCases := []struct {
		xrefType XRefType
		expected string
	}{
		{XRefTypeFree, "free"},
		{XRefTypeStandard, "standard"},
		{XRefTypeInObjStream, "in_obj_stream"},
		{XRefType(99), "unknown"},
	}

	for _, tc := range testCases {
		if got := tc.xrefType.String(); got != tc.expected {
			t.Errorf("XRefType(%d).String() = %q, want %q", tc.xrefType, got, tc.expected)
		}
	}
}

func TestNewStandardXRefEntry(t *testing.T) {
	entry := NewStandardXRefEntry(1, 1000, 0)

	if entry.Type != XRefTypeStandard {
		t.Errorf("Type = %v, want %v", entry.Type, XRefTypeStandard)
	}
	if entry.ObjectNumber != 1 {
		t.Errorf("ObjectNumber = %d, want 1", entry.ObjectNumber)
	}
	if entry.Location != 1000 {
		t.Errorf("Location = %d, want 1000", entry.Location)
	}
	if entry.Generation != 0 {
		t.Errorf("Generation = %d, want 0", entry.Generation)
	}
}

func TestNewFreeXRefEntry(t *testing.T) {
	entry := NewFreeXRefEntry(0, 1, 65535)

	if entry.Type != XRefTypeFree {
		t.Errorf("Type = %v, want %v", entry.Type, XRefTypeFree)
	}
	if entry.ObjectNumber != 0 {
		t.Errorf("ObjectNumber = %d, want 0", entry.ObjectNumber)
	}
	if entry.Generation != 65535 {
		t.Errorf("Generation = %d, want 65535", entry.Generation)
	}
}

func TestNewObjStreamXRefEntry(t *testing.T) {
	entry := NewObjStreamXRefEntry(5, 10, 3)

	if entry.Type != XRefTypeInObjStream {
		t.Errorf("Type = %v, want %v", entry.Type, XRefTypeInObjStream)
	}
	if entry.ObjectNumber != 5 {
		t.Errorf("ObjectNumber = %d, want 5", entry.ObjectNumber)
	}
	if entry.ObjStream == nil {
		t.Fatal("ObjStream is nil")
	}
	if entry.ObjStream.ObjStreamID != 10 {
		t.Errorf("ObjStreamID = %d, want 10", entry.ObjStream.ObjStreamID)
	}
	if entry.ObjStream.IndexInStream != 3 {
		t.Errorf("IndexInStream = %d, want 3", entry.ObjStream.IndexInStream)
	}
	if entry.Generation != 0 {
		t.Errorf("Generation = %d, want 0 (objects in streams always have gen 0)", entry.Generation)
	}
}

func TestXRefCache(t *testing.T) {
	cache := NewXRefCache()

	t.Run("AddEntry", func(t *testing.T) {
		entry := NewStandardXRefEntry(1, 1000, 0)
		cache.AddEntry(entry)

		retrieved := cache.GetEntry(1)
		if retrieved == nil {
			t.Fatal("GetEntry returned nil")
		}
		if retrieved.Location != 1000 {
			t.Errorf("Location = %d, want 1000", retrieved.Location)
		}
	})

	t.Run("FirstEntryWins", func(t *testing.T) {
		// Add an entry
		entry1 := NewStandardXRefEntry(2, 2000, 0)
		cache.AddEntry(entry1)

		// Try to add another entry for the same object
		entry2 := NewStandardXRefEntry(2, 3000, 0)
		cache.AddEntry(entry2)

		// First entry should be preserved
		retrieved := cache.GetEntry(2)
		if retrieved.Location != 2000 {
			t.Errorf("Location = %d, want 2000 (first entry)", retrieved.Location)
		}
	})

	t.Run("GetNonExistent", func(t *testing.T) {
		retrieved := cache.GetEntry(999)
		if retrieved != nil {
			t.Error("Expected nil for non-existent entry")
		}
	})
}

func TestWriteXRefTable(t *testing.T) {
	entries := []*ExtendedXRefEntry{
		NewFreeXRefEntry(0, 0, 65535),
		NewStandardXRefEntry(1, 1000, 0),
		NewStandardXRefEntry(2, 2000, 0),
	}

	var buf bytes.Buffer
	err := WriteXRefTable(&buf, entries, 0)
	if err != nil {
		t.Fatalf("WriteXRefTable failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("xref")) {
		t.Error("Output should contain 'xref'")
	}
	if !bytes.Contains([]byte(output), []byte("0 3")) {
		t.Error("Output should contain subsection header '0 3'")
	}
}

func TestBytesNeeded(t *testing.T) {
	testCases := []struct {
		n        int
		expected int
	}{
		{0, 1},
		{1, 1},
		{255, 1},
		{256, 2},
		{65535, 2},
		{65536, 3},
	}

	for _, tc := range testCases {
		if got := bytesNeeded(tc.n); got != tc.expected {
			t.Errorf("bytesNeeded(%d) = %d, want %d", tc.n, got, tc.expected)
		}
	}
}

func TestReadXRefField(t *testing.T) {
	testCases := []struct {
		data     []byte
		offset   int
		width    int
		expected int
	}{
		{[]byte{0x00}, 0, 1, 0},
		{[]byte{0xFF}, 0, 1, 255},
		{[]byte{0x01, 0x00}, 0, 2, 256},
		{[]byte{0xFF, 0xFF}, 0, 2, 65535},
		{[]byte{0x00, 0x01, 0x00}, 0, 3, 256},
	}

	for _, tc := range testCases {
		if got := readXRefField(tc.data, tc.offset, tc.width); got != tc.expected {
			t.Errorf("readXRefField(%v, %d, %d) = %d, want %d", tc.data, tc.offset, tc.width, got, tc.expected)
		}
	}
}

func TestOBJSTREAM_FORBIDDEN(t *testing.T) {
	forbidden := []string{"XRef", "Encrypt", "Catalog", "Pages", "Outlines"}
	for _, name := range forbidden {
		if !OBJSTREAM_FORBIDDEN[name] {
			t.Errorf("%s should be forbidden in object streams", name)
		}
	}

	allowed := []string{"Font", "Image", "Metadata"}
	for _, name := range allowed {
		if OBJSTREAM_FORBIDDEN[name] {
			t.Errorf("%s should not be forbidden in object streams", name)
		}
	}
}

func TestCanBeInObjectStream(t *testing.T) {
	t.Run("RegularDict", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Type", generic.NameObject("Font"))
		if !CanBeInObjectStream(dict) {
			t.Error("Font dictionary should be allowed in object streams")
		}
	})

	t.Run("XRefDict", func(t *testing.T) {
		dict := generic.NewDictionary()
		dict.Set("Type", generic.NameObject("XRef"))
		if CanBeInObjectStream(dict) {
			t.Error("XRef dictionary should NOT be allowed in object streams")
		}
	})

	t.Run("Stream", func(t *testing.T) {
		stream := generic.NewStream(generic.NewDictionary(), []byte("test"))
		if CanBeInObjectStream(stream) {
			t.Error("Streams should NOT be allowed in object streams")
		}
	})

	t.Run("IntegerObject", func(t *testing.T) {
		obj := generic.IntegerObject(42)
		if !CanBeInObjectStream(obj) {
			t.Error("Integer objects should be allowed in object streams")
		}
	})
}

func TestXRefSection(t *testing.T) {
	section := &XRefSection{
		Type:        XRefSectionTypeTable,
		StartObject: 0,
		Entries: []*ExtendedXRefEntry{
			NewFreeXRefEntry(0, 0, 65535),
			NewStandardXRefEntry(1, 1000, 0),
		},
		PreviousXRef: 0,
	}

	if section.Type != XRefSectionTypeTable {
		t.Errorf("Type = %v, want %v", section.Type, XRefSectionTypeTable)
	}
	if len(section.Entries) != 2 {
		t.Errorf("Entries count = %d, want 2", len(section.Entries))
	}
}
