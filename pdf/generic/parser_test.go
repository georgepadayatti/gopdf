package generic

import (
	"bytes"
	"testing"
)

func TestParseNull(t *testing.T) {
	parser := NewParserFromBytes([]byte("null"))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	if _, ok := obj.(NullObject); !ok {
		t.Error("Expected NullObject")
	}
}

func TestParseBoolean(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"true", true},
		{"false", false},
	}

	for _, tt := range tests {
		parser := NewParserFromBytes([]byte(tt.input))
		obj, err := parser.ParseObject()
		if err != nil {
			t.Fatalf("ParseObject failed: %v", err)
		}

		b, ok := obj.(BooleanObject)
		if !ok {
			t.Error("Expected BooleanObject")
			continue
		}

		if bool(b) != tt.expected {
			t.Errorf("Expected %v, got %v", tt.expected, bool(b))
		}
	}
}

func TestParseInteger(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"0", 0},
		{"42", 42},
		{"-123", -123},
		{"+456", 456},
		{"999999", 999999},
	}

	for _, tt := range tests {
		parser := NewParserFromBytes([]byte(tt.input))
		obj, err := parser.ParseObject()
		if err != nil {
			t.Fatalf("ParseObject failed for '%s': %v", tt.input, err)
		}

		i, ok := obj.(IntegerObject)
		if !ok {
			t.Errorf("Expected IntegerObject for '%s'", tt.input)
			continue
		}

		if int64(i) != tt.expected {
			t.Errorf("Expected %d, got %d", tt.expected, int64(i))
		}
	}
}

func TestParseReal(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"3.14"},
		{"-2.5"},
		{"0.001"},
		{".5"},
	}

	for _, tt := range tests {
		parser := NewParserFromBytes([]byte(tt.input))
		obj, err := parser.ParseObject()
		if err != nil {
			t.Fatalf("ParseObject failed for '%s': %v", tt.input, err)
		}

		_, ok := obj.(RealObject)
		if !ok {
			t.Errorf("Expected RealObject for '%s'", tt.input)
		}
	}
}

func TestParseName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/Type", "Type"},
		{"/Page", "Page"},
		{"/Font", "Font"},
		{"/Name#20With#20Spaces", "Name With Spaces"},
	}

	for _, tt := range tests {
		parser := NewParserFromBytes([]byte(tt.input))
		obj, err := parser.ParseObject()
		if err != nil {
			t.Fatalf("ParseObject failed for '%s': %v", tt.input, err)
		}

		n, ok := obj.(NameObject)
		if !ok {
			t.Errorf("Expected NameObject for '%s'", tt.input)
			continue
		}

		if string(n) != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, string(n))
		}
	}
}

func TestParseLiteralString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"(Hello)", "Hello"},
		{"(Hello World)", "Hello World"},
		{"(Line1\\nLine2)", "Line1\nLine2"},
		{"(Escaped \\(parens\\))", "Escaped (parens)"},
		{"(Nested (string))", "Nested (string)"},
	}

	for _, tt := range tests {
		parser := NewParserFromBytes([]byte(tt.input))
		obj, err := parser.ParseObject()
		if err != nil {
			t.Fatalf("ParseObject failed for '%s': %v", tt.input, err)
		}

		s, ok := obj.(*StringObject)
		if !ok {
			t.Errorf("Expected StringObject for '%s'", tt.input)
			continue
		}

		if string(s.Value) != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, string(s.Value))
		}
	}
}

func TestParseHexString(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{"<48656C6C6F>", []byte("Hello")},
		{"<DEADBEEF>", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"<ABC>", []byte{0xAB, 0xC0}}, // Odd length gets 0 appended
	}

	for _, tt := range tests {
		parser := NewParserFromBytes([]byte(tt.input))
		obj, err := parser.ParseObject()
		if err != nil {
			t.Fatalf("ParseObject failed for '%s': %v", tt.input, err)
		}

		s, ok := obj.(*StringObject)
		if !ok {
			t.Errorf("Expected StringObject for '%s'", tt.input)
			continue
		}

		if !bytes.Equal(s.Value, tt.expected) {
			t.Errorf("Expected %v, got %v", tt.expected, s.Value)
		}
	}
}

func TestParseArray(t *testing.T) {
	input := "[1 2 3 /Name (String)]"
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	arr, ok := obj.(ArrayObject)
	if !ok {
		t.Fatal("Expected ArrayObject")
	}

	if len(arr) != 5 {
		t.Errorf("Expected 5 elements, got %d", len(arr))
	}

	// Check types
	if _, ok := arr[0].(IntegerObject); !ok {
		t.Error("Element 0 should be IntegerObject")
	}
	if _, ok := arr[3].(NameObject); !ok {
		t.Error("Element 3 should be NameObject")
	}
	if _, ok := arr[4].(*StringObject); !ok {
		t.Error("Element 4 should be StringObject")
	}
}

func TestParseDictionary(t *testing.T) {
	input := "<< /Type /Page /Count 5 /MediaBox [0 0 612 792] >>"
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	dict, ok := obj.(*DictionaryObject)
	if !ok {
		t.Fatal("Expected DictionaryObject")
	}

	if dict.GetName("Type") != "Page" {
		t.Errorf("Expected Type 'Page', got '%s'", dict.GetName("Type"))
	}

	if count, ok := dict.GetInt("Count"); !ok || count != 5 {
		t.Errorf("Expected Count 5, got %d", count)
	}

	mediaBox := dict.GetArray("MediaBox")
	if mediaBox == nil || len(mediaBox) != 4 {
		t.Error("Expected MediaBox array with 4 elements")
	}
}

func TestParseReference(t *testing.T) {
	input := "10 0 R"
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObjectOrReference()
	if err != nil {
		t.Fatalf("ParseObjectOrReference failed: %v", err)
	}

	ref, ok := obj.(Reference)
	if !ok {
		t.Fatal("Expected Reference")
	}

	if ref.ObjectNumber != 10 {
		t.Errorf("Expected object number 10, got %d", ref.ObjectNumber)
	}

	if ref.GenerationNumber != 0 {
		t.Errorf("Expected generation 0, got %d", ref.GenerationNumber)
	}
}

func TestParseIndirectObject(t *testing.T) {
	input := "5 0 obj\n42\nendobj"
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseIndirectObject()
	if err != nil {
		t.Fatalf("ParseIndirectObject failed: %v", err)
	}

	if obj.ObjectNumber != 5 {
		t.Errorf("Expected object number 5, got %d", obj.ObjectNumber)
	}

	if obj.GenerationNumber != 0 {
		t.Errorf("Expected generation 0, got %d", obj.GenerationNumber)
	}

	if i, ok := obj.Object.(IntegerObject); !ok || int64(i) != 42 {
		t.Error("Expected Integer 42")
	}
}

func TestParseStream(t *testing.T) {
	input := "1 0 obj\n<< /Length 5 >>\nstream\nHello\nendstream\nendobj"
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseIndirectObject()
	if err != nil {
		t.Fatalf("ParseIndirectObject failed: %v", err)
	}

	stream, ok := obj.Object.(*StreamObject)
	if !ok {
		t.Fatal("Expected StreamObject")
	}

	if string(stream.Data) != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", string(stream.Data))
	}
}

func TestParseWhitespaceAndComments(t *testing.T) {
	input := `
	% This is a comment
	42 % Another comment
	`
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	if i, ok := obj.(IntegerObject); !ok || int64(i) != 42 {
		t.Error("Expected Integer 42")
	}
}

func TestParseComplexDictionary(t *testing.T) {
	input := `<<
		/Type /Catalog
		/Pages 2 0 R
		/Names <<
			/Dests 3 0 R
		>>
		/Outlines 4 0 R
	>>`

	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	dict, ok := obj.(*DictionaryObject)
	if !ok {
		t.Fatal("Expected DictionaryObject")
	}

	if dict.GetName("Type") != "Catalog" {
		t.Error("Expected Type 'Catalog'")
	}

	pagesRef, ok := dict.Get("Pages").(Reference)
	if !ok || pagesRef.ObjectNumber != 2 {
		t.Error("Expected Pages reference to object 2")
	}

	names := dict.GetDict("Names")
	if names == nil {
		t.Error("Expected Names dictionary")
	}
}

func TestParseOctalEscape(t *testing.T) {
	input := "(\\101\\102\\103)" // ABC in octal
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	s, ok := obj.(*StringObject)
	if !ok {
		t.Fatal("Expected StringObject")
	}

	if string(s.Value) != "ABC" {
		t.Errorf("Expected 'ABC', got '%s'", string(s.Value))
	}
}

func TestParseNestedArrays(t *testing.T) {
	input := "[[1 2] [3 4] [5 6]]"
	parser := NewParserFromBytes([]byte(input))
	obj, err := parser.ParseObject()
	if err != nil {
		t.Fatalf("ParseObject failed: %v", err)
	}

	arr, ok := obj.(ArrayObject)
	if !ok {
		t.Fatal("Expected ArrayObject")
	}

	if len(arr) != 3 {
		t.Errorf("Expected 3 elements, got %d", len(arr))
	}

	innerArr, ok := arr[0].(ArrayObject)
	if !ok {
		t.Fatal("Expected inner ArrayObject")
	}

	if len(innerArr) != 2 {
		t.Errorf("Expected 2 elements in inner array, got %d", len(innerArr))
	}
}
