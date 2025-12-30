package generic

import (
	"bytes"
	"testing"
)

func TestNullObject(t *testing.T) {
	null := NullObject{}
	var buf bytes.Buffer
	if err := null.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if buf.String() != "null" {
		t.Errorf("Expected 'null', got '%s'", buf.String())
	}

	cloned := null.Clone()
	if _, ok := cloned.(NullObject); !ok {
		t.Error("Clone should return NullObject")
	}
}

func TestBooleanObject(t *testing.T) {
	tests := []struct {
		value    BooleanObject
		expected string
	}{
		{BooleanObject(true), "true"},
		{BooleanObject(false), "false"},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		if err := tt.value.Write(&buf); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if buf.String() != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, buf.String())
		}
	}
}

func TestIntegerObject(t *testing.T) {
	tests := []struct {
		value    IntegerObject
		expected string
	}{
		{IntegerObject(0), "0"},
		{IntegerObject(42), "42"},
		{IntegerObject(-123), "-123"},
		{IntegerObject(9999999), "9999999"},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		if err := tt.value.Write(&buf); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if buf.String() != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, buf.String())
		}
	}
}

func TestRealObject(t *testing.T) {
	tests := []struct {
		value RealObject
	}{
		{RealObject(0.0)},
		{RealObject(3.14159)},
		{RealObject(-2.5)},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		if err := tt.value.Write(&buf); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if buf.Len() == 0 {
			t.Error("Expected non-empty output")
		}
	}
}

func TestNameObject(t *testing.T) {
	tests := []struct {
		value    NameObject
		expected string
	}{
		{NameObject("Type"), "/Type"},
		{NameObject("Page"), "/Page"},
		{NameObject("Font"), "/Font"},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		if err := tt.value.Write(&buf); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if buf.String() != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, buf.String())
		}
	}
}

func TestStringObject(t *testing.T) {
	// Literal string
	litStr := NewLiteralString("Hello World")
	var buf bytes.Buffer
	if err := litStr.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if buf.String() != "(Hello World)" {
		t.Errorf("Expected '(Hello World)', got '%s'", buf.String())
	}

	// Hex string
	hexStr := NewHexString([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	buf.Reset()
	if err := hexStr.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if buf.String() != "<deadbeef>" {
		t.Errorf("Expected '<deadbeef>', got '%s'", buf.String())
	}

	// Text string
	textStr := NewTextString("Test")
	if textStr.Text() != "Test" {
		t.Errorf("Expected 'Test', got '%s'", textStr.Text())
	}
}

func TestArrayObject(t *testing.T) {
	arr := NewArray(
		IntegerObject(1),
		IntegerObject(2),
		IntegerObject(3),
	)

	var buf bytes.Buffer
	if err := arr.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if buf.String() != "[1 2 3]" {
		t.Errorf("Expected '[1 2 3]', got '%s'", buf.String())
	}

	if len(arr) != 3 {
		t.Errorf("Expected length 3, got %d", len(arr))
	}

	if arr.Get(1).(IntegerObject) != 2 {
		t.Error("Get(1) should return 2")
	}

	if arr.Get(10) != nil {
		t.Error("Get(10) should return nil")
	}
}

func TestDictionaryObject(t *testing.T) {
	dict := NewDictionary()
	dict.Set("Type", NameObject("Page"))
	dict.Set("Count", IntegerObject(5))

	if !dict.Has("Type") {
		t.Error("Should have 'Type' key")
	}

	if dict.GetName("Type") != "Page" {
		t.Errorf("Expected 'Page', got '%s'", dict.GetName("Type"))
	}

	if count, ok := dict.GetInt("Count"); !ok || count != 5 {
		t.Errorf("Expected 5, got %d", count)
	}

	dict.Delete("Count")
	if dict.Has("Count") {
		t.Error("Should not have 'Count' after delete")
	}

	if dict.Len() != 1 {
		t.Errorf("Expected length 1, got %d", dict.Len())
	}
}

func TestStreamObject(t *testing.T) {
	dict := NewDictionary()
	dict.Set("Filter", NameObject("FlateDecode"))

	data := []byte("Hello, World!")
	stream := NewStream(dict, data)

	if !bytes.Equal(stream.GetDecodedData(), data) {
		t.Error("Decoded data mismatch")
	}

	var buf bytes.Buffer
	if err := stream.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("stream")) {
		t.Error("Output should contain 'stream'")
	}
}

func TestReference(t *testing.T) {
	ref := NewReference(10, 0)

	if ref.ObjectNumber != 10 {
		t.Errorf("Expected object number 10, got %d", ref.ObjectNumber)
	}

	if ref.GenerationNumber != 0 {
		t.Errorf("Expected generation 0, got %d", ref.GenerationNumber)
	}

	var buf bytes.Buffer
	if err := ref.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if buf.String() != "10 0 R" {
		t.Errorf("Expected '10 0 R', got '%s'", buf.String())
	}
}

func TestIndirectObject(t *testing.T) {
	obj := IntegerObject(42)
	indirect := NewIndirectObject(5, 0, obj)

	if indirect.ObjectNumber != 5 {
		t.Errorf("Expected object number 5, got %d", indirect.ObjectNumber)
	}

	var buf bytes.Buffer
	if err := indirect.Write(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("5 0 obj")) {
		t.Error("Output should contain '5 0 obj'")
	}
	if !bytes.Contains([]byte(output), []byte("endobj")) {
		t.Error("Output should contain 'endobj'")
	}
}

func TestRectangle(t *testing.T) {
	arr := ArrayObject{
		RealObject(0),
		RealObject(0),
		RealObject(612),
		RealObject(792),
	}

	rect, err := NewRectangle(arr)
	if err != nil {
		t.Fatalf("NewRectangle failed: %v", err)
	}

	if rect.Width() != 612 {
		t.Errorf("Expected width 612, got %f", rect.Width())
	}

	if rect.Height() != 792 {
		t.Errorf("Expected height 792, got %f", rect.Height())
	}

	arrOut := rect.ToArray()
	if len(arrOut) != 4 {
		t.Errorf("Expected array of 4 elements, got %d", len(arrOut))
	}
}

func TestClone(t *testing.T) {
	// Test dictionary clone
	dict := NewDictionary()
	dict.Set("Key", IntegerObject(42))

	cloned := dict.Clone().(*DictionaryObject)
	cloned.Set("Key", IntegerObject(100))

	if v, _ := dict.GetInt("Key"); v != 42 {
		t.Error("Original dict should not be modified")
	}

	// Test array clone
	arr := ArrayObject{IntegerObject(1), IntegerObject(2)}
	clonedArr := arr.Clone().(ArrayObject)
	clonedArr[0] = IntegerObject(100)

	if arr[0].(IntegerObject) != 1 {
		t.Error("Original array should not be modified")
	}
}

func TestTrailerDictionary(t *testing.T) {
	trailer := NewTrailer()
	trailer.Set("Size", IntegerObject(100))
	trailer.Set("Root", Reference{ObjectNumber: 1, GenerationNumber: 0})

	size := trailer.GetSize()
	if size != 100 {
		t.Errorf("Expected size 100, got %d", size)
	}

	root := trailer.GetRoot()
	if root == nil || root.ObjectNumber != 1 {
		t.Error("GetRoot failed")
	}
}

func TestComputeFileID(t *testing.T) {
	info := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	id := ComputeFileID(info)
	if len(id) != 16 { // MD5 produces 16 bytes
		t.Errorf("Expected 16 bytes, got %d", len(id))
	}

	// Same input should produce same output
	id2 := ComputeFileID(info)
	if !bytes.Equal(id, id2) {
		t.Error("Same input should produce same ID")
	}
}
