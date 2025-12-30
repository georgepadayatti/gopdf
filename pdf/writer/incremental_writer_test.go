package writer

import (
	"bytes"
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
)

// createMinimalPDF creates a minimal valid PDF for testing.
func createMinimalPDF() []byte {
	var buf bytes.Buffer

	// Header
	buf.WriteString("%PDF-1.7\n")
	buf.Write([]byte{0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A}) // Binary comment

	// Object 1: Catalog
	catalogOffset := buf.Len()
	buf.WriteString("1 0 obj\n")
	buf.WriteString("<< /Type /Catalog /Pages 2 0 R >>\n")
	buf.WriteString("endobj\n")

	// Object 2: Pages
	pagesOffset := buf.Len()
	buf.WriteString("2 0 obj\n")
	buf.WriteString("<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n")
	buf.WriteString("endobj\n")

	// Object 3: Page
	pageOffset := buf.Len()
	buf.WriteString("3 0 obj\n")
	buf.WriteString("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n")
	buf.WriteString("endobj\n")

	// XRef table
	xrefOffset := buf.Len()
	buf.WriteString("xref\n")
	buf.WriteString("0 4\n")
	buf.WriteString("0000000000 65535 f \n")
	buf.WriteString(formatXRefEntry(catalogOffset))
	buf.WriteString(formatXRefEntry(pagesOffset))
	buf.WriteString(formatXRefEntry(pageOffset))

	// Trailer
	buf.WriteString("trailer\n")
	buf.WriteString("<< /Size 4 /Root 1 0 R >>\n")
	buf.WriteString("startxref\n")
	buf.WriteString(formatOffset(xrefOffset))
	buf.WriteString("\n%%EOF\n")

	return buf.Bytes()
}

func formatXRefEntry(offset int) string {
	return formatOffset(offset) + " 00000 n \n"
}

func formatOffset(offset int) string {
	s := "0000000000"
	o := []byte(s)
	offsetStr := []byte(string('0' + rune(offset/1000000000%10)))
	offsetStr = append(offsetStr, byte('0'+offset/100000000%10))
	offsetStr = append(offsetStr, byte('0'+offset/10000000%10))
	offsetStr = append(offsetStr, byte('0'+offset/1000000%10))
	offsetStr = append(offsetStr, byte('0'+offset/100000%10))
	offsetStr = append(offsetStr, byte('0'+offset/10000%10))
	offsetStr = append(offsetStr, byte('0'+offset/1000%10))
	offsetStr = append(offsetStr, byte('0'+offset/100%10))
	offsetStr = append(offsetStr, byte('0'+offset/10%10))
	offsetStr = append(offsetStr, byte('0'+offset%10))
	copy(o, offsetStr)
	return string(o)
}

func TestNewIncrementalPdfFileWriter(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)
	if w == nil {
		t.Fatal("Writer is nil")
	}

	if w.Reader != r {
		t.Error("Reader not set correctly")
	}

	if w.NextObjectNumber() <= 0 {
		t.Error("NextObjectNumber should be positive")
	}
}

func TestIncrementalWriter_AddObject(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	// Add a new object
	dict := generic.NewDictionary()
	dict.Set("Test", generic.NameObject("Value"))

	ref := w.AddObject(dict)
	if ref.ObjectNumber == 0 {
		t.Error("Object number should not be 0")
	}

	// Verify object can be retrieved
	obj, err := w.GetObject(ref.ObjectNumber)
	if err != nil {
		t.Errorf("Failed to get object: %v", err)
	}

	if obj == nil {
		t.Error("Object should not be nil")
	}
}

func TestIncrementalWriter_UpdateObject(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	// Update an existing object
	dict := generic.NewDictionary()
	dict.Set("Updated", generic.NameObject("True"))

	w.UpdateObject(1, dict) // Update object 1 (catalog)

	// Verify update
	obj, err := w.GetObject(1)
	if err != nil {
		t.Errorf("Failed to get object: %v", err)
	}

	if dictObj, ok := obj.(*generic.DictionaryObject); ok {
		if dictObj.GetName("Updated") != "True" {
			t.Error("Object not updated correctly")
		}
	} else {
		t.Error("Object should be a dictionary")
	}
}

func TestIncrementalWriter_HasChanges(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	if w.HasChanges() {
		t.Error("Should have no changes initially")
	}

	dict := generic.NewDictionary()
	w.AddObject(dict)

	if !w.HasChanges() {
		t.Error("Should have changes after adding object")
	}
}

func TestIncrementalWriter_Write_NoChanges(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	var buf bytes.Buffer
	err = w.Write(&buf)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	// With no changes, output should be same as input
	if !bytes.Equal(buf.Bytes(), pdfData) {
		t.Error("Output should equal input when no changes")
	}
}

func TestIncrementalWriter_Write_WithChanges(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	// Add a new object
	dict := generic.NewDictionary()
	dict.Set("NewKey", generic.NameObject("NewValue"))
	w.AddObject(dict)

	var buf bytes.Buffer
	err = w.Write(&buf)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	// Output should be larger than input
	if buf.Len() <= len(pdfData) {
		t.Error("Output should be larger than input with changes")
	}

	// Output should start with original PDF
	if !bytes.HasPrefix(buf.Bytes(), pdfData) {
		t.Error("Output should start with original PDF")
	}

	// Output should have xref
	if !bytes.Contains(buf.Bytes(), []byte("xref")) {
		t.Error("Output should contain xref")
	}

	// Output should have Prev pointer
	if !bytes.Contains(buf.Bytes(), []byte("/Prev")) {
		t.Error("Output should contain /Prev pointer")
	}
}

func TestPDFVersion_Compare(t *testing.T) {
	testCases := []struct {
		v1, v2   PDFVersion
		expected int
	}{
		{PDFVersion{1, 4}, PDFVersion{1, 4}, 0},
		{PDFVersion{1, 5}, PDFVersion{1, 4}, 1},
		{PDFVersion{1, 4}, PDFVersion{1, 5}, -1},
		{PDFVersion{2, 0}, PDFVersion{1, 7}, 1},
		{PDFVersion{1, 7}, PDFVersion{2, 0}, -1},
	}

	for _, tc := range testCases {
		result := tc.v1.Compare(tc.v2)
		if (result < 0 && tc.expected >= 0) || (result > 0 && tc.expected <= 0) || (result == 0 && tc.expected != 0) {
			t.Errorf("Compare(%v, %v) = %d, want %d", tc.v1, tc.v2, result, tc.expected)
		}
	}
}

func TestPDFVersion_String(t *testing.T) {
	v := PDFVersion{1, 7}
	if v.String() != "1.7" {
		t.Errorf("String() = %q, want %q", v.String(), "1.7")
	}
}

func TestParseVersion(t *testing.T) {
	testCases := []struct {
		input    string
		expected PDFVersion
	}{
		{"1.4", PDFVersion{1, 4}},
		{"1.7", PDFVersion{1, 7}},
		{"2.0", PDFVersion{2, 0}},
		{"", DefaultOutputVersion},
		{"invalid", DefaultOutputVersion},
	}

	for _, tc := range testCases {
		result := ParseVersion(tc.input)
		if result != tc.expected {
			t.Errorf("ParseVersion(%q) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

func TestObjectKey(t *testing.T) {
	k1 := ObjectKey{ObjectNumber: 1, Generation: 0}
	k2 := ObjectKey{ObjectNumber: 1, Generation: 0}
	k3 := ObjectKey{ObjectNumber: 2, Generation: 0}

	if k1 != k2 {
		t.Error("Equal keys should be equal")
	}

	if k1 == k3 {
		t.Error("Different keys should not be equal")
	}
}

func TestIncrementalWriter_DocumentID(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	id1, id2 := w.DocumentID()
	// Both IDs should be set (16 bytes each)
	if len(id1) != 16 {
		t.Errorf("ID1 length = %d, want 16", len(id1))
	}
	if len(id2) != 16 {
		t.Errorf("ID2 length = %d, want 16", len(id2))
	}
}

func TestIncrementalWriter_RootRef(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	ref := w.RootRef()
	if ref.ObjectNumber == 0 {
		t.Error("Root reference should be set")
	}
}

func TestChunkedCopy(t *testing.T) {
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	src := bytes.NewReader(data)
	var dst bytes.Buffer

	err := ChunkedCopy(src, &dst, 1024)
	if err != nil {
		t.Errorf("ChunkedCopy failed: %v", err)
	}

	if !bytes.Equal(dst.Bytes(), data) {
		t.Error("ChunkedCopy output doesn't match input")
	}
}

func TestIncrementalWriter_SetForceWrite(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)
	w.SetForceWrite(true)

	// With force write, output should include xref even with no changes
	var buf bytes.Buffer
	err = w.Write(&buf)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	// Check that we have more than just the original
	// (force write adds new trailer/xref)
	output := buf.Bytes()

	// Count occurrences of "xref"
	count := bytes.Count(output, []byte("xref"))
	if count < 2 {
		t.Error("Force write should add a second xref section")
	}
}

func TestIncrementalWriter_IsEncrypted(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	if w.IsEncrypted() {
		t.Error("Test PDF should not be encrypted")
	}
}

func TestIncrementalWriter_StreamXRefs(t *testing.T) {
	pdfData := createMinimalPDF()
	r, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	w := NewIncrementalPdfFileWriter(r)

	// Default should be false for table-based xref
	initial := w.StreamXRefs()

	w.SetStreamXRefs(true)
	if !w.StreamXRefs() {
		t.Error("StreamXRefs should be true after setting")
	}

	w.SetStreamXRefs(false)
	if w.StreamXRefs() {
		t.Error("StreamXRefs should be false after unsetting")
	}

	// Restore
	w.SetStreamXRefs(initial)
}
