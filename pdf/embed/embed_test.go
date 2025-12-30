package embed

import (
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestDefaultEmbeddedFileParams(t *testing.T) {
	params := DefaultEmbeddedFileParams()

	if !params.EmbedSize {
		t.Error("EmbedSize should be true by default")
	}

	if !params.EmbedChecksum {
		t.Error("EmbedChecksum should be true by default")
	}

	if params.CreationDate != nil {
		t.Error("CreationDate should be nil by default")
	}

	if params.ModificationDate != nil {
		t.Error("ModificationDate should be nil by default")
	}
}

func TestNewEmbeddedFileFromData(t *testing.T) {
	data := []byte("Hello, World!")

	ef := NewEmbeddedFileFromData(data, false, nil, MimeTypeText)

	if ef == nil {
		t.Fatal("NewEmbeddedFileFromData returned nil")
	}

	if ef.Dictionary.GetName("Type") != "EmbeddedFile" {
		t.Error("Expected Type to be EmbeddedFile")
	}

	if ef.Dictionary.GetName("Subtype") != MimeTypeText {
		t.Errorf("Expected Subtype to be %s", MimeTypeText)
	}

	if len(ef.Data) != len(data) {
		t.Errorf("Expected data length %d, got %d", len(data), len(ef.Data))
	}
}

func TestNewEmbeddedFileFromDataWithCompression(t *testing.T) {
	data := []byte("Hello, World! This is some test data that should be compressed.")

	ef := NewEmbeddedFileFromData(data, true, nil, "")

	if ef == nil {
		t.Fatal("NewEmbeddedFileFromData returned nil")
	}

	// Check that compression was applied
	if ef.Dictionary.GetName("Filter") != "FlateDecode" {
		t.Error("Expected Filter to be FlateDecode when compression is enabled")
	}
}

func TestEmbeddedFileApplyParams(t *testing.T) {
	data := []byte("Test data for params")
	now := time.Now()

	params := &EmbeddedFileParams{
		EmbedSize:        true,
		EmbedChecksum:    true,
		CreationDate:     &now,
		ModificationDate: &now,
	}

	ef := NewEmbeddedFileFromData(data, false, params, "")
	ef.ApplyParams()

	paramsDict := ef.Dictionary.GetDict("Params")
	if paramsDict == nil {
		t.Fatal("Expected Params dictionary to be set")
	}

	// Check size
	if size, ok := paramsDict.GetInt("Size"); !ok || size != int64(len(data)) {
		t.Errorf("Expected Size to be %d", len(data))
	}

	// Check checksum
	if !paramsDict.Has("CheckSum") {
		t.Error("Expected CheckSum to be set")
	}

	// Check dates
	if !paramsDict.Has("CreationDate") {
		t.Error("Expected CreationDate to be set")
	}

	if !paramsDict.Has("ModDate") {
		t.Error("Expected ModDate to be set")
	}
}

func TestNewFileSpec(t *testing.T) {
	data := []byte("File content")
	ef := NewEmbeddedFileFromData(data, false, nil, MimeTypePDF)

	spec := NewFileSpec("document.pdf", ef)

	if spec.FileSpecString != "document.pdf" {
		t.Errorf("Expected FileSpecString to be 'document.pdf', got '%s'", spec.FileSpecString)
	}

	if spec.EmbeddedData != ef {
		t.Error("Expected EmbeddedData to match")
	}
}

func TestFileSpecAsPdfObject(t *testing.T) {
	data := []byte("File content")
	ef := NewEmbeddedFileFromData(data, false, nil, MimeTypePDF)

	spec := &FileSpec{
		FileSpecString:   "document.pdf",
		FileName:         "Document.pdf",
		EmbeddedData:     ef,
		Description:      "Test document",
		AFRelationship:   AFRelationshipSource,
	}

	ref := generic.Reference{ObjectNumber: 10, GenerationNumber: 0}
	obj := spec.AsPdfObject(ref)

	if obj.GetName("Type") != "Filespec" {
		t.Error("Expected Type to be Filespec")
	}

	if !obj.Has("F") {
		t.Error("Expected F key to be set")
	}

	if !obj.Has("UF") {
		t.Error("Expected UF key to be set when FileName is provided")
	}

	if !obj.Has("EF") {
		t.Error("Expected EF key to be set when EmbeddedData is provided")
	}

	if !obj.Has("Desc") {
		t.Error("Expected Desc key to be set")
	}

	if obj.GetName("AFRelationship") != AFRelationshipSource {
		t.Error("Expected AFRelationship to be set correctly")
	}
}

func TestEmbeddedFileWriter(t *testing.T) {
	w := NewEmbeddedFileWriter(1)

	if w.nextObjNum != 1 {
		t.Errorf("Expected nextObjNum to be 1, got %d", w.nextObjNum)
	}

	// Add an object
	dict := generic.NewDictionary()
	dict.Set("Test", generic.NameObject("Value"))

	ref := w.AddObject(dict)

	if ref.ObjectNumber != 1 {
		t.Errorf("Expected object number 1, got %d", ref.ObjectNumber)
	}

	if w.nextObjNum != 2 {
		t.Errorf("Expected nextObjNum to be 2, got %d", w.nextObjNum)
	}

	if len(w.GetObjects()) != 1 {
		t.Errorf("Expected 1 object, got %d", len(w.GetObjects()))
	}
}

func TestEmbeddedFileWriterEmbedFile(t *testing.T) {
	w := NewEmbeddedFileWriter(1)

	data := []byte("Embedded file content")
	ef := NewEmbeddedFileFromData(data, false, nil, MimeTypePDF)

	spec := &FileSpec{
		FileSpecString: "embedded.pdf",
		EmbeddedData:   ef,
	}

	specObj, specRef, efRef, err := w.EmbedFile(spec)

	if err != nil {
		t.Fatalf("EmbedFile returned error: %v", err)
	}

	if specObj == nil {
		t.Error("Expected specObj to not be nil")
	}

	if specRef.ObjectNumber == 0 {
		t.Error("Expected valid specRef")
	}

	if efRef.ObjectNumber == 0 {
		t.Error("Expected valid efRef")
	}

	// Should have 2 objects: the stream and the file spec
	if len(w.GetObjects()) != 2 {
		t.Errorf("Expected 2 objects, got %d", len(w.GetObjects()))
	}
}

func TestEmbeddedFileWriterEmbedFileNoData(t *testing.T) {
	w := NewEmbeddedFileWriter(1)

	spec := &FileSpec{
		FileSpecString: "embedded.pdf",
		EmbeddedData:   nil,
	}

	_, _, _, err := w.EmbedFile(spec)

	if err != ErrNoEmbeddedFile {
		t.Errorf("Expected ErrNoEmbeddedFile, got %v", err)
	}
}

func TestCreateNamesDict(t *testing.T) {
	ref := generic.Reference{ObjectNumber: 5, GenerationNumber: 0}

	names := CreateNamesDict(nil, "test.pdf", ref)

	if names == nil {
		t.Fatal("Expected names dict to not be nil")
	}

	efTree := names.GetDict("EmbeddedFiles")
	if efTree == nil {
		t.Fatal("Expected EmbeddedFiles to be set")
	}

	namesArr := efTree.GetArray("Names")
	if namesArr == nil {
		t.Fatal("Expected Names array to be set")
	}

	if len(namesArr) != 2 {
		t.Errorf("Expected 2 elements in Names array, got %d", len(namesArr))
	}
}

func TestCreateNamesDictExisting(t *testing.T) {
	// Create existing names dict with an entry
	existing := generic.NewDictionary()
	efTree := generic.NewDictionary()
	existingArr := generic.ArrayObject{
		generic.NewTextString("existing.pdf"),
		generic.Reference{ObjectNumber: 1, GenerationNumber: 0},
	}
	efTree.Set("Names", existingArr)
	existing.Set("EmbeddedFiles", efTree)

	ref := generic.Reference{ObjectNumber: 5, GenerationNumber: 0}
	names := CreateNamesDict(existing, "new.pdf", ref)

	efTreeResult := names.GetDict("EmbeddedFiles")
	namesArr := efTreeResult.GetArray("Names")

	// Should have 4 elements now (2 original + 2 new)
	if len(namesArr) != 4 {
		t.Errorf("Expected 4 elements in Names array, got %d", len(namesArr))
	}
}

func TestFormatPdfDate(t *testing.T) {
	// Use a fixed time for testing
	loc, _ := time.LoadLocation("UTC")
	testTime := time.Date(2024, 1, 15, 10, 30, 45, 0, loc)

	result := formatPdfDate(testTime)

	// Should start with D:
	if result[:2] != "D:" {
		t.Errorf("Expected date to start with 'D:', got '%s'", result[:2])
	}

	// Should contain the date/time components
	if len(result) < 20 {
		t.Errorf("Date string too short: %s", result)
	}
}

func TestMimeTypeConstants(t *testing.T) {
	// Verify MIME type constants are valid
	mimeTypes := []string{
		MimeTypePDF,
		MimeTypeXML,
		MimeTypeText,
		MimeTypeHTML,
		MimeTypeJPEG,
		MimeTypePNG,
		MimeTypeZIP,
		MimeTypeJSON,
		MimeTypeBinary,
	}

	for _, mt := range mimeTypes {
		if mt == "" {
			t.Error("MIME type should not be empty")
		}
	}
}

func TestAFRelationshipConstants(t *testing.T) {
	// Verify AF relationship constants are valid
	relationships := []string{
		AFRelationshipSource,
		AFRelationshipData,
		AFRelationshipAlternative,
		AFRelationshipSupplement,
		AFRelationshipEncryptedPayload,
		AFRelationshipFormData,
		AFRelationshipSchema,
		AFRelationshipUnspecified,
	}

	for _, r := range relationships {
		if r == "" {
			t.Error("AF relationship should not be empty")
		}
	}
}

func TestRelatedFileSpec(t *testing.T) {
	data := []byte("Related file content")
	ef := NewEmbeddedFileFromData(data, false, nil, MimeTypeText)

	rfs := RelatedFileSpec{
		Name:         "related.txt",
		EmbeddedData: ef,
	}

	if rfs.Name != "related.txt" {
		t.Errorf("Expected name 'related.txt', got '%s'", rfs.Name)
	}

	if rfs.EmbeddedData != ef {
		t.Error("Expected EmbeddedData to match")
	}
}

func TestFileSpecWithRelatedFiles(t *testing.T) {
	data := []byte("Main file")
	ef := NewEmbeddedFileFromData(data, false, nil, MimeTypePDF)

	relatedData := []byte("Related file")
	relatedEf := NewEmbeddedFileFromData(relatedData, false, nil, MimeTypeText)

	spec := &FileSpec{
		FileSpecString: "main.pdf",
		FileName:       "Main.pdf",
		EmbeddedData:   ef,
		FRelatedFiles: []RelatedFileSpec{
			{Name: "related.txt", EmbeddedData: relatedEf},
		},
		UFRelatedFiles: []RelatedFileSpec{
			{Name: "unicode_related.txt", EmbeddedData: relatedEf},
		},
	}

	ref := generic.Reference{ObjectNumber: 10, GenerationNumber: 0}
	obj := spec.AsPdfObject(ref)

	if !obj.Has("RF") {
		t.Error("Expected RF key to be set when related files are provided")
	}
}
