package metadata

import (
	"strings"
	"testing"
	"time"
)

func TestExpandedNameString(t *testing.T) {
	tests := []struct {
		name     ExpandedName
		expected string
	}{
		{ExpandedName{NS: "http://example.com/", LocalName: "test"}, "http://example.com/test"},
		{ExpandedName{NS: "http://example.com#", LocalName: "test"}, "http://example.com#test"},
		{ExpandedName{NS: "http://example.com", LocalName: "test"}, "http://example.com/test"},
	}

	for _, tt := range tests {
		result := tt.name.String()
		if result != tt.expected {
			t.Errorf("ExpandedName.String() = %s, want %s", result, tt.expected)
		}
	}
}

func TestExpandedNameTag(t *testing.T) {
	name := ExpandedName{NS: "http://example.com/", LocalName: "test"}
	expected := "{http://example.com/}test"

	if name.Tag() != expected {
		t.Errorf("ExpandedName.Tag() = %s, want %s", name.Tag(), expected)
	}
}

func TestXmpArrayTypeString(t *testing.T) {
	tests := []struct {
		arrayType XmpArrayType
		expected  string
	}{
		{XmpArrayOrdered, "Seq"},
		{XmpArrayUnordered, "Bag"},
		{XmpArrayAlternative, "Alt"},
	}

	for _, tt := range tests {
		result := tt.arrayType.String()
		if result != tt.expected {
			t.Errorf("XmpArrayType.String() = %s, want %s", result, tt.expected)
		}
	}
}

func TestXmpArrayTypeAsRDF(t *testing.T) {
	arrayType := XmpArrayOrdered
	rdf := arrayType.AsRDF()

	if rdf.NS != NSRDF {
		t.Error("Expected RDF namespace")
	}
	if rdf.LocalName != "Seq" {
		t.Errorf("Expected Seq, got %s", rdf.LocalName)
	}
}

func TestNewXmpValue(t *testing.T) {
	value := NewXmpValue("test")
	if value.Value != "test" {
		t.Errorf("Expected 'test', got '%v'", value.Value)
	}
}

func TestNewXmpValueWithLang(t *testing.T) {
	value := NewXmpValueWithLang("test", "en")
	if value.Value != "test" {
		t.Errorf("Expected 'test', got '%v'", value.Value)
	}
	if value.Language != "en" {
		t.Errorf("Expected 'en', got '%s'", value.Language)
	}
}

func TestXmpStructure(t *testing.T) {
	structure := NewXmpStructure()
	value := NewXmpValue("test value")

	structure.Set(DCTitle, value)

	retrieved := structure.Get(DCTitle)
	if retrieved == nil {
		t.Fatal("Expected to retrieve value")
	}
	if retrieved.Value != "test value" {
		t.Errorf("Expected 'test value', got '%v'", retrieved.Value)
	}
}

func TestNewXmpOrderedArray(t *testing.T) {
	arr := NewXmpOrderedArray(NewXmpValue("a"), NewXmpValue("b"))
	if arr.ArrayType != XmpArrayOrdered {
		t.Error("Expected ordered array")
	}
	if len(arr.Entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(arr.Entries))
	}
}

func TestNewXmpUnorderedArray(t *testing.T) {
	arr := NewXmpUnorderedArray(NewXmpValue("a"))
	if arr.ArrayType != XmpArrayUnordered {
		t.Error("Expected unordered array")
	}
}

func TestNewXmpAlternativeArray(t *testing.T) {
	arr := NewXmpAlternativeArray(NewXmpValue("a"))
	if arr.ArrayType != XmpArrayAlternative {
		t.Error("Expected alternative array")
	}
}

func TestNewDocumentMetadata(t *testing.T) {
	meta := NewDocumentMetadata()

	if meta.Producer != Vendor {
		t.Errorf("Expected producer '%s', got '%s'", Vendor, meta.Producer)
	}
	if meta.LastModified == nil {
		t.Error("Expected LastModified to be set")
	}
}

func TestDocumentMetadataViewOver(t *testing.T) {
	base := &DocumentMetadata{
		Title:   "Base Title",
		Author:  "Base Author",
		Creator: "Base Creator",
	}

	overlay := &DocumentMetadata{
		Title: "Overlay Title",
	}

	view := overlay.ViewOver(base)

	if view.Title != "Overlay Title" {
		t.Errorf("Expected overlay title, got '%s'", view.Title)
	}
	if view.Author != "Base Author" {
		t.Errorf("Expected base author, got '%s'", view.Author)
	}
	if view.Creator != "Base Creator" {
		t.Errorf("Expected base creator, got '%s'", view.Creator)
	}
}

func TestDocumentMetadataToXMP(t *testing.T) {
	now := time.Now()
	meta := &DocumentMetadata{
		Title:        "Test Document",
		Author:       "Test Author",
		Subject:      "Test Subject",
		Keywords:     []string{"test", "document"},
		Creator:      "Test Creator",
		Producer:     Vendor,
		Created:      &now,
		LastModified: &now,
	}

	roots := DocumentMetadataToXMP(meta)

	if len(roots) != 1 {
		t.Errorf("Expected 1 root, got %d", len(roots))
	}

	root := roots[0]
	if root.Get(PDFProducer) == nil {
		t.Error("Expected PDFProducer to be set")
	}
}

func TestSerializeXMP(t *testing.T) {
	meta := &DocumentMetadata{
		Title:    "Test Document",
		Author:   "Test Author",
		Producer: Vendor,
	}

	roots := DocumentMetadataToXMP(meta)
	data, err := SerializeXMP(roots)
	if err != nil {
		t.Fatalf("SerializeXMP failed: %v", err)
	}

	xmpStr := string(data)

	// Check for XMP packet markers
	if !strings.Contains(xmpStr, "<?xpacket begin=") {
		t.Error("Missing XMP packet begin marker")
	}
	if !strings.Contains(xmpStr, "<?xpacket end=") {
		t.Error("Missing XMP packet end marker")
	}
	if !strings.Contains(xmpStr, "x:xmpmeta") {
		t.Error("Missing xmpmeta element")
	}
	if !strings.Contains(xmpStr, "rdf:RDF") {
		t.Error("Missing RDF element")
	}
}

func TestDocumentMetadataToInfoDict(t *testing.T) {
	now := time.Now()
	meta := &DocumentMetadata{
		Title:        "Test Document",
		Author:       "Test Author",
		Subject:      "Test Subject",
		Keywords:     []string{"test", "document"},
		Creator:      "Test Creator",
		Producer:     "Test Producer",
		Created:      &now,
		LastModified: &now,
	}

	entries := DocumentMetadataToInfoDict(meta)

	// Check that all expected entries are present
	entryMap := make(map[string]string)
	for _, entry := range entries {
		entryMap[entry.Key] = entry.Value
	}

	if entryMap["Title"] != "Test Document" {
		t.Error("Title not set correctly")
	}
	if entryMap["Author"] != "Test Author" {
		t.Error("Author not set correctly")
	}
	if entryMap["Subject"] != "Test Subject" {
		t.Error("Subject not set correctly")
	}
	if entryMap["Keywords"] != "test, document" {
		t.Error("Keywords not set correctly")
	}
	if entryMap["Creator"] != "Test Creator" {
		t.Error("Creator not set correctly")
	}
	if entryMap["Producer"] != "Test Producer" {
		t.Error("Producer not set correctly")
	}
	if !strings.HasPrefix(entryMap["CreationDate"], "D:") {
		t.Error("CreationDate not formatted correctly")
	}
	if !strings.HasPrefix(entryMap["ModDate"], "D:") {
		t.Error("ModDate not formatted correctly")
	}
}

func TestFormatPDFDate(t *testing.T) {
	// Test a specific time
	loc := time.FixedZone("Test", 3600) // +01:00
	testTime := time.Date(2024, 1, 15, 10, 30, 45, 0, loc)

	result := formatPDFDate(testTime)

	if !strings.HasPrefix(result, "D:20240115103045") {
		t.Errorf("Unexpected date format: %s", result)
	}
}

func TestParsePDFDate(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"D:20240115103045+01'00'", false},
		{"D:20240115103045", false},
		{"D:20240115", false},
		{"invalid", true},
		{"20240115", true}, // Missing D: prefix
	}

	for _, tt := range tests {
		result, err := ParsePDFDate(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePDFDate(%s) expected error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParsePDFDate(%s) unexpected error: %v", tt.input, err)
			}
			if result == nil {
				t.Errorf("ParsePDFDate(%s) returned nil", tt.input)
			}
		}
	}
}

func TestGetPrefix(t *testing.T) {
	tests := []struct {
		ns       string
		expected string
	}{
		{NSRDF, "rdf"},
		{NSDC, "dc"},
		{NSPDF, "pdf"},
		{NSXMP, "xmp"},
		{NSPDFAId, "pdfaid"},
		{NSXML, "xml"},
		{"http://unknown.ns/", "ns"},
	}

	for _, tt := range tests {
		result := getPrefix(tt.ns)
		if result != tt.expected {
			t.Errorf("getPrefix(%s) = %s, want %s", tt.ns, result, tt.expected)
		}
	}
}

func TestCommonExpandedNames(t *testing.T) {
	// Verify that common expanded names are properly defined
	tests := []struct {
		name     ExpandedName
		expNS    string
		expLocal string
	}{
		{DCTitle, NSDC, "title"},
		{DCCreator, NSDC, "creator"},
		{DCDescription, NSDC, "description"},
		{PDFKeywords, NSPDF, "keywords"},
		{PDFProducer, NSPDF, "Producer"},
		{XMPCreatorTool, NSXMP, "CreatorTool"},
		{XMPCreateDate, NSXMP, "CreateDate"},
		{XMPModifyDate, NSXMP, "ModifyDate"},
	}

	for _, tt := range tests {
		if tt.name.NS != tt.expNS {
			t.Errorf("Expected NS %s, got %s", tt.expNS, tt.name.NS)
		}
		if tt.name.LocalName != tt.expLocal {
			t.Errorf("Expected LocalName %s, got %s", tt.expLocal, tt.name.LocalName)
		}
	}
}

func TestSerializeXMPWithArray(t *testing.T) {
	structure := NewXmpStructure()

	// Create an alternative array for title (common for localized strings)
	titleArray := NewXmpAlternativeArray(
		NewXmpValueWithLang("English Title", "en"),
		NewXmpValueWithLang("Titre Français", "fr"),
	)
	structure.Set(DCTitle, &XmpValue{Value: titleArray})

	data, err := SerializeXMP([]*XmpStructure{structure})
	if err != nil {
		t.Fatalf("SerializeXMP failed: %v", err)
	}

	xmpStr := string(data)
	if !strings.Contains(xmpStr, "rdf:Alt") {
		t.Error("Expected rdf:Alt for alternative array")
	}
	if !strings.Contains(xmpStr, "xml:lang") {
		t.Error("Expected xml:lang attribute")
	}
}

func TestStringWithLanguage(t *testing.T) {
	swl := StringWithLanguage{
		Value:    "Hello",
		Language: "en",
	}

	if swl.Value != "Hello" {
		t.Errorf("Expected 'Hello', got '%s'", swl.Value)
	}
	if swl.Language != "en" {
		t.Errorf("Expected 'en', got '%s'", swl.Language)
	}
}

func TestDocumentMetadataToXMPWithKeywords(t *testing.T) {
	meta := &DocumentMetadata{
		Keywords: []string{"keyword1", "keyword2", "keyword3"},
	}

	roots := DocumentMetadataToXMP(meta)
	if len(roots) != 1 {
		t.Fatal("Expected 1 root")
	}

	keywordsValue := roots[0].Get(PDFKeywords)
	if keywordsValue == nil {
		t.Fatal("Expected keywords value")
	}

	str, ok := keywordsValue.Value.(string)
	if !ok {
		t.Fatal("Expected string value for keywords")
	}

	if str != "keyword1, keyword2, keyword3" {
		t.Errorf("Unexpected keywords: %s", str)
	}
}

func TestXmpURIType(t *testing.T) {
	uri := XmpURI("http://example.com/resource")

	if string(uri) != "http://example.com/resource" {
		t.Error("XmpURI not stored correctly")
	}
}
