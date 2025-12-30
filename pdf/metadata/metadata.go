// Package metadata provides PDF document metadata and XMP handling.
package metadata

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Version identifier
const Vendor = "gopdf 0.1.0"

// XML namespace URIs
const (
	NSXML     = "http://www.w3.org/XML/1998/namespace"
	NSRDF     = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	NSXMP     = "http://ns.adobe.com/xap/1.0/"
	NSDC      = "http://purl.org/dc/elements/1.1/"
	NSPDF     = "http://ns.adobe.com/pdf/1.3/"
	NSPDFAId  = "http://www.aiim.org/pdfa/ns/id/"
	NSPDFUAId = "http://www.aiim.org/pdfua/ns/id/"
	NSX       = "adobe:ns:meta/"
)

// ExpandedName represents an expanded XML name with namespace.
type ExpandedName struct {
	NS        string
	LocalName string
}

// String returns the string representation of the expanded name.
func (e ExpandedName) String() string {
	sep := ""
	if !strings.HasSuffix(e.NS, "/") && !strings.HasSuffix(e.NS, "#") {
		sep = "/"
	}
	return fmt.Sprintf("%s%s%s", e.NS, sep, e.LocalName)
}

// Tag returns the Clark notation tag for XML serialization.
func (e ExpandedName) Tag() string {
	return fmt.Sprintf("{%s}%s", e.NS, e.LocalName)
}

// Common expanded names
var (
	XMLLang        = ExpandedName{NS: NSXML, LocalName: "lang"}
	RDFRDF         = ExpandedName{NS: NSRDF, LocalName: "RDF"}
	RDFSeq         = ExpandedName{NS: NSRDF, LocalName: "Seq"}
	RDFBag         = ExpandedName{NS: NSRDF, LocalName: "Bag"}
	RDFAlt         = ExpandedName{NS: NSRDF, LocalName: "Alt"}
	RDFLi          = ExpandedName{NS: NSRDF, LocalName: "li"}
	RDFValue       = ExpandedName{NS: NSRDF, LocalName: "value"}
	RDFResource    = ExpandedName{NS: NSRDF, LocalName: "resource"}
	RDFAbout       = ExpandedName{NS: NSRDF, LocalName: "about"}
	RDFParseType   = ExpandedName{NS: NSRDF, LocalName: "parseType"}
	RDFDescription = ExpandedName{NS: NSRDF, LocalName: "Description"}
	XXmpmeta       = ExpandedName{NS: NSX, LocalName: "xmpmeta"}
	XXmptk         = ExpandedName{NS: NSX, LocalName: "xmptk"}
	DCTitle        = ExpandedName{NS: NSDC, LocalName: "title"}
	DCCreator      = ExpandedName{NS: NSDC, LocalName: "creator"}
	DCDescription  = ExpandedName{NS: NSDC, LocalName: "description"}
	PDFKeywords    = ExpandedName{NS: NSPDF, LocalName: "keywords"}
	PDFProducer    = ExpandedName{NS: NSPDF, LocalName: "Producer"}
	XMPCreatorTool = ExpandedName{NS: NSXMP, LocalName: "CreatorTool"}
	XMPCreateDate  = ExpandedName{NS: NSXMP, LocalName: "CreateDate"}
	XMPModifyDate  = ExpandedName{NS: NSXMP, LocalName: "ModifyDate"}
)

// StringWithLanguage represents a string with an optional language code.
type StringWithLanguage struct {
	Value    string
	Language string
}

// DocumentMetadata represents simple document metadata.
type DocumentMetadata struct {
	// Title is the document's title.
	Title string

	// TitleLang is the language code for the title.
	TitleLang string

	// Author is the document's author.
	Author string

	// AuthorLang is the language code for the author.
	AuthorLang string

	// Subject is the document's subject.
	Subject string

	// SubjectLang is the language code for the subject.
	SubjectLang string

	// Keywords are keywords associated with the document.
	Keywords []string

	// Creator is the software that authored the document.
	Creator string

	// Producer is the software that produced the PDF.
	Producer string

	// Created is when the document was created.
	Created *time.Time

	// LastModified is when the document was last modified.
	LastModified *time.Time

	// XmpExtra contains additional XMP metadata structures.
	XmpExtra []XmpStructure

	// XmpUnmanaged flags metadata as XMP-only.
	XmpUnmanaged bool
}

// NewDocumentMetadata creates a new DocumentMetadata with default values.
func NewDocumentMetadata() *DocumentMetadata {
	now := time.Now()
	return &DocumentMetadata{
		Producer:     Vendor,
		LastModified: &now,
	}
}

// ViewOver creates a view of this metadata over base metadata.
func (m *DocumentMetadata) ViewOver(base *DocumentMetadata) *DocumentMetadata {
	result := &DocumentMetadata{}

	if m.Title != "" {
		result.Title = m.Title
		result.TitleLang = m.TitleLang
	} else if base != nil {
		result.Title = base.Title
		result.TitleLang = base.TitleLang
	}

	if m.Author != "" {
		result.Author = m.Author
		result.AuthorLang = m.AuthorLang
	} else if base != nil {
		result.Author = base.Author
		result.AuthorLang = base.AuthorLang
	}

	if m.Subject != "" {
		result.Subject = m.Subject
		result.SubjectLang = m.SubjectLang
	} else if base != nil {
		result.Subject = base.Subject
		result.SubjectLang = base.SubjectLang
	}

	if len(m.Keywords) > 0 {
		result.Keywords = append([]string{}, m.Keywords...)
	} else if base != nil {
		result.Keywords = append([]string{}, base.Keywords...)
	}

	if m.Creator != "" {
		result.Creator = m.Creator
	} else if base != nil {
		result.Creator = base.Creator
	}

	if m.Created != nil {
		result.Created = m.Created
	} else if base != nil {
		result.Created = base.Created
	}

	result.LastModified = m.LastModified

	return result
}

// XmpArrayType represents the type of XMP array.
type XmpArrayType int

const (
	XmpArrayOrdered XmpArrayType = iota
	XmpArrayUnordered
	XmpArrayAlternative
)

// String returns the RDF element name for the array type.
func (t XmpArrayType) String() string {
	switch t {
	case XmpArrayOrdered:
		return "Seq"
	case XmpArrayUnordered:
		return "Bag"
	case XmpArrayAlternative:
		return "Alt"
	default:
		return "Seq"
	}
}

// AsRDF returns the expanded name for the array type.
func (t XmpArrayType) AsRDF() ExpandedName {
	return ExpandedName{NS: NSRDF, LocalName: t.String()}
}

// XmpValue represents a general XMP value.
type XmpValue struct {
	// Value can be string, XmpStructure, XmpArray, or XmpURI
	Value interface{}

	// Language is the xml:lang qualifier.
	Language string

	// Qualifiers are additional qualifiers.
	Qualifiers map[ExpandedName]*XmpValue
}

// NewXmpValue creates a new XmpValue with a string value.
func NewXmpValue(value string) *XmpValue {
	return &XmpValue{Value: value}
}

// NewXmpValueWithLang creates a new XmpValue with a string value and language.
func NewXmpValueWithLang(value, lang string) *XmpValue {
	return &XmpValue{Value: value, Language: lang}
}

// XmpStructure represents an XMP structure value.
type XmpStructure struct {
	Fields map[ExpandedName]*XmpValue
}

// NewXmpStructure creates a new empty XmpStructure.
func NewXmpStructure() *XmpStructure {
	return &XmpStructure{Fields: make(map[ExpandedName]*XmpValue)}
}

// Set sets a field value.
func (s *XmpStructure) Set(name ExpandedName, value *XmpValue) {
	s.Fields[name] = value
}

// Get gets a field value.
func (s *XmpStructure) Get(name ExpandedName) *XmpValue {
	return s.Fields[name]
}

// XmpArray represents an XMP array.
type XmpArray struct {
	ArrayType XmpArrayType
	Entries   []*XmpValue
}

// NewXmpOrderedArray creates a new ordered XMP array.
func NewXmpOrderedArray(entries ...*XmpValue) *XmpArray {
	return &XmpArray{ArrayType: XmpArrayOrdered, Entries: entries}
}

// NewXmpUnorderedArray creates a new unordered XMP array.
func NewXmpUnorderedArray(entries ...*XmpValue) *XmpArray {
	return &XmpArray{ArrayType: XmpArrayUnordered, Entries: entries}
}

// NewXmpAlternativeArray creates a new alternative XMP array.
func NewXmpAlternativeArray(entries ...*XmpValue) *XmpArray {
	return &XmpArray{ArrayType: XmpArrayAlternative, Entries: entries}
}

// XmpURI represents an XMP URI value.
type XmpURI string

// SerializeXMP serializes XMP structures to XML bytes.
func SerializeXMP(roots []*XmpStructure) ([]byte, error) {
	var buf bytes.Buffer

	// Write XMP packet header
	buf.WriteString("<?xpacket begin=\"\ufeff\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n")
	buf.WriteString(fmt.Sprintf("<x:xmpmeta xmlns:x=\"%s\" x:xmptk=\"%s\">\n", NSX, Vendor))
	buf.WriteString(fmt.Sprintf("<rdf:RDF xmlns:rdf=\"%s\">\n", NSRDF))

	for _, root := range roots {
		if err := serializeXmpStructure(&buf, root); err != nil {
			return nil, err
		}
	}

	buf.WriteString("</rdf:RDF>\n")
	buf.WriteString("</x:xmpmeta>\n")
	buf.WriteString("<?xpacket end=\"r\"?>")

	return buf.Bytes(), nil
}

func serializeXmpStructure(buf *bytes.Buffer, structure *XmpStructure) error {
	buf.WriteString(fmt.Sprintf("<rdf:Description rdf:about=\"\""))

	// Collect namespace prefixes
	nsPrefixes := collectNamespaces(structure)

	// Write namespace declarations
	for prefix, ns := range nsPrefixes {
		buf.WriteString(fmt.Sprintf(" xmlns:%s=\"%s\"", prefix, ns))
	}

	buf.WriteString(">\n")

	// Write fields
	for name, value := range structure.Fields {
		prefix := getPrefix(name.NS)
		if err := serializeXmpValue(buf, prefix, name.LocalName, value); err != nil {
			return err
		}
	}

	buf.WriteString("</rdf:Description>\n")
	return nil
}

func serializeXmpValue(buf *bytes.Buffer, prefix, localName string, value *XmpValue) error {
	tag := fmt.Sprintf("%s:%s", prefix, localName)

	switch v := value.Value.(type) {
	case string:
		buf.WriteString(fmt.Sprintf("<%s", tag))
		if value.Language != "" {
			buf.WriteString(fmt.Sprintf(" xml:lang=\"%s\"", escapeXML(value.Language)))
		}
		buf.WriteString(">")
		buf.WriteString(escapeXML(v))
		buf.WriteString(fmt.Sprintf("</%s>\n", tag))

	case *XmpArray:
		buf.WriteString(fmt.Sprintf("<%s>\n", tag))
		buf.WriteString(fmt.Sprintf("<rdf:%s>\n", v.ArrayType.String()))
		for _, entry := range v.Entries {
			buf.WriteString("<rdf:li")
			if entry.Language != "" {
				buf.WriteString(fmt.Sprintf(" xml:lang=\"%s\"", escapeXML(entry.Language)))
			}
			buf.WriteString(">")
			if str, ok := entry.Value.(string); ok {
				buf.WriteString(escapeXML(str))
			}
			buf.WriteString("</rdf:li>\n")
		}
		buf.WriteString(fmt.Sprintf("</rdf:%s>\n", v.ArrayType.String()))
		buf.WriteString(fmt.Sprintf("</%s>\n", tag))

	case *XmpStructure:
		buf.WriteString(fmt.Sprintf("<%s rdf:parseType=\"Resource\">\n", tag))
		for fieldName, fieldValue := range v.Fields {
			fieldPrefix := getPrefix(fieldName.NS)
			if err := serializeXmpValue(buf, fieldPrefix, fieldName.LocalName, fieldValue); err != nil {
				return err
			}
		}
		buf.WriteString(fmt.Sprintf("</%s>\n", tag))

	case XmpURI:
		buf.WriteString(fmt.Sprintf("<%s rdf:resource=\"%s\"/>\n", tag, escapeXML(string(v))))
	}

	return nil
}

// escapeXML escapes special XML characters.
func escapeXML(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func collectNamespaces(structure *XmpStructure) map[string]string {
	nsPrefixes := make(map[string]string)

	for name := range structure.Fields {
		prefix := getPrefix(name.NS)
		if prefix != "" && prefix != "rdf" {
			nsPrefixes[prefix] = name.NS
		}
	}

	return nsPrefixes
}

func getPrefix(ns string) string {
	switch ns {
	case NSRDF:
		return "rdf"
	case NSDC:
		return "dc"
	case NSPDF:
		return "pdf"
	case NSXMP:
		return "xmp"
	case NSPDFAId:
		return "pdfaid"
	case NSPDFUAId:
		return "pdfuaid"
	case NSXML:
		return "xml"
	default:
		return "ns"
	}
}

// DocumentMetadataToXMP converts DocumentMetadata to XMP structures.
func DocumentMetadataToXMP(meta *DocumentMetadata) []*XmpStructure {
	root := NewXmpStructure()

	if meta.Title != "" {
		entry := NewXmpValueWithLang(meta.Title, meta.TitleLang)
		if meta.TitleLang == "" {
			entry.Language = "x-default"
		}
		root.Set(DCTitle, &XmpValue{Value: NewXmpAlternativeArray(entry)})
	}

	if meta.Author != "" {
		entry := NewXmpValue(meta.Author)
		root.Set(DCCreator, &XmpValue{Value: NewXmpOrderedArray(entry)})
	}

	if meta.Subject != "" {
		entry := NewXmpValueWithLang(meta.Subject, meta.SubjectLang)
		if meta.SubjectLang == "" {
			entry.Language = "x-default"
		}
		root.Set(DCDescription, &XmpValue{Value: NewXmpAlternativeArray(entry)})
	}

	if len(meta.Keywords) > 0 {
		root.Set(PDFKeywords, NewXmpValue(strings.Join(meta.Keywords, ", ")))
	}

	if meta.Creator != "" {
		root.Set(XMPCreatorTool, NewXmpValue(meta.Creator))
	}

	if meta.Producer != "" {
		root.Set(PDFProducer, NewXmpValue(meta.Producer))
	}

	if meta.Created != nil {
		root.Set(XMPCreateDate, NewXmpValue(meta.Created.Format(time.RFC3339)))
	}

	if meta.LastModified != nil {
		root.Set(XMPModifyDate, NewXmpValue(meta.LastModified.Format(time.RFC3339)))
	}

	return []*XmpStructure{root}
}

// InfoDictEntry represents an entry in the PDF info dictionary.
type InfoDictEntry struct {
	Key   string
	Value string
}

// DocumentMetadataToInfoDict converts metadata to PDF info dictionary entries.
func DocumentMetadataToInfoDict(meta *DocumentMetadata) []InfoDictEntry {
	var entries []InfoDictEntry

	if meta.Title != "" {
		entries = append(entries, InfoDictEntry{Key: "Title", Value: meta.Title})
	}

	if meta.Author != "" {
		entries = append(entries, InfoDictEntry{Key: "Author", Value: meta.Author})
	}

	if meta.Subject != "" {
		entries = append(entries, InfoDictEntry{Key: "Subject", Value: meta.Subject})
	}

	if len(meta.Keywords) > 0 {
		entries = append(entries, InfoDictEntry{Key: "Keywords", Value: strings.Join(meta.Keywords, ", ")})
	}

	if meta.Creator != "" {
		entries = append(entries, InfoDictEntry{Key: "Creator", Value: meta.Creator})
	}

	if meta.Producer != "" {
		entries = append(entries, InfoDictEntry{Key: "Producer", Value: meta.Producer})
	}

	if meta.Created != nil {
		entries = append(entries, InfoDictEntry{Key: "CreationDate", Value: formatPDFDate(*meta.Created)})
	}

	if meta.LastModified != nil {
		entries = append(entries, InfoDictEntry{Key: "ModDate", Value: formatPDFDate(*meta.LastModified)})
	}

	return entries
}

// formatPDFDate formats a time as a PDF date string (D:YYYYMMDDHHmmSSOHH'mm').
func formatPDFDate(t time.Time) string {
	_, offset := t.Zone()
	hours := offset / 3600
	minutes := (offset % 3600) / 60
	sign := "+"
	if offset < 0 {
		sign = "-"
		hours = -hours
		minutes = -minutes
	}

	return fmt.Sprintf("D:%04d%02d%02d%02d%02d%02d%s%02d'%02d'",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
		sign, hours, minutes)
}

// ParsePDFDate parses a PDF date string.
func ParsePDFDate(s string) (*time.Time, error) {
	if !strings.HasPrefix(s, "D:") {
		return nil, fmt.Errorf("invalid PDF date: missing D: prefix")
	}

	s = s[2:] // Remove "D:" prefix

	// Normalize the string - remove quotes and convert to standard format
	s = strings.ReplaceAll(s, "'", "")

	// Try various formats
	formats := []string{
		"20060102150405-0700",
		"20060102150405+0700",
		"20060102150405Z",
		"20060102150405",
		"200601021504",
		"2006010215",
		"20060102",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return &t, nil
		}
	}

	return nil, fmt.Errorf("unable to parse PDF date: %s", s)
}
