// Package generic provides PDF object types and manipulation utilities.
package generic

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// PdfObject is the base interface for all PDF objects.
type PdfObject interface {
	// Write serializes the object to PDF format.
	Write(w io.Writer) error
	// Clone creates a deep copy of the object.
	Clone() PdfObject
	// GetObjectNumber returns the object number if this is an indirect object.
	GetObjectNumber() int
	// GetGenerationNumber returns the generation number if this is an indirect object.
	GetGenerationNumber() int
}

// Reference represents an indirect reference to a PDF object.
type Reference struct {
	ObjectNumber     int
	GenerationNumber int
}

// NewReference creates a new reference.
func NewReference(objNum, genNum int) Reference {
	return Reference{ObjectNumber: objNum, GenerationNumber: genNum}
}

// Write implements PdfObject.
func (r Reference) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%d %d R", r.ObjectNumber, r.GenerationNumber)
	return err
}

// Clone implements PdfObject.
func (r Reference) Clone() PdfObject {
	return Reference{ObjectNumber: r.ObjectNumber, GenerationNumber: r.GenerationNumber}
}

// GetObjectNumber implements PdfObject.
func (r Reference) GetObjectNumber() int {
	return r.ObjectNumber
}

// GetGenerationNumber implements PdfObject.
func (r Reference) GetGenerationNumber() int {
	return r.GenerationNumber
}

// String returns the string representation.
func (r Reference) String() string {
	return fmt.Sprintf("%d %d R", r.ObjectNumber, r.GenerationNumber)
}

// IndirectObject wraps a PDF object with its object and generation numbers.
type IndirectObject struct {
	ObjectNumber     int
	GenerationNumber int
	Object           PdfObject
}

// NewIndirectObject creates a new indirect object.
func NewIndirectObject(objNum, genNum int, obj PdfObject) *IndirectObject {
	return &IndirectObject{
		ObjectNumber:     objNum,
		GenerationNumber: genNum,
		Object:           obj,
	}
}

// Write implements PdfObject.
func (i *IndirectObject) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%d %d obj\n", i.ObjectNumber, i.GenerationNumber)
	if err != nil {
		return err
	}
	if i.Object != nil {
		if err := i.Object.Write(w); err != nil {
			return err
		}
	}
	_, err = w.Write([]byte("\nendobj\n"))
	return err
}

// Clone implements PdfObject.
func (i *IndirectObject) Clone() PdfObject {
	var obj PdfObject
	if i.Object != nil {
		obj = i.Object.Clone()
	}
	return &IndirectObject{
		ObjectNumber:     i.ObjectNumber,
		GenerationNumber: i.GenerationNumber,
		Object:           obj,
	}
}

// GetObjectNumber implements PdfObject.
func (i *IndirectObject) GetObjectNumber() int {
	return i.ObjectNumber
}

// GetGenerationNumber implements PdfObject.
func (i *IndirectObject) GetGenerationNumber() int {
	return i.GenerationNumber
}

// GetReference returns a reference to this indirect object.
func (i *IndirectObject) GetReference() Reference {
	return Reference{ObjectNumber: i.ObjectNumber, GenerationNumber: i.GenerationNumber}
}

// NullObject represents the PDF null value.
type NullObject struct{}

// Write implements PdfObject.
func (n NullObject) Write(w io.Writer) error {
	_, err := w.Write([]byte("null"))
	return err
}

// Clone implements PdfObject.
func (n NullObject) Clone() PdfObject {
	return NullObject{}
}

// GetObjectNumber implements PdfObject.
func (n NullObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (n NullObject) GetGenerationNumber() int { return 0 }

// BooleanObject represents a PDF boolean value.
type BooleanObject bool

// Write implements PdfObject.
func (b BooleanObject) Write(w io.Writer) error {
	if b {
		_, err := w.Write([]byte("true"))
		return err
	}
	_, err := w.Write([]byte("false"))
	return err
}

// Clone implements PdfObject.
func (b BooleanObject) Clone() PdfObject {
	return b
}

// GetObjectNumber implements PdfObject.
func (b BooleanObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (b BooleanObject) GetGenerationNumber() int { return 0 }

// IntegerObject represents a PDF integer value.
type IntegerObject int64

// Write implements PdfObject.
func (i IntegerObject) Write(w io.Writer) error {
	_, err := fmt.Fprintf(w, "%d", int64(i))
	return err
}

// Clone implements PdfObject.
func (i IntegerObject) Clone() PdfObject {
	return i
}

// GetObjectNumber implements PdfObject.
func (i IntegerObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (i IntegerObject) GetGenerationNumber() int { return 0 }

// RealObject represents a PDF real (floating point) value.
type RealObject float64

// Write implements PdfObject.
func (r RealObject) Write(w io.Writer) error {
	// Use minimal precision
	s := strconv.FormatFloat(float64(r), 'f', -1, 64)
	_, err := w.Write([]byte(s))
	return err
}

// Clone implements PdfObject.
func (r RealObject) Clone() PdfObject {
	return r
}

// GetObjectNumber implements PdfObject.
func (r RealObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (r RealObject) GetGenerationNumber() int { return 0 }

// NameObject represents a PDF name object (e.g., /Type).
type NameObject string

// escapedChars maps characters that need escaping in PDF names.
var nameEscapeRegex = regexp.MustCompile(`[^!-~]|[#%/\[\]()<>{}]`)

// Write implements PdfObject.
func (n NameObject) Write(w io.Writer) error {
	escaped := nameEscapeRegex.ReplaceAllStringFunc(string(n), func(s string) string {
		return fmt.Sprintf("#%02X", s[0])
	})
	_, err := fmt.Fprintf(w, "/%s", escaped)
	return err
}

// Clone implements PdfObject.
func (n NameObject) Clone() PdfObject {
	return n
}

// GetObjectNumber implements PdfObject.
func (n NameObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (n NameObject) GetGenerationNumber() int { return 0 }

// String returns the name without the leading slash.
func (n NameObject) String() string {
	return string(n)
}

// StringObject represents a PDF string object.
type StringObject struct {
	Value    []byte
	IsHex    bool
	Encoding string // "utf-16be", "pdfdoc", or empty for bytes
}

// NewLiteralString creates a new literal string.
func NewLiteralString(s string) *StringObject {
	return &StringObject{Value: []byte(s), IsHex: false}
}

// NewHexString creates a new hex string.
func NewHexString(data []byte) *StringObject {
	return &StringObject{Value: data, IsHex: true}
}

// NewTextString creates a PDF text string with UTF-16BE BOM if needed.
func NewTextString(s string) *StringObject {
	// Check if we need UTF-16BE encoding
	needsUnicode := false
	for _, r := range s {
		if r > 255 {
			needsUnicode = true
			break
		}
	}

	if needsUnicode {
		// UTF-16BE with BOM
		var buf bytes.Buffer
		buf.Write([]byte{0xFE, 0xFF}) // BOM
		for _, r := range s {
			buf.WriteByte(byte(r >> 8))
			buf.WriteByte(byte(r & 0xFF))
		}
		return &StringObject{Value: buf.Bytes(), Encoding: "utf-16be"}
	}

	return &StringObject{Value: []byte(s), Encoding: "pdfdoc"}
}

// Write implements PdfObject.
func (s *StringObject) Write(w io.Writer) error {
	if s.IsHex {
		_, err := fmt.Fprintf(w, "<%s>", hex.EncodeToString(s.Value))
		return err
	}

	// Literal string - escape special characters
	var buf bytes.Buffer
	buf.WriteByte('(')
	for _, b := range s.Value {
		switch b {
		case '\\':
			buf.WriteString("\\\\")
		case '(':
			buf.WriteString("\\(")
		case ')':
			buf.WriteString("\\)")
		case '\n':
			buf.WriteString("\\n")
		case '\r':
			buf.WriteString("\\r")
		case '\t':
			buf.WriteString("\\t")
		default:
			if b < 32 || b > 126 {
				buf.WriteString(fmt.Sprintf("\\%03o", b))
			} else {
				buf.WriteByte(b)
			}
		}
	}
	buf.WriteByte(')')
	_, err := w.Write(buf.Bytes())
	return err
}

// Clone implements PdfObject.
func (s *StringObject) Clone() PdfObject {
	val := make([]byte, len(s.Value))
	copy(val, s.Value)
	return &StringObject{Value: val, IsHex: s.IsHex, Encoding: s.Encoding}
}

// GetObjectNumber implements PdfObject.
func (s *StringObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (s *StringObject) GetGenerationNumber() int { return 0 }

// Text returns the string value decoded as text.
func (s *StringObject) Text() string {
	if len(s.Value) >= 2 && s.Value[0] == 0xFE && s.Value[1] == 0xFF {
		// UTF-16BE
		var result strings.Builder
		for i := 2; i+1 < len(s.Value); i += 2 {
			result.WriteRune(rune(s.Value[i])<<8 | rune(s.Value[i+1]))
		}
		return result.String()
	}
	return string(s.Value)
}

// ArrayObject represents a PDF array.
type ArrayObject []PdfObject

// NewArray creates a new array.
func NewArray(items ...PdfObject) ArrayObject {
	return ArrayObject(items)
}

// Write implements PdfObject.
func (a ArrayObject) Write(w io.Writer) error {
	if _, err := w.Write([]byte("[")); err != nil {
		return err
	}
	for i, item := range a {
		if i > 0 {
			if _, err := w.Write([]byte(" ")); err != nil {
				return err
			}
		}
		if err := item.Write(w); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte("]"))
	return err
}

// Clone implements PdfObject.
func (a ArrayObject) Clone() PdfObject {
	result := make(ArrayObject, len(a))
	for i, item := range a {
		result[i] = item.Clone()
	}
	return result
}

// GetObjectNumber implements PdfObject.
func (a ArrayObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (a ArrayObject) GetGenerationNumber() int { return 0 }

// Get returns the item at the given index.
func (a ArrayObject) Get(index int) PdfObject {
	if index < 0 || index >= len(a) {
		return nil
	}
	return a[index]
}

// DictionaryObject represents a PDF dictionary.
type DictionaryObject struct {
	entries map[string]PdfObject
	order   []string // Preserve insertion order
}

// NewDictionary creates a new dictionary.
func NewDictionary() *DictionaryObject {
	return &DictionaryObject{
		entries: make(map[string]PdfObject),
		order:   make([]string, 0),
	}
}

// Write implements PdfObject.
func (d *DictionaryObject) Write(w io.Writer) error {
	if _, err := w.Write([]byte("<<")); err != nil {
		return err
	}
	for _, key := range d.order {
		val := d.entries[key]
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
		if err := NameObject(key).Write(w); err != nil {
			return err
		}
		if _, err := w.Write([]byte(" ")); err != nil {
			return err
		}
		if err := val.Write(w); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte("\n>>"))
	return err
}

// Clone implements PdfObject.
func (d *DictionaryObject) Clone() PdfObject {
	result := NewDictionary()
	for _, key := range d.order {
		result.Set(key, d.entries[key].Clone())
	}
	return result
}

// GetObjectNumber implements PdfObject.
func (d *DictionaryObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (d *DictionaryObject) GetGenerationNumber() int { return 0 }

// Set sets a key-value pair.
func (d *DictionaryObject) Set(key string, value PdfObject) {
	if _, exists := d.entries[key]; !exists {
		d.order = append(d.order, key)
	}
	d.entries[key] = value
}

// Get returns the value for a key.
func (d *DictionaryObject) Get(key string) PdfObject {
	return d.entries[key]
}

// GetName returns a name value.
func (d *DictionaryObject) GetName(key string) string {
	if val := d.Get(key); val != nil {
		if name, ok := val.(NameObject); ok {
			return string(name)
		}
	}
	return ""
}

// GetInt returns an integer value.
func (d *DictionaryObject) GetInt(key string) (int64, bool) {
	if val := d.Get(key); val != nil {
		if i, ok := val.(IntegerObject); ok {
			return int64(i), true
		}
	}
	return 0, false
}

// GetArray returns an array value.
func (d *DictionaryObject) GetArray(key string) ArrayObject {
	if val := d.Get(key); val != nil {
		if arr, ok := val.(ArrayObject); ok {
			return arr
		}
	}
	return nil
}

// GetDict returns a dictionary value.
func (d *DictionaryObject) GetDict(key string) *DictionaryObject {
	if val := d.Get(key); val != nil {
		if dict, ok := val.(*DictionaryObject); ok {
			return dict
		}
	}
	return nil
}

// Delete removes a key.
func (d *DictionaryObject) Delete(key string) {
	if _, exists := d.entries[key]; exists {
		delete(d.entries, key)
		for i, k := range d.order {
			if k == key {
				d.order = append(d.order[:i], d.order[i+1:]...)
				break
			}
		}
	}
}

// Has returns true if the key exists.
func (d *DictionaryObject) Has(key string) bool {
	_, exists := d.entries[key]
	return exists
}

// Keys returns all keys.
func (d *DictionaryObject) Keys() []string {
	return d.order
}

// Len returns the number of entries.
func (d *DictionaryObject) Len() int {
	return len(d.entries)
}

// StreamObject represents a PDF stream.
type StreamObject struct {
	Dictionary *DictionaryObject
	Data       []byte
	// Decoded contains the decoded (unfiltered) data
	Decoded []byte
	// EncodedData contains the filtered/encoded data for writing
	EncodedData []byte
}

// NewStream creates a new stream.
func NewStream(dict *DictionaryObject, data []byte) *StreamObject {
	if dict == nil {
		dict = NewDictionary()
	}
	return &StreamObject{
		Dictionary: dict,
		Data:       data,
		Decoded:    data,
	}
}

// Write implements PdfObject.
func (s *StreamObject) Write(w io.Writer) error {
	// Use encoded data if available, otherwise raw data
	data := s.Data
	if len(s.EncodedData) > 0 {
		data = s.EncodedData
	}

	s.Dictionary.Set("Length", IntegerObject(len(data)))
	if err := s.Dictionary.Write(w); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\nstream\n")); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err := w.Write([]byte("\nendstream"))
	return err
}

// Clone implements PdfObject.
func (s *StreamObject) Clone() PdfObject {
	data := make([]byte, len(s.Data))
	copy(data, s.Data)
	decoded := make([]byte, len(s.Decoded))
	copy(decoded, s.Decoded)
	return &StreamObject{
		Dictionary: s.Dictionary.Clone().(*DictionaryObject),
		Data:       data,
		Decoded:    decoded,
	}
}

// GetObjectNumber implements PdfObject.
func (s *StreamObject) GetObjectNumber() int { return 0 }

// GetGenerationNumber implements PdfObject.
func (s *StreamObject) GetGenerationNumber() int { return 0 }

// GetDecodedData returns the decoded stream data.
func (s *StreamObject) GetDecodedData() []byte {
	if len(s.Decoded) > 0 {
		return s.Decoded
	}
	return s.Data
}

// Rectangle represents a PDF rectangle (lower-left and upper-right coordinates).
type Rectangle struct {
	LLX, LLY float64 // Lower-left
	URX, URY float64 // Upper-right
}

// NewRectangle creates a rectangle from an array.
func NewRectangle(arr ArrayObject) (*Rectangle, error) {
	if len(arr) != 4 {
		return nil, fmt.Errorf("rectangle must have 4 elements, got %d", len(arr))
	}

	var values [4]float64
	for i, obj := range arr {
		switch v := obj.(type) {
		case IntegerObject:
			values[i] = float64(v)
		case RealObject:
			values[i] = float64(v)
		default:
			return nil, fmt.Errorf("rectangle element %d must be numeric", i)
		}
	}

	return &Rectangle{
		LLX: values[0],
		LLY: values[1],
		URX: values[2],
		URY: values[3],
	}, nil
}

// ToArray converts the rectangle to a PDF array.
func (r *Rectangle) ToArray() ArrayObject {
	return ArrayObject{
		RealObject(r.LLX),
		RealObject(r.LLY),
		RealObject(r.URX),
		RealObject(r.URY),
	}
}

// Width returns the rectangle width.
func (r *Rectangle) Width() float64 {
	return r.URX - r.LLX
}

// Height returns the rectangle height.
func (r *Rectangle) Height() float64 {
	return r.URY - r.LLY
}

// TrailerDictionary represents the PDF trailer.
type TrailerDictionary struct {
	*DictionaryObject
}

// NewTrailer creates a new trailer dictionary.
func NewTrailer() *TrailerDictionary {
	return &TrailerDictionary{DictionaryObject: NewDictionary()}
}

// GetRoot returns the document catalog reference.
func (t *TrailerDictionary) GetRoot() *Reference {
	if ref, ok := t.Get("Root").(Reference); ok {
		return &ref
	}
	return nil
}

// GetInfo returns the document info reference.
func (t *TrailerDictionary) GetInfo() *Reference {
	if ref, ok := t.Get("Info").(Reference); ok {
		return &ref
	}
	return nil
}

// GetSize returns the size (total number of objects).
func (t *TrailerDictionary) GetSize() int64 {
	if size, ok := t.GetInt("Size"); ok {
		return size
	}
	return 0
}

// GetPrev returns the previous xref offset.
func (t *TrailerDictionary) GetPrev() (int64, bool) {
	return t.GetInt("Prev")
}

// ComputeFileID generates a file ID based on document parameters.
func ComputeFileID(info map[string]string) []byte {
	h := md5.New()
	for k, v := range info {
		h.Write([]byte(k))
		h.Write([]byte(v))
	}
	return h.Sum(nil)
}
