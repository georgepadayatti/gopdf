// Package reader provides XRef table handling utilities.
package reader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// XRefType represents different types of cross-reference entries.
type XRefType int

const (
	// XRefTypeFree represents a freeing instruction.
	XRefTypeFree XRefType = iota
	// XRefTypeStandard represents a regular top-level object.
	XRefTypeStandard
	// XRefTypeInObjStream represents an object that's part of an object stream.
	XRefTypeInObjStream
)

// String returns the string representation of the XRef type.
func (t XRefType) String() string {
	switch t {
	case XRefTypeFree:
		return "free"
	case XRefTypeStandard:
		return "standard"
	case XRefTypeInObjStream:
		return "in_obj_stream"
	default:
		return "unknown"
	}
}

// ObjStreamRef identifies an object that's part of an object stream.
type ObjStreamRef struct {
	// ObjStreamID is the ID number of the object stream (generation is 0).
	ObjStreamID int
	// IndexInStream is the index of the object in the stream.
	IndexInStream int
}

// ExtendedXRefEntry represents a cross-reference entry with full type information.
type ExtendedXRefEntry struct {
	// Type is the type of cross-reference entry.
	Type XRefType

	// Location is where the object is located.
	// For standard entries: the byte offset in the file.
	// For object stream entries: nil (use ObjStreamRef instead).
	Location int64

	// ObjStream is set for objects in object streams.
	ObjStream *ObjStreamRef

	// Generation is the object generation number.
	Generation int

	// ObjectNumber is the object number this entry refers to.
	ObjectNumber int
}

// NewStandardXRefEntry creates a standard XRef entry.
func NewStandardXRefEntry(objNum int, offset int64, generation int) *ExtendedXRefEntry {
	return &ExtendedXRefEntry{
		Type:         XRefTypeStandard,
		ObjectNumber: objNum,
		Location:     offset,
		Generation:   generation,
	}
}

// NewFreeXRefEntry creates a free XRef entry.
func NewFreeXRefEntry(objNum int, nextFree int64, generation int) *ExtendedXRefEntry {
	return &ExtendedXRefEntry{
		Type:         XRefTypeFree,
		ObjectNumber: objNum,
		Location:     nextFree,
		Generation:   generation,
	}
}

// NewObjStreamXRefEntry creates an XRef entry for an object in a stream.
func NewObjStreamXRefEntry(objNum, streamObjNum, indexInStream int) *ExtendedXRefEntry {
	return &ExtendedXRefEntry{
		Type:         XRefTypeInObjStream,
		ObjectNumber: objNum,
		ObjStream: &ObjStreamRef{
			ObjStreamID:   streamObjNum,
			IndexInStream: indexInStream,
		},
		Generation: 0, // Objects in streams always have generation 0
	}
}

// XRefSectionType represents the type of XRef section.
type XRefSectionType int

const (
	// XRefSectionTypeTable is a traditional XRef table.
	XRefSectionTypeTable XRefSectionType = iota
	// XRefSectionTypeStream is an XRef stream (PDF 1.5+).
	XRefSectionTypeStream
)

// XRefSection represents a section of the cross-reference table.
type XRefSection struct {
	// Type is whether this is a table or stream section.
	Type XRefSectionType

	// StartObject is the first object number in the section.
	StartObject int

	// Entries are the XRef entries in this section.
	Entries []*ExtendedXRefEntry

	// PreviousXRef is the byte offset of the previous XRef section.
	PreviousXRef int64

	// Trailer is the trailer dictionary for this section.
	Trailer *generic.TrailerDictionary
}

// XRefCache caches cross-reference information.
type XRefCache struct {
	// Entries maps object numbers to XRef entries.
	Entries map[int]*ExtendedXRefEntry

	// Sections holds all XRef sections in order.
	Sections []*XRefSection

	// CurrentTrailer is the most recent trailer dictionary.
	CurrentTrailer *generic.TrailerDictionary
}

// NewXRefCache creates a new XRef cache.
func NewXRefCache() *XRefCache {
	return &XRefCache{
		Entries:  make(map[int]*ExtendedXRefEntry),
		Sections: make([]*XRefSection, 0),
	}
}

// AddEntry adds an XRef entry to the cache.
func (c *XRefCache) AddEntry(entry *ExtendedXRefEntry) {
	// Only add if not already present (newer entries take precedence)
	if _, exists := c.Entries[entry.ObjectNumber]; !exists {
		c.Entries[entry.ObjectNumber] = entry
	}
}

// GetEntry retrieves an XRef entry by object number.
func (c *XRefCache) GetEntry(objNum int) *ExtendedXRefEntry {
	return c.Entries[objNum]
}

// AddSection adds an XRef section to the cache.
func (c *XRefCache) AddSection(section *XRefSection) {
	c.Sections = append(c.Sections, section)
	for _, entry := range section.Entries {
		c.AddEntry(entry)
	}
	if section.Trailer != nil && c.CurrentTrailer == nil {
		c.CurrentTrailer = section.Trailer
	}
}

// ObjectStream represents an object stream containing multiple objects.
type ObjectStream struct {
	// StreamObject is the underlying stream.
	StreamObject *generic.StreamObject

	// N is the number of objects in the stream.
	N int

	// First is the byte offset of the first object.
	First int

	// ObjectOffsets maps object indices to their offsets within the stream.
	ObjectOffsets map[int]int

	// DecodedData is the decoded stream data.
	DecodedData []byte
}

// ParseObjectStream parses an object stream.
func ParseObjectStream(stream *generic.StreamObject) (*ObjectStream, error) {
	dict := stream.Dictionary

	n, ok := dict.GetInt("N")
	if !ok {
		return nil, errors.New("object stream missing /N")
	}

	first, ok := dict.GetInt("First")
	if !ok {
		return nil, errors.New("object stream missing /First")
	}

	os := &ObjectStream{
		StreamObject:  stream,
		N:             int(n),
		First:         int(first),
		ObjectOffsets: make(map[int]int),
		DecodedData:   stream.Data,
	}

	// Parse the object number and offset pairs
	headerData := stream.Data[:first]
	parts := strings.Fields(string(headerData))

	for i := 0; i < len(parts)-1; i += 2 {
		objNum, err := strconv.Atoi(parts[i])
		if err != nil {
			continue
		}
		offset, err := strconv.Atoi(parts[i+1])
		if err != nil {
			continue
		}
		os.ObjectOffsets[i/2] = offset
		_ = objNum // The index in the stream is what we need
	}

	return os, nil
}

// GetObject retrieves an object from the stream by its index.
func (os *ObjectStream) GetObject(index int) ([]byte, error) {
	if index < 0 || index >= os.N {
		return nil, fmt.Errorf("object index %d out of range [0, %d)", index, os.N)
	}

	offset, ok := os.ObjectOffsets[index]
	if !ok {
		return nil, fmt.Errorf("no offset for object at index %d", index)
	}

	start := os.First + offset

	// Find end (start of next object or end of stream)
	end := len(os.DecodedData)
	for i := index + 1; i < os.N; i++ {
		if nextOffset, ok := os.ObjectOffsets[i]; ok {
			end = os.First + nextOffset
			break
		}
	}

	if start >= len(os.DecodedData) || end > len(os.DecodedData) {
		return nil, fmt.Errorf("object data out of bounds")
	}

	return os.DecodedData[start:end], nil
}

// ParseXRefTable parses a traditional XRef table.
func ParseXRefTable(data []byte, offset int64) (*XRefSection, error) {
	reader := bytes.NewReader(data[offset:])
	section := &XRefSection{
		Type:    XRefSectionTypeTable,
		Entries: make([]*ExtendedXRefEntry, 0),
	}

	// Skip "xref" keyword
	var line []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' || b == '\r' {
			break
		}
		line = append(line, b)
	}

	// Skip any trailing whitespace
	skipWhitespace(reader)

	// Parse subsections
	for {
		// Read start object and count
		lineBytes := make([]byte, 0, 32)
		for {
			b, err := reader.ReadByte()
			if err != nil {
				break
			}
			if b == '\n' || b == '\r' {
				break
			}
			lineBytes = append(lineBytes, b)
		}

		lineStr := strings.TrimSpace(string(lineBytes))
		if lineStr == "trailer" {
			break
		}

		parts := strings.Fields(lineStr)
		if len(parts) != 2 {
			continue
		}

		startObj, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		count, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		// Parse entries
		for i := 0; i < count; i++ {
			entryBytes := make([]byte, 20)
			_, err := io.ReadFull(reader, entryBytes)
			if err != nil {
				return nil, err
			}

			entryStr := string(bytes.TrimSpace(entryBytes))
			entryParts := strings.Fields(entryStr)
			if len(entryParts) < 3 {
				continue
			}

			byteOffset, _ := strconv.ParseInt(entryParts[0], 10, 64)
			generation, _ := strconv.Atoi(entryParts[1])
			inUse := entryParts[2] == "n"

			objNum := startObj + i
			if inUse {
				section.Entries = append(section.Entries, NewStandardXRefEntry(objNum, byteOffset, generation))
			} else {
				section.Entries = append(section.Entries, NewFreeXRefEntry(objNum, byteOffset, generation))
			}
		}
	}

	return section, nil
}

// ParseXRefStream parses an XRef stream.
func ParseXRefStream(stream *generic.StreamObject) (*XRefSection, error) {
	dict := stream.Dictionary

	section := &XRefSection{
		Type:    XRefSectionTypeStream,
		Entries: make([]*ExtendedXRefEntry, 0),
	}

	// Get W array (field widths)
	wArray := dict.GetArray("W")
	if wArray == nil || len(wArray) != 3 {
		return nil, errors.New("invalid /W array in XRef stream")
	}

	w := make([]int, 3)
	for i, v := range wArray {
		if intObj, ok := v.(generic.IntegerObject); ok {
			w[i] = int(intObj)
		}
	}

	// Get Index array (optional)
	indexArray := dict.GetArray("Index")
	var subsections [][2]int
	if indexArray != nil {
		for i := 0; i < len(indexArray); i += 2 {
			start, _ := indexArray[i].(generic.IntegerObject)
			count, _ := indexArray[i+1].(generic.IntegerObject)
			subsections = append(subsections, [2]int{int(start), int(count)})
		}
	} else {
		// Default: single subsection starting at 0
		size, _ := dict.GetInt("Size")
		subsections = [][2]int{{0, int(size)}}
	}

	entrySize := w[0] + w[1] + w[2]
	data := stream.Data
	pos := 0

	for _, subsec := range subsections {
		startObj := subsec[0]
		count := subsec[1]

		for i := 0; i < count; i++ {
			if pos+entrySize > len(data) {
				break
			}

			entryData := data[pos : pos+entrySize]
			pos += entrySize

			objNum := startObj + i

			// Parse fields
			field1 := readXRefField(entryData, 0, w[0])
			field2 := readXRefField(entryData, w[0], w[1])
			field3 := readXRefField(entryData, w[0]+w[1], w[2])

			// Default type is 1 (standard) if width is 0
			entryType := field1
			if w[0] == 0 {
				entryType = 1
			}

			switch entryType {
			case 0: // Free entry
				section.Entries = append(section.Entries, NewFreeXRefEntry(objNum, int64(field2), field3))
			case 1: // Standard entry
				section.Entries = append(section.Entries, NewStandardXRefEntry(objNum, int64(field2), field3))
			case 2: // Object stream entry
				section.Entries = append(section.Entries, NewObjStreamXRefEntry(objNum, field2, field3))
			}
		}
	}

	return section, nil
}

// readXRefField reads a field from XRef stream entry data.
func readXRefField(data []byte, offset, width int) int {
	if width == 0 {
		return 0
	}

	var value int
	for i := 0; i < width; i++ {
		value = (value << 8) | int(data[offset+i])
	}
	return value
}

// WriteXRefTable writes a traditional XRef table.
func WriteXRefTable(w io.Writer, entries []*ExtendedXRefEntry, startObj int) error {
	// Sort entries by object number
	// (assuming they're already sorted)

	fmt.Fprintf(w, "xref\n")
	fmt.Fprintf(w, "%d %d\n", startObj, len(entries))

	for _, entry := range entries {
		if entry.Type == XRefTypeFree {
			fmt.Fprintf(w, "%010d %05d f \n", entry.Location, entry.Generation)
		} else {
			fmt.Fprintf(w, "%010d %05d n \n", entry.Location, entry.Generation)
		}
	}

	return nil
}

// WriteXRefStream writes an XRef stream.
func WriteXRefStream(entries []*ExtendedXRefEntry, prev int64) (*generic.StreamObject, error) {
	// Determine field widths
	maxOffset := int64(0)
	maxGen := 0
	hasObjStreams := false

	for _, e := range entries {
		if e.Location > maxOffset {
			maxOffset = e.Location
		}
		if e.Generation > maxGen {
			maxGen = e.Generation
		}
		if e.Type == XRefTypeInObjStream {
			hasObjStreams = true
		}
	}

	// Calculate widths
	w1 := 1 // Type field
	w2 := bytesNeeded(int(maxOffset))
	w3 := bytesNeeded(maxGen)

	if hasObjStreams {
		// Object stream index might need more space
		if w3 < 2 {
			w3 = 2
		}
	}

	// Build stream data
	var buf bytes.Buffer
	for _, e := range entries {
		// Write type
		buf.WriteByte(byte(e.Type))

		// Write field 2
		writeField(&buf, e.Location, w2)

		// Write field 3
		if e.Type == XRefTypeInObjStream && e.ObjStream != nil {
			writeField(&buf, int64(e.ObjStream.IndexInStream), w3)
		} else {
			writeField(&buf, int64(e.Generation), w3)
		}
	}

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("XRef"))
	dict.Set("Size", generic.IntegerObject(len(entries)))
	dict.Set("W", generic.ArrayObject{
		generic.IntegerObject(w1),
		generic.IntegerObject(w2),
		generic.IntegerObject(w3),
	})

	if prev > 0 {
		dict.Set("Prev", generic.IntegerObject(prev))
	}

	return generic.NewStream(dict, buf.Bytes()), nil
}

func bytesNeeded(n int) int {
	if n == 0 {
		return 1
	}
	bytes := 0
	for n > 0 {
		bytes++
		n >>= 8
	}
	return bytes
}

func writeField(w *bytes.Buffer, value int64, width int) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(value))
	w.Write(data[8-width:])
}

func skipWhitespace(r *bytes.Reader) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			r.UnreadByte()
			return
		}
	}
}

// OBJSTREAM_FORBIDDEN is a set of object types that cannot be in object streams.
var OBJSTREAM_FORBIDDEN = map[string]bool{
	"XRef":     true,
	"Encrypt":  true,
	"Catalog":  true,
	"Pages":    true,
	"Outlines": true,
}

// CanBeInObjectStream checks if an object can be placed in an object stream.
func CanBeInObjectStream(obj generic.PdfObject) bool {
	if dict, ok := obj.(*generic.DictionaryObject); ok {
		if typeName := dict.GetName("Type"); typeName != "" {
			return !OBJSTREAM_FORBIDDEN[typeName]
		}
	}
	// Streams cannot be in object streams
	if _, ok := obj.(*generic.StreamObject); ok {
		return false
	}
	return true
}
