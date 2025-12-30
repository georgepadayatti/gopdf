// Package reader provides PDF file reading and parsing.
package reader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/georgepadayatti/gopdf/pdf/filters"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors
var (
	ErrInvalidPDF      = errors.New("invalid PDF file")
	ErrNoXRef          = errors.New("no xref found")
	ErrObjectNotFound  = errors.New("object not found")
	ErrInvalidXRef     = errors.New("invalid xref")
	ErrEncrypted       = errors.New("PDF is encrypted")
	ErrUnsupportedXRef = errors.New("unsupported xref type")
)

// XRefEntry represents an entry in the cross-reference table.
type XRefEntry struct {
	Offset     int64
	Generation int
	InUse      bool
	// For object streams
	ObjectStreamRef int
	IndexInStream   int
}

// PdfFileReader reads and parses PDF files.
type PdfFileReader struct {
	data    []byte
	Version string
	Trailer *generic.TrailerDictionary
	XRef    map[int]*XRefEntry
	Objects map[int]generic.PdfObject

	// Document structure
	Root     *generic.DictionaryObject
	Info     *generic.DictionaryObject
	Pages    []*generic.DictionaryObject
	AcroForm *generic.DictionaryObject

	// For incremental updates
	XRefOffsets []int64
	Trailers    []*generic.TrailerDictionary

	// Encryption
	Encrypted       bool
	SecurityHandler interface{} // Will be implemented later

	// HasXRefStream indicates if the PDF uses xref streams
	HasXRefStream bool
}

// NewPdfFileReader creates a new PDF reader.
func NewPdfFileReader(r io.Reader) (*PdfFileReader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read PDF data: %w", err)
	}

	return NewPdfFileReaderFromBytes(data)
}

// NewPdfFileReaderFromBytes creates a new PDF reader from bytes.
func NewPdfFileReaderFromBytes(data []byte) (*PdfFileReader, error) {
	reader := &PdfFileReader{
		data:    data,
		XRef:    make(map[int]*XRefEntry),
		Objects: make(map[int]generic.PdfObject),
	}

	if err := reader.parse(); err != nil {
		return nil, err
	}

	return reader, nil
}

// parse parses the PDF file.
func (r *PdfFileReader) parse() error {
	// Check PDF header
	if err := r.parseHeader(); err != nil {
		return err
	}

	// Find and parse xref
	if err := r.findAndParseXRef(); err != nil {
		return err
	}

	// Check for encryption
	if r.Trailer.Has("Encrypt") {
		r.Encrypted = true
		// For now, we'll handle basic/no encryption
		// Full encryption support will be added later
	}

	// Load document structure
	if err := r.loadDocumentStructure(); err != nil {
		return err
	}

	return nil
}

// parseHeader parses the PDF header.
func (r *PdfFileReader) parseHeader() error {
	if len(r.data) < 8 {
		return ErrInvalidPDF
	}

	headerRegex := regexp.MustCompile(`%PDF-(\d+\.\d+)`)
	match := headerRegex.Find(r.data[:min(100, len(r.data))])
	if match == nil {
		return fmt.Errorf("%w: missing PDF header", ErrInvalidPDF)
	}

	r.Version = string(match[5:])
	return nil
}

// findAndParseXRef finds the xref table and parses it.
func (r *PdfFileReader) findAndParseXRef() error {
	// Find startxref
	startxrefPos := bytes.LastIndex(r.data, []byte("startxref"))
	if startxrefPos == -1 {
		return ErrNoXRef
	}

	// Parse xref offset
	remaining := r.data[startxrefPos+9:]
	xrefOffset, err := r.parseXRefOffset(remaining)
	if err != nil {
		return err
	}

	// Parse xref chain
	return r.parseXRefChain(xrefOffset)
}

// parseXRefOffset parses the xref offset from startxref.
func (r *PdfFileReader) parseXRefOffset(data []byte) (int64, error) {
	// Skip whitespace
	i := 0
	for i < len(data) && (data[i] == ' ' || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
		i++
	}

	// Read number
	start := i
	for i < len(data) && data[i] >= '0' && data[i] <= '9' {
		i++
	}

	if start == i {
		return 0, fmt.Errorf("%w: missing xref offset", ErrInvalidXRef)
	}

	offset, err := strconv.ParseInt(string(data[start:i]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid xref offset: %v", ErrInvalidXRef, err)
	}

	return offset, nil
}

// parseXRefChain parses the chain of xref tables/streams.
func (r *PdfFileReader) parseXRefChain(offset int64) error {
	visited := make(map[int64]bool)

	for offset > 0 {
		if visited[offset] {
			break // Avoid infinite loops
		}
		visited[offset] = true
		r.XRefOffsets = append(r.XRefOffsets, offset)

		// Check if it's an xref table or stream
		if offset >= int64(len(r.data)) {
			return fmt.Errorf("%w: xref offset out of bounds", ErrInvalidXRef)
		}

		// Skip whitespace at offset
		pos := int(offset)
		for pos < len(r.data) && (r.data[pos] == ' ' || r.data[pos] == '\n' || r.data[pos] == '\r') {
			pos++
		}

		if pos+4 < len(r.data) && string(r.data[pos:pos+4]) == "xref" {
			// Traditional xref table
			trailer, err := r.parseXRefTable(int64(pos))
			if err != nil {
				return err
			}
			r.Trailers = append(r.Trailers, trailer)
			if r.Trailer == nil {
				r.Trailer = trailer
			}

			// Get prev offset
			if prev, ok := trailer.GetPrev(); ok {
				offset = prev
			} else {
				offset = 0
			}
		} else {
			// Cross-reference stream
			trailer, err := r.parseXRefStream(int64(pos))
			if err != nil {
				return err
			}
			r.Trailers = append(r.Trailers, trailer)
			if r.Trailer == nil {
				r.Trailer = trailer
			}

			// Get prev offset
			if prev, ok := trailer.GetPrev(); ok {
				offset = prev
			} else {
				offset = 0
			}
		}
	}

	return nil
}

// parseXRefTable parses a traditional xref table.
func (r *PdfFileReader) parseXRefTable(offset int64) (*generic.TrailerDictionary, error) {
	pos := int(offset)

	// Skip "xref" and whitespace
	pos += 4
	for pos < len(r.data) && (r.data[pos] == ' ' || r.data[pos] == '\n' || r.data[pos] == '\r') {
		pos++
	}

	// Parse subsections
	for {
		// Check for trailer
		if pos+7 < len(r.data) && string(r.data[pos:pos+7]) == "trailer" {
			pos += 7
			break
		}

		// Parse subsection header: start_obj count
		startObj, count, newPos, err := r.parseXRefSubsectionHeader(pos)
		if err != nil {
			return nil, err
		}
		pos = newPos

		// Parse entries
		for i := 0; i < count; i++ {
			entry, newPos, err := r.parseXRefEntry(pos)
			if err != nil {
				return nil, err
			}
			pos = newPos

			objNum := startObj + i
			if _, exists := r.XRef[objNum]; !exists {
				r.XRef[objNum] = entry
			}
		}
	}

	// Skip whitespace
	for pos < len(r.data) && (r.data[pos] == ' ' || r.data[pos] == '\n' || r.data[pos] == '\r') {
		pos++
	}

	// Parse trailer dictionary
	parser := generic.NewParserFromBytes(r.data[pos:])
	obj, err := parser.ParseObject()
	if err != nil {
		return nil, fmt.Errorf("failed to parse trailer: %w", err)
	}

	dict, ok := obj.(*generic.DictionaryObject)
	if !ok {
		return nil, fmt.Errorf("%w: trailer must be dictionary", ErrInvalidXRef)
	}

	return &generic.TrailerDictionary{DictionaryObject: dict}, nil
}

// parseXRefSubsectionHeader parses xref subsection header.
func (r *PdfFileReader) parseXRefSubsectionHeader(pos int) (startObj, count, newPos int, err error) {
	// Skip whitespace
	for pos < len(r.data) && (r.data[pos] == ' ' || r.data[pos] == '\n' || r.data[pos] == '\r') {
		pos++
	}

	// Read start object number
	start := pos
	for pos < len(r.data) && r.data[pos] >= '0' && r.data[pos] <= '9' {
		pos++
	}
	if start == pos {
		return 0, 0, pos, fmt.Errorf("%w: missing subsection start", ErrInvalidXRef)
	}
	startObj64, _ := strconv.ParseInt(string(r.data[start:pos]), 10, 32)
	startObj = int(startObj64)

	// Skip whitespace
	for pos < len(r.data) && (r.data[pos] == ' ' || r.data[pos] == '\t') {
		pos++
	}

	// Read count
	start = pos
	for pos < len(r.data) && r.data[pos] >= '0' && r.data[pos] <= '9' {
		pos++
	}
	if start == pos {
		return 0, 0, pos, fmt.Errorf("%w: missing subsection count", ErrInvalidXRef)
	}
	count64, _ := strconv.ParseInt(string(r.data[start:pos]), 10, 32)
	count = int(count64)

	// Skip to next line
	for pos < len(r.data) && r.data[pos] != '\n' && r.data[pos] != '\r' {
		pos++
	}
	for pos < len(r.data) && (r.data[pos] == '\n' || r.data[pos] == '\r') {
		pos++
	}

	return startObj, count, pos, nil
}

// parseXRefEntry parses a single xref entry.
func (r *PdfFileReader) parseXRefEntry(pos int) (*XRefEntry, int, error) {
	// Format: nnnnnnnnnn ggggg n/f
	// 10-digit offset, space, 5-digit generation, space, 'n' or 'f', EOL

	if pos+20 > len(r.data) {
		return nil, pos, fmt.Errorf("%w: truncated xref entry", ErrInvalidXRef)
	}

	line := string(r.data[pos : pos+20])

	// Parse offset
	offsetStr := strings.TrimSpace(line[:10])
	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil {
		return nil, pos, fmt.Errorf("%w: invalid offset: %v", ErrInvalidXRef, err)
	}

	// Parse generation
	genStr := strings.TrimSpace(line[11:16])
	gen, err := strconv.ParseInt(genStr, 10, 32)
	if err != nil {
		return nil, pos, fmt.Errorf("%w: invalid generation: %v", ErrInvalidXRef, err)
	}

	// Parse status
	status := line[17]
	inUse := status == 'n'

	// Skip to next line
	pos += 20
	for pos < len(r.data) && (r.data[pos] == '\n' || r.data[pos] == '\r' || r.data[pos] == ' ') {
		pos++
	}

	return &XRefEntry{
		Offset:     offset,
		Generation: int(gen),
		InUse:      inUse,
	}, pos, nil
}

// parseXRefStream parses a cross-reference stream.
func (r *PdfFileReader) parseXRefStream(offset int64) (*generic.TrailerDictionary, error) {
	parser := generic.NewParserFromBytes(r.data[offset:])
	indirectObj, err := parser.ParseIndirectObject()
	if err != nil {
		return nil, fmt.Errorf("failed to parse xref stream: %w", err)
	}

	stream, ok := indirectObj.Object.(*generic.StreamObject)
	if !ok {
		return nil, fmt.Errorf("%w: xref stream expected", ErrInvalidXRef)
	}

	dict := stream.Dictionary

	// Decode stream data
	streamData, err := r.decodeStream(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to decode xref stream: %w", err)
	}

	// Parse W array (field widths)
	wArray := dict.GetArray("W")
	if wArray == nil || len(wArray) != 3 {
		return nil, fmt.Errorf("%w: invalid W array", ErrInvalidXRef)
	}

	var w [3]int
	for i, v := range wArray {
		if iv, ok := v.(generic.IntegerObject); ok {
			w[i] = int(iv)
		}
	}

	entrySize := w[0] + w[1] + w[2]
	if entrySize == 0 {
		return nil, fmt.Errorf("%w: zero entry size", ErrInvalidXRef)
	}

	// Parse Index array
	var indexPairs []int
	if indexArray := dict.GetArray("Index"); indexArray != nil {
		for _, v := range indexArray {
			if iv, ok := v.(generic.IntegerObject); ok {
				indexPairs = append(indexPairs, int(iv))
			}
		}
	} else {
		// Default: [0 Size]
		if size, ok := dict.GetInt("Size"); ok {
			indexPairs = []int{0, int(size)}
		}
	}

	// Parse entries
	dataPos := 0
	for i := 0; i < len(indexPairs); i += 2 {
		startObj := indexPairs[i]
		count := indexPairs[i+1]

		for j := 0; j < count; j++ {
			if dataPos+entrySize > len(streamData) {
				break
			}

			entry := r.parseXRefStreamEntry(streamData[dataPos:dataPos+entrySize], w)
			objNum := startObj + j

			if _, exists := r.XRef[objNum]; !exists {
				r.XRef[objNum] = entry
			}

			dataPos += entrySize
		}
	}

	return &generic.TrailerDictionary{DictionaryObject: dict}, nil
}

// parseXRefStreamEntry parses a single xref stream entry.
func (r *PdfFileReader) parseXRefStreamEntry(data []byte, w [3]int) *XRefEntry {
	readField := func(start, length int) int64 {
		if length == 0 {
			return 0
		}
		var val int64
		for i := 0; i < length && start+i < len(data); i++ {
			val = (val << 8) | int64(data[start+i])
		}
		return val
	}

	typ := readField(0, w[0])
	if w[0] == 0 {
		typ = 1 // Default type
	}

	field2 := readField(w[0], w[1])
	field3 := readField(w[0]+w[1], w[2])

	switch typ {
	case 0:
		// Free object
		return &XRefEntry{
			Offset:     field2,
			Generation: int(field3),
			InUse:      false,
		}
	case 1:
		// Normal object
		return &XRefEntry{
			Offset:     field2,
			Generation: int(field3),
			InUse:      true,
		}
	case 2:
		// Compressed object in object stream
		return &XRefEntry{
			ObjectStreamRef: int(field2),
			IndexInStream:   int(field3),
			InUse:           true,
		}
	default:
		return &XRefEntry{InUse: false}
	}
}

// loadDocumentStructure loads the document catalog and other structures.
func (r *PdfFileReader) loadDocumentStructure() error {
	// Load Root (document catalog)
	rootRef := r.Trailer.GetRoot()
	if rootRef == nil {
		return fmt.Errorf("%w: missing Root", ErrInvalidPDF)
	}

	rootObj, err := r.GetObject(rootRef.ObjectNumber)
	if err != nil {
		return fmt.Errorf("failed to load Root: %w", err)
	}

	root, ok := rootObj.(*generic.DictionaryObject)
	if !ok {
		return fmt.Errorf("%w: Root must be dictionary", ErrInvalidPDF)
	}
	r.Root = root

	// Load Info if present
	if infoRef := r.Trailer.GetInfo(); infoRef != nil {
		if infoObj, err := r.GetObject(infoRef.ObjectNumber); err == nil {
			if info, ok := infoObj.(*generic.DictionaryObject); ok {
				r.Info = info
			}
		}
	}

	// Load pages
	if err := r.loadPages(); err != nil {
		return fmt.Errorf("failed to load pages: %w", err)
	}

	// Load AcroForm if present
	if acroFormRef, ok := r.Root.Get("AcroForm").(generic.Reference); ok {
		if acroFormObj, err := r.GetObject(acroFormRef.ObjectNumber); err == nil {
			if acroForm, ok := acroFormObj.(*generic.DictionaryObject); ok {
				r.AcroForm = acroForm
			}
		}
	} else if acroForm := r.Root.GetDict("AcroForm"); acroForm != nil {
		r.AcroForm = acroForm
	}

	return nil
}

// loadPages loads all pages from the page tree.
func (r *PdfFileReader) loadPages() error {
	pagesRef, ok := r.Root.Get("Pages").(generic.Reference)
	if !ok {
		return fmt.Errorf("%w: missing Pages reference", ErrInvalidPDF)
	}

	pagesObj, err := r.GetObject(pagesRef.ObjectNumber)
	if err != nil {
		return err
	}

	pagesDict, ok := pagesObj.(*generic.DictionaryObject)
	if !ok {
		return fmt.Errorf("%w: Pages must be dictionary", ErrInvalidPDF)
	}

	return r.loadPageTree(pagesDict)
}

// loadPageTree recursively loads pages from a page tree node.
func (r *PdfFileReader) loadPageTree(node *generic.DictionaryObject) error {
	nodeType := node.GetName("Type")

	if nodeType == "Page" {
		r.Pages = append(r.Pages, node)
		return nil
	}

	// Pages node - iterate kids
	kids := node.GetArray("Kids")
	if kids == nil {
		return nil
	}

	for _, kid := range kids {
		ref, ok := kid.(generic.Reference)
		if !ok {
			continue
		}

		kidObj, err := r.GetObject(ref.ObjectNumber)
		if err != nil {
			continue
		}

		kidDict, ok := kidObj.(*generic.DictionaryObject)
		if !ok {
			continue
		}

		if err := r.loadPageTree(kidDict); err != nil {
			return err
		}
	}

	return nil
}

// GetObject retrieves an object by object number.
func (r *PdfFileReader) GetObject(objNum int) (generic.PdfObject, error) {
	// Check cache
	if obj, ok := r.Objects[objNum]; ok {
		return obj, nil
	}

	// Find in xref
	entry, ok := r.XRef[objNum]
	if !ok {
		return nil, fmt.Errorf("%w: object %d", ErrObjectNotFound, objNum)
	}

	if !entry.InUse {
		return nil, fmt.Errorf("%w: object %d is free", ErrObjectNotFound, objNum)
	}

	var obj generic.PdfObject
	var err error

	if entry.ObjectStreamRef > 0 {
		// Object is in an object stream
		obj, err = r.getObjectFromStream(objNum, entry.ObjectStreamRef, entry.IndexInStream)
	} else {
		// Regular object
		obj, err = r.getObjectAtOffset(entry.Offset)
	}

	if err != nil {
		return nil, err
	}

	// Cache the object
	r.Objects[objNum] = obj
	return obj, nil
}

// getObjectAtOffset reads an object at the given file offset.
func (r *PdfFileReader) getObjectAtOffset(offset int64) (generic.PdfObject, error) {
	if offset >= int64(len(r.data)) {
		return nil, fmt.Errorf("%w: offset out of bounds", ErrObjectNotFound)
	}

	parser := generic.NewParserFromBytes(r.data[offset:])
	indirectObj, err := parser.ParseIndirectObject()
	if err != nil {
		return nil, err
	}

	// If it's a stream, decode it
	if stream, ok := indirectObj.Object.(*generic.StreamObject); ok {
		decoded, err := r.decodeStream(stream)
		if err == nil {
			stream.Decoded = decoded
		}
	}

	return indirectObj.Object, nil
}

// getObjectFromStream retrieves an object from an object stream.
func (r *PdfFileReader) getObjectFromStream(objNum, streamObjNum, index int) (generic.PdfObject, error) {
	// Get the object stream
	streamObj, err := r.GetObject(streamObjNum)
	if err != nil {
		return nil, err
	}

	stream, ok := streamObj.(*generic.StreamObject)
	if !ok {
		return nil, fmt.Errorf("object stream %d is not a stream", streamObjNum)
	}

	// Decode stream data
	data := stream.GetDecodedData()
	if len(data) == 0 {
		data, err = r.decodeStream(stream)
		if err != nil {
			return nil, err
		}
	}

	// Parse N and First from dictionary
	n, _ := stream.Dictionary.GetInt("N")
	first, _ := stream.Dictionary.GetInt("First")

	// Parse the index
	indexData := data[:first]
	var offsets []struct {
		objNum int
		offset int
	}

	parser := generic.NewParserFromBytes(indexData)
	for i := int64(0); i < n; i++ {
		objNumObj, err := parser.ParseObject()
		if err != nil {
			break
		}
		offsetObj, err := parser.ParseObject()
		if err != nil {
			break
		}

		on, _ := objNumObj.(generic.IntegerObject)
		off, _ := offsetObj.(generic.IntegerObject)
		offsets = append(offsets, struct {
			objNum int
			offset int
		}{int(on), int(off)})
	}

	if index >= len(offsets) {
		return nil, fmt.Errorf("index %d out of bounds", index)
	}

	// Parse the object
	objOffset := int(first) + offsets[index].offset
	parser = generic.NewParserFromBytes(data[objOffset:])
	return parser.ParseObjectOrReference()
}

// decodeStream decodes a stream's data.
func (r *PdfFileReader) decodeStream(stream *generic.StreamObject) ([]byte, error) {
	data := stream.Data

	// Get filter(s)
	var filterNames []string
	if filter := stream.Dictionary.Get("Filter"); filter != nil {
		switch f := filter.(type) {
		case generic.NameObject:
			filterNames = []string{string(f)}
		case generic.ArrayObject:
			for _, item := range f {
				if name, ok := item.(generic.NameObject); ok {
					filterNames = append(filterNames, string(name))
				}
			}
		}
	}

	if len(filterNames) == 0 {
		return data, nil
	}

	// Get decode parameters
	var decodeParms []map[string]interface{}
	if dp := stream.Dictionary.Get("DecodeParms"); dp != nil {
		decodeParms = r.extractDecodeParms(dp)
	}

	return filters.DecodeStream(data, filterNames, decodeParms)
}

// extractDecodeParms extracts decode parameters from a PDF object.
func (r *PdfFileReader) extractDecodeParms(obj generic.PdfObject) []map[string]interface{} {
	var result []map[string]interface{}

	switch v := obj.(type) {
	case *generic.DictionaryObject:
		result = append(result, r.dictToMap(v))
	case generic.ArrayObject:
		for _, item := range v {
			if dict, ok := item.(*generic.DictionaryObject); ok {
				result = append(result, r.dictToMap(dict))
			} else {
				result = append(result, nil)
			}
		}
	}

	return result
}

// dictToMap converts a PDF dictionary to a Go map.
func (r *PdfFileReader) dictToMap(dict *generic.DictionaryObject) map[string]interface{} {
	if dict == nil {
		return nil
	}

	result := make(map[string]interface{})
	for _, key := range dict.Keys() {
		val := dict.Get(key)
		switch v := val.(type) {
		case generic.IntegerObject:
			result[key] = int(v)
		case generic.RealObject:
			result[key] = float64(v)
		case generic.BooleanObject:
			result[key] = bool(v)
		case generic.NameObject:
			result[key] = string(v)
		case *generic.StringObject:
			result[key] = v.Text()
		}
	}
	return result
}

// ResolveReference resolves a reference to its actual object.
func (r *PdfFileReader) ResolveReference(obj generic.PdfObject) (generic.PdfObject, error) {
	if ref, ok := obj.(generic.Reference); ok {
		return r.GetObject(ref.ObjectNumber)
	}
	return obj, nil
}

// GetPageCount returns the number of pages.
func (r *PdfFileReader) GetPageCount() int {
	return len(r.Pages)
}

// GetPage returns a page by index (0-based).
func (r *PdfFileReader) GetPage(index int) (*generic.DictionaryObject, error) {
	if index < 0 || index >= len(r.Pages) {
		return nil, fmt.Errorf("page index %d out of bounds", index)
	}
	return r.Pages[index], nil
}

// GetSignatureFields returns all signature fields in the document.
func (r *PdfFileReader) GetSignatureFields() ([]*generic.DictionaryObject, error) {
	var sigFields []*generic.DictionaryObject

	if r.AcroForm == nil {
		return sigFields, nil
	}

	fields := r.AcroForm.GetArray("Fields")
	if fields == nil {
		return sigFields, nil
	}

	for _, fieldRef := range fields {
		field, err := r.resolveField(fieldRef)
		if err != nil {
			continue
		}

		fieldType := field.GetName("FT")
		if fieldType == "Sig" {
			sigFields = append(sigFields, field)
		}

		// Check kids
		kids := field.GetArray("Kids")
		for _, kidRef := range kids {
			kid, err := r.resolveField(kidRef)
			if err != nil {
				continue
			}
			if kid.GetName("FT") == "Sig" {
				sigFields = append(sigFields, kid)
			}
		}
	}

	return sigFields, nil
}

// resolveField resolves a field reference.
func (r *PdfFileReader) resolveField(obj generic.PdfObject) (*generic.DictionaryObject, error) {
	resolved, err := r.ResolveReference(obj)
	if err != nil {
		return nil, err
	}

	dict, ok := resolved.(*generic.DictionaryObject)
	if !ok {
		return nil, fmt.Errorf("field is not a dictionary")
	}

	return dict, nil
}

// GetEmbeddedSignatures returns the embedded signatures in the document.
func (r *PdfFileReader) GetEmbeddedSignatures() ([]*EmbeddedSignature, error) {
	sigFields, err := r.GetSignatureFields()
	if err != nil {
		return nil, err
	}

	var sigs []*EmbeddedSignature
	for _, field := range sigFields {
		// Get V (signature value)
		vRef, ok := field.Get("V").(generic.Reference)
		if !ok {
			continue
		}

		vObj, err := r.GetObject(vRef.ObjectNumber)
		if err != nil {
			continue
		}

		sigDict, ok := vObj.(*generic.DictionaryObject)
		if !ok {
			continue
		}

		sig := &EmbeddedSignature{
			Field:      field,
			Dictionary: sigDict,
			Reader:     r,
		}

		// Parse byte range
		if byteRange := sigDict.GetArray("ByteRange"); byteRange != nil && len(byteRange) == 4 {
			for i, v := range byteRange {
				if iv, ok := v.(generic.IntegerObject); ok {
					sig.ByteRange[i] = int64(iv)
				}
			}
		}

		// Get Contents
		if contents := sigDict.Get("Contents"); contents != nil {
			if str, ok := contents.(*generic.StringObject); ok {
				sig.Contents = str.Value
			}
		}

		sigs = append(sigs, sig)
	}

	return sigs, nil
}

// EmbeddedSignature represents an embedded PDF signature.
type EmbeddedSignature struct {
	Field      *generic.DictionaryObject
	Dictionary *generic.DictionaryObject
	ByteRange  [4]int64
	Contents   []byte
	Reader     *PdfFileReader
}

// GetSignedData returns the signed data (bytes covered by the signature).
func (e *EmbeddedSignature) GetSignedData() []byte {
	data := e.Reader.data
	offset1 := e.ByteRange[0]
	len1 := e.ByteRange[1]
	offset2 := e.ByteRange[2]
	len2 := e.ByteRange[3]

	result := make([]byte, len1+len2)
	copy(result[:len1], data[offset1:offset1+len1])
	copy(result[len1:], data[offset2:offset2+len2])

	return result
}

// GetSubFilter returns the signature sub-filter.
func (e *EmbeddedSignature) GetSubFilter() string {
	return e.Dictionary.GetName("SubFilter")
}

// GetFilter returns the signature filter.
func (e *EmbeddedSignature) GetFilter() string {
	return e.Dictionary.GetName("Filter")
}

// GetSigningTime returns the signing time (M field).
func (e *EmbeddedSignature) GetSigningTime() string {
	if m := e.Dictionary.Get("M"); m != nil {
		if str, ok := m.(*generic.StringObject); ok {
			return str.Text()
		}
	}
	return ""
}

// GetReason returns the signing reason.
func (e *EmbeddedSignature) GetReason() string {
	if reason := e.Dictionary.Get("Reason"); reason != nil {
		if str, ok := reason.(*generic.StringObject); ok {
			return str.Text()
		}
	}
	return ""
}

// GetLocation returns the signing location.
func (e *EmbeddedSignature) GetLocation() string {
	if loc := e.Dictionary.Get("Location"); loc != nil {
		if str, ok := loc.(*generic.StringObject); ok {
			return str.Text()
		}
	}
	return ""
}

// GetContactInfo returns the signer's contact info.
func (e *EmbeddedSignature) GetContactInfo() string {
	if contact := e.Dictionary.Get("ContactInfo"); contact != nil {
		if str, ok := contact.(*generic.StringObject); ok {
			return str.Text()
		}
	}
	return ""
}

// Data returns the raw PDF data.
func (r *PdfFileReader) Data() []byte {
	return r.data
}

// Decrypt decrypts the PDF with the given password.
func (r *PdfFileReader) Decrypt(password string) error {
	if !r.Encrypted {
		return nil
	}

	// TODO: Implement full decryption support
	// For now, this is a stub that marks the document as decrypted
	// if an empty password is provided (for unprotected encrypted PDFs)
	if password == "" {
		// Try empty password - some PDFs are encrypted but not password protected
		return nil
	}

	return errors.New("decryption with password not yet implemented")
}

// DecryptPubkey decrypts the PDF using public key encryption.
func (r *PdfFileReader) DecryptPubkey(credential interface{}) error {
	if !r.Encrypted {
		return nil
	}

	// TODO: Implement public key decryption
	return errors.New("public key decryption not yet implemented")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
