// Package writer provides PDF file writing and incremental update support.
// This file contains the IncrementalPdfFileWriter for incremental updates.
package writer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/metadata"
	"github.com/georgepadayatti/gopdf/pdf/reader"
)

// Common errors for incremental writer
var (
	ErrNoEncryptionCredentials = errors.New("cannot update this document without encryption credentials")
	ErrInvalidContainer        = errors.New("invalid container reference")
)

// IOChunkSize is the default chunk size for I/O operations.
const IOChunkSize = 4096

// IncrementalPdfFileWriter handles incremental updates to existing PDFs.
// Incremental updates append modifications to the end of the file,
// which is critical when the original file contents should not be
// modified (e.g., when it contains digital signatures).
type IncrementalPdfFileWriter struct {
	// Reader is the underlying PDF reader
	Reader *reader.PdfFileReader

	// Objects contains modified/new objects to be written
	Objects map[ObjectKey]*generic.IndirectObject

	// nextObjNum is the next object number to use
	nextObjNum int

	// originalData stores the original PDF data
	originalData []byte

	// inputStream is the original input stream (for in-place updates)
	inputStream io.ReadWriteSeeker

	// trailer is the trailer dictionary (copied from reader)
	trailer *generic.TrailerDictionary

	// rootRef is the reference to the document catalog
	rootRef generic.Reference

	// infoRef is the reference to the info dictionary (may be nil)
	infoRef *generic.Reference

	// documentID is the file identifier array
	documentID generic.ArrayObject

	// outputVersion is the PDF version for output
	outputVersion PDFVersion

	// streamXRefs indicates whether to use xref streams
	streamXRefs bool

	// securityHandler for encrypted PDFs
	securityHandler interface{}

	// encryptRef is the reference to the encryption dictionary
	encryptRef *generic.Reference

	// forceWriteWhenEmpty forces write even when no changes
	forceWriteWhenEmpty bool

	// meta holds document metadata
	meta *metadata.DocumentMetadata

	// resolvesObjsFrom is the list of handlers to resolve objects from
	resolvesObjsFrom []ObjectResolver
}

// ObjectKey uniquely identifies an object by number and generation
type ObjectKey struct {
	ObjectNumber int
	Generation   int
}

// ObjectResolver resolves PDF objects
type ObjectResolver interface {
	GetObject(objNum int) (generic.PdfObject, error)
}

// PDFVersion represents a PDF version as (major, minor)
type PDFVersion struct {
	Major int
	Minor int
}

// Compare compares two PDF versions
func (v PDFVersion) Compare(other PDFVersion) int {
	if v.Major != other.Major {
		return v.Major - other.Major
	}
	return v.Minor - other.Minor
}

// String returns the string representation of the version
func (v PDFVersion) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// DefaultOutputVersion is the default output PDF version
var DefaultOutputVersion = PDFVersion{Major: 1, Minor: 7}

// NewIncrementalPdfFileWriter creates an incremental writer from an existing PDF.
func NewIncrementalPdfFileWriter(r *reader.PdfFileReader) *IncrementalPdfFileWriter {
	return NewIncrementalPdfFileWriterWithStream(r, nil)
}

// NewIncrementalPdfFileWriterWithStream creates an incremental writer with an input stream.
func NewIncrementalPdfFileWriterWithStream(r *reader.PdfFileReader, inputStream io.ReadWriteSeeker) *IncrementalPdfFileWriter {
	// Find next object number
	maxObjNum := 0
	for objNum := range r.XRef {
		if objNum > maxObjNum {
			maxObjNum = objNum
		}
	}

	// Handle document ID
	documentID := handleDocumentID(r)

	// Get root reference
	var rootRef generic.Reference
	if r.Trailer != nil {
		if root := r.Trailer.GetRoot(); root != nil {
			rootRef = *root
		}
	}

	// Get info reference
	var infoRef *generic.Reference
	if r.Trailer != nil {
		infoRef = r.Trailer.GetInfo()
	}

	// Determine if using xref streams
	// Check if the reader has xref streams by looking for xref stream offsets
	streamXRefs := len(r.XRefOffsets) > 0 && r.HasXRefStream

	// Parse input version
	inputVersion := ParseVersion(r.Version)

	w := &IncrementalPdfFileWriter{
		Reader:          r,
		Objects:         make(map[ObjectKey]*generic.IndirectObject),
		nextObjNum:      maxObjNum + 1,
		originalData:    r.Data(),
		inputStream:     inputStream,
		trailer:         r.Trailer,
		rootRef:         rootRef,
		infoRef:         infoRef,
		documentID:      documentID,
		outputVersion:   DefaultOutputVersion,
		streamXRefs:     streamXRefs,
		securityHandler: r.SecurityHandler,
	}

	// Set output version to at least input version
	if inputVersion.Compare(w.outputVersion) > 0 {
		w.outputVersion = inputVersion
	}

	// If encrypted, store encrypt reference
	if r.Encrypted && r.Trailer != nil {
		if encRef := r.Trailer.Get("Encrypt"); encRef != nil {
			if ref, ok := encRef.(*generic.IndirectObject); ok {
				w.encryptRef = &generic.Reference{
					ObjectNumber:     ref.ObjectNumber,
					GenerationNumber: ref.GenerationNumber,
				}
			}
		}
	}

	w.resolvesObjsFrom = []ObjectResolver{w, r}

	return w
}

// FromReader creates an incremental writer from a PDF reader.
func FromReader(r *reader.PdfFileReader) *IncrementalPdfFileWriter {
	return NewIncrementalPdfFileWriter(r)
}

// handleDocumentID handles document ID for incremental updates.
// The first part of the ID is preserved (required for encryption),
// the second part is regenerated.
func handleDocumentID(r *reader.PdfFileReader) generic.ArrayObject {
	id2 := make([]byte, 16)
	rand.Read(id2)

	var id1 []byte
	if r.Trailer != nil {
		if idArray := r.Trailer.GetArray("ID"); idArray != nil && len(idArray) >= 1 {
			if str, ok := idArray[0].(*generic.StringObject); ok {
				id1 = str.Value
			}
		}
	}

	if id1 == nil {
		id1 = make([]byte, 16)
		rand.Read(id1)
	}

	return generic.ArrayObject{
		&generic.StringObject{Value: id1},
		&generic.StringObject{Value: id2},
	}
}

// ParseVersion parses a PDF version string like "1.7" into a PDFVersion.
func ParseVersion(version string) PDFVersion {
	var major, minor int
	fmt.Sscanf(version, "%d.%d", &major, &minor)
	if major == 0 {
		return DefaultOutputVersion
	}
	return PDFVersion{Major: major, Minor: minor}
}

// EnsureOutputVersion ensures the output version is at least the given version.
func (w *IncrementalPdfFileWriter) EnsureOutputVersion(version PDFVersion) error {
	// Check if input version already satisfies
	inputVersion := ParseVersion(w.Reader.Version)
	if inputVersion.Compare(version) >= 0 {
		return nil
	}

	// Check catalog version
	root, err := w.GetRoot()
	if err == nil && root != nil {
		if verName := root.GetName("Version"); verName != "" {
			if catVersion := ParseCatalogVersion(verName); catVersion.Compare(version) >= 0 {
				return nil
			}
		}
	}

	// Update catalog version
	if root != nil {
		versionStr := fmt.Sprintf("/%d.%d", version.Major, version.Minor)
		root.Set("Version", generic.NameObject(versionStr[1:]))
		w.UpdateRoot()
	}

	w.outputVersion = version
	return nil
}

// ParseCatalogVersion parses a version from the catalog.
func ParseCatalogVersion(ver string) PDFVersion {
	// Version like "1.7" or "/1.7"
	if len(ver) > 0 && ver[0] == '/' {
		ver = ver[1:]
	}
	return ParseVersion(ver)
}

// GetObject retrieves an object by number, preferring modified versions.
func (w *IncrementalPdfFileWriter) GetObject(objNum int) (generic.PdfObject, error) {
	// Check modified objects first
	for key, indObj := range w.Objects {
		if key.ObjectNumber == objNum {
			return indObj.Object, nil
		}
	}

	// Fall back to reader
	return w.Reader.GetObject(objNum)
}

// GetRoot returns the document catalog.
func (w *IncrementalPdfFileWriter) GetRoot() (*generic.DictionaryObject, error) {
	if w.rootRef.ObjectNumber == 0 {
		return nil, errors.New("no root reference")
	}
	obj, err := w.GetObject(w.rootRef.ObjectNumber)
	if err != nil {
		return nil, err
	}
	if dict, ok := obj.(*generic.DictionaryObject); ok {
		return dict, nil
	}
	return nil, errors.New("root is not a dictionary")
}

// AddObject adds a new object and returns its reference.
func (w *IncrementalPdfFileWriter) AddObject(obj generic.PdfObject) generic.Reference {
	objNum := w.nextObjNum
	w.nextObjNum++

	key := ObjectKey{ObjectNumber: objNum, Generation: 0}
	w.Objects[key] = generic.NewIndirectObject(objNum, 0, obj)

	return generic.Reference{ObjectNumber: objNum, GenerationNumber: 0}
}

// UpdateObject updates an existing object.
func (w *IncrementalPdfFileWriter) UpdateObject(objNum int, obj generic.PdfObject) {
	gen := 0
	if entry := w.Reader.XRef[objNum]; entry != nil {
		gen = entry.Generation
	}

	key := ObjectKey{ObjectNumber: objNum, Generation: gen}
	w.Objects[key] = generic.NewIndirectObject(objNum, gen, obj)
}

// MarkUpdate marks an object reference for update.
func (w *IncrementalPdfFileWriter) MarkUpdate(ref generic.Reference) error {
	obj, err := w.GetObject(ref.ObjectNumber)
	if err != nil {
		return err
	}
	w.UpdateObject(ref.ObjectNumber, obj)
	return nil
}

// UpdateContainer updates the container of a PDF object.
// This is a stub - full container tracking would require storing container
// references on each object, which Go's interface system doesn't easily support.
func (w *IncrementalPdfFileWriter) UpdateContainer(obj generic.PdfObject) error {
	// In a full implementation, we would track container references
	// and update them here. For now, callers should use MarkUpdate directly.
	return nil
}

// UpdateRoot marks the root catalog for update.
func (w *IncrementalPdfFileWriter) UpdateRoot() {
	w.MarkUpdate(w.rootRef)
}

// SetInfo sets the info dictionary.
func (w *IncrementalPdfFileWriter) SetInfo(info *generic.DictionaryObject) generic.Reference {
	var ref generic.Reference

	if info == nil {
		// Remove info
		if w.infoRef != nil {
			w.trailer.Delete("Info")
			w.infoRef = nil
		}
		return ref
	}

	if w.infoRef != nil {
		// Update existing
		w.UpdateObject(w.infoRef.ObjectNumber, info)
		ref = *w.infoRef
	} else {
		// Create new
		ref = w.AddObject(info)
		w.infoRef = &ref
	}

	w.trailer.Set("Info", &generic.IndirectObject{
		ObjectNumber:     ref.ObjectNumber,
		GenerationNumber: ref.GenerationNumber,
	})

	return ref
}

// SetCustomTrailerEntry sets a custom entry in the trailer.
func (w *IncrementalPdfFileWriter) SetCustomTrailerEntry(key string, value generic.PdfObject) {
	w.trailer.Set(key, value)
}

// GetTrailer returns the trailer dictionary.
func (w *IncrementalPdfFileWriter) GetTrailer() *generic.TrailerDictionary {
	return w.trailer
}

// populateTrailer populates the trailer dictionary for writing.
func (w *IncrementalPdfFileWriter) populateTrailer(trailer *generic.DictionaryObject) error {
	// Copy existing trailer entries
	if w.trailer != nil && w.trailer.DictionaryObject != nil {
		for _, key := range w.trailer.DictionaryObject.Keys() {
			val := w.trailer.Get(key)
			if val != nil {
				trailer.Set(key, val)
			}
		}
	}

	// Set required entries
	trailer.Set("Size", generic.IntegerObject(w.nextObjNum))

	// Set Prev to point to previous xref
	if len(w.Reader.XRefOffsets) > 0 {
		trailer.Set("Prev", generic.IntegerObject(w.Reader.XRefOffsets[0]))
	}

	// Set document ID
	trailer.Set("ID", w.documentID)

	// Set Root
	trailer.Set("Root", w.rootRef)

	// Set Info if present
	if w.infoRef != nil {
		trailer.Set("Info", *w.infoRef)
	}

	// Check encryption
	if w.Reader.Encrypted && w.securityHandler != nil {
		// Encryption credentials required
		// In a full implementation, check if authenticated
	}

	return nil
}

// Write writes the incremental update to the given writer.
func (w *IncrementalPdfFileWriter) Write(out io.Writer) error {
	if len(w.Objects) == 0 && !w.forceWriteWhenEmpty {
		// No changes, just write original
		_, err := out.Write(w.originalData)
		return err
	}

	return w.write(out, false)
}

// write performs the actual writing.
func (w *IncrementalPdfFileWriter) write(out io.Writer, skipHeader bool) error {
	var buf bytes.Buffer

	// Write original PDF (header)
	if !skipHeader {
		buf.Write(w.originalData)
	}

	// Track object offsets
	offsets := make(map[ObjectKey]int64)

	// Get sorted object keys for deterministic output
	keys := make([]ObjectKey, 0, len(w.Objects))
	for k := range w.Objects {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ObjectNumber != keys[j].ObjectNumber {
			return keys[i].ObjectNumber < keys[j].ObjectNumber
		}
		return keys[i].Generation < keys[j].Generation
	})

	// Write modified/new objects
	baseOffset := int64(len(w.originalData))
	for _, key := range keys {
		obj := w.Objects[key]
		offsets[key] = baseOffset + int64(buf.Len()) - int64(len(w.originalData))
		obj.Write(&buf)
		buf.WriteByte('\n')
	}

	// Write xref
	xrefOffset := baseOffset + int64(buf.Len()) - int64(len(w.originalData))

	if w.streamXRefs {
		if err := w.writeXRefStream(&buf, offsets, xrefOffset); err != nil {
			return err
		}
	} else {
		if err := w.writeXRefTable(&buf, offsets, xrefOffset); err != nil {
			return err
		}
	}

	_, err := out.Write(buf.Bytes())
	return err
}

// writeXRefTable writes a traditional xref table.
func (w *IncrementalPdfFileWriter) writeXRefTable(buf *bytes.Buffer, offsets map[ObjectKey]int64, xrefOffset int64) error {
	fmt.Fprintf(buf, "xref\n")

	// Group consecutive objects into subsections
	type subsection struct {
		start   int
		entries []ObjectKey
	}

	var subsections []subsection

	// Sort keys by object number
	keys := make([]ObjectKey, 0, len(offsets))
	for k := range offsets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ObjectNumber < keys[j].ObjectNumber
	})

	// Build subsections
	if len(keys) > 0 {
		current := subsection{start: keys[0].ObjectNumber, entries: []ObjectKey{keys[0]}}
		for i := 1; i < len(keys); i++ {
			if keys[i].ObjectNumber == current.start+len(current.entries) {
				current.entries = append(current.entries, keys[i])
			} else {
				subsections = append(subsections, current)
				current = subsection{start: keys[i].ObjectNumber, entries: []ObjectKey{keys[i]}}
			}
		}
		subsections = append(subsections, current)
	}

	// Write subsections
	for _, sub := range subsections {
		fmt.Fprintf(buf, "%d %d\n", sub.start, len(sub.entries))
		for _, key := range sub.entries {
			offset := offsets[key]
			obj := w.Objects[key]
			fmt.Fprintf(buf, "%010d %05d n \n", offset, obj.GenerationNumber)
		}
	}

	// Write trailer
	trailer := generic.NewDictionary()
	if err := w.populateTrailer(trailer); err != nil {
		return err
	}

	fmt.Fprintf(buf, "trailer\n")
	trailer.Write(buf)
	fmt.Fprintf(buf, "\nstartxref\n%d\n%%%%EOF\n", xrefOffset)

	return nil
}

// writeXRefStream writes an xref stream.
func (w *IncrementalPdfFileWriter) writeXRefStream(buf *bytes.Buffer, offsets map[ObjectKey]int64, xrefOffset int64) error {
	// Build xref stream
	// This is a simplified implementation

	// For now, fall back to table format
	// TODO: Implement proper xref stream writing
	return w.writeXRefTable(buf, offsets, xrefOffset)
}

// WriteUpdatedSection writes only the updated section (for concatenation).
func (w *IncrementalPdfFileWriter) WriteUpdatedSection(out io.Writer) error {
	return w.write(out, true)
}

// WriteInPlace writes the update in-place to the input stream.
func (w *IncrementalPdfFileWriter) WriteInPlace() error {
	if w.inputStream == nil {
		return errors.New("no input stream for in-place writing")
	}

	// Seek to end of original content
	_, err := w.inputStream.Seek(0, os.SEEK_END)
	if err != nil {
		return err
	}

	return w.WriteUpdatedSection(w.inputStream)
}

// Encrypt handles updates to encrypted files.
func (w *IncrementalPdfFileWriter) Encrypt(userPassword string) error {
	if !w.Reader.Encrypted {
		return errors.New("document is not encrypted")
	}

	// Decrypt the document
	err := w.Reader.Decrypt(userPassword)
	if err != nil {
		return err
	}

	// Store encryption reference from original
	if w.Reader.Trailer != nil {
		if encObj := w.Reader.Trailer.Get("Encrypt"); encObj != nil {
			if ref, ok := encObj.(*generic.IndirectObject); ok {
				w.encryptRef = &generic.Reference{
					ObjectNumber:     ref.ObjectNumber,
					GenerationNumber: ref.GenerationNumber,
				}
			}
		}
	}

	w.securityHandler = w.Reader.SecurityHandler

	return nil
}

// DocumentID returns the document ID (first and second part).
func (w *IncrementalPdfFileWriter) DocumentID() ([]byte, []byte) {
	if len(w.documentID) < 2 {
		return nil, nil
	}

	var id1, id2 []byte
	if str, ok := w.documentID[0].(*generic.StringObject); ok {
		id1 = str.Value
	}
	if str, ok := w.documentID[1].(*generic.StringObject); ok {
		id2 = str.Value
	}

	return id1, id2
}

// RootRef returns the root catalog reference.
func (w *IncrementalPdfFileWriter) RootRef() generic.Reference {
	return w.rootRef
}

// OutputVersion returns the output PDF version.
func (w *IncrementalPdfFileWriter) OutputVersion() PDFVersion {
	return w.outputVersion
}

// NextObjectNumber returns the next available object number.
func (w *IncrementalPdfFileWriter) NextObjectNumber() int {
	return w.nextObjNum
}

// HasChanges returns true if there are pending changes.
func (w *IncrementalPdfFileWriter) HasChanges() bool {
	return len(w.Objects) > 0
}

// SetForceWrite forces writing even when there are no changes.
func (w *IncrementalPdfFileWriter) SetForceWrite(force bool) {
	w.forceWriteWhenEmpty = force
}

// GetSecurityHandler returns the security handler if present.
func (w *IncrementalPdfFileWriter) GetSecurityHandler() interface{} {
	return w.securityHandler
}

// IsEncrypted returns true if the document is encrypted.
func (w *IncrementalPdfFileWriter) IsEncrypted() bool {
	return w.Reader.Encrypted
}

// StreamXRefs returns true if using xref streams.
func (w *IncrementalPdfFileWriter) StreamXRefs() bool {
	return w.streamXRefs
}

// SetStreamXRefs sets whether to use xref streams.
func (w *IncrementalPdfFileWriter) SetStreamXRefs(use bool) {
	w.streamXRefs = use
}

// AddStreamToPage adds a content stream to a page, optionally prepending it.
// If resources is provided, they are merged into the page's resources.
// Returns a reference to the page.
func (w *IncrementalPdfFileWriter) AddStreamToPage(pageNum int, streamRef generic.Reference, resources *generic.DictionaryObject, prepend bool) (generic.Reference, error) {
	// Get the page
	page, err := w.Reader.GetPage(pageNum)
	if err != nil {
		return generic.Reference{}, fmt.Errorf("failed to get page %d: %w", pageNum, err)
	}

	// Clone the page for modification
	pageCopy := page.Clone().(*generic.DictionaryObject)

	// Get or create Contents array
	contents := pageCopy.Get("Contents")
	var contentArray generic.ArrayObject

	switch c := contents.(type) {
	case *generic.IndirectObject:
		// Single stream - convert to array
		contentArray = generic.ArrayObject{c}
	case generic.Reference:
		contentArray = generic.ArrayObject{c}
	case *generic.ArrayObject:
		contentArray = *c
	case generic.ArrayObject:
		contentArray = c
	case nil:
		contentArray = generic.ArrayObject{}
	default:
		// Try to use as-is if it's a reference-like object
		contentArray = generic.ArrayObject{c}
	}

	// Add new stream
	if prepend {
		contentArray = append(generic.ArrayObject{streamRef}, contentArray...)
	} else {
		contentArray = append(contentArray, streamRef)
	}

	pageCopy.Set("Contents", contentArray)

	// Merge resources if provided
	if resources != nil {
		pageResources := pageCopy.GetDict("Resources")
		if pageResources == nil {
			pageResources = generic.NewDictionary()
		} else {
			pageResources = pageResources.Clone().(*generic.DictionaryObject)
		}

		// Merge each resource category
		for _, key := range resources.Keys() {
			resVal := resources.Get(key)
			if resDict, ok := resVal.(*generic.DictionaryObject); ok {
				existingDict := pageResources.GetDict(key)
				if existingDict == nil {
					existingDict = generic.NewDictionary()
				} else {
					existingDict = existingDict.Clone().(*generic.DictionaryObject)
				}
				// Merge entries
				for _, k := range resDict.Keys() {
					existingDict.Set(k, resDict.Get(k))
				}
				pageResources.Set(key, existingDict)
			} else {
				pageResources.Set(key, resVal)
			}
		}
		pageCopy.Set("Resources", pageResources)
	}

	// Find and update page object
	pageObjNum := w.findPageObjectNumber(pageNum)
	if pageObjNum <= 0 {
		return generic.Reference{}, fmt.Errorf("could not find page object number for page %d", pageNum)
	}

	w.UpdateObject(pageObjNum, pageCopy)

	return w.getPageReference(pageNum), nil
}

// ChunkedCopy copies data from src to dst in chunks.
func ChunkedCopy(src io.Reader, dst io.Writer, chunkSize int) error {
	if chunkSize <= 0 {
		chunkSize = IOChunkSize
	}
	buf := make([]byte, chunkSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// SignaturePlaceholder holds signature placeholder information.
type SignaturePlaceholder struct {
	SigDict        *generic.DictionaryObject
	SigDictRef     generic.Reference
	ContentsSize   int
	ByteRangeStart int64
	ContentsStart  int64
}

// SignatureInfo contains information needed to complete a signature.
type SignatureInfo struct {
	Data           []byte
	ByteRange      [4]int64
	ContentsOffset int64
	ContentsSize   int
}

// GetDataToSign returns the data that should be signed (excluding Contents).
func (s *SignatureInfo) GetDataToSign() []byte {
	part1 := s.Data[s.ByteRange[0] : s.ByteRange[0]+s.ByteRange[1]]
	part2 := s.Data[s.ByteRange[2] : s.ByteRange[2]+s.ByteRange[3]]

	result := make([]byte, len(part1)+len(part2))
	copy(result, part1)
	copy(result[len(part1):], part2)

	return result
}

// EmbedSignature embeds the signature into the PDF data.
func (s *SignatureInfo) EmbedSignature(signature []byte) []byte {
	result := make([]byte, len(s.Data))
	copy(result, s.Data)

	// Convert signature to hex and pad
	hexSig := fmt.Sprintf("%X", signature)
	if len(hexSig) > s.ContentsSize*2 {
		hexSig = hexSig[:s.ContentsSize*2]
	}
	for len(hexSig) < s.ContentsSize*2 {
		hexSig += "0"
	}

	// Copy hex signature into contents area
	copy(result[s.ContentsOffset:], []byte(hexSig))

	return result
}

// AddSignatureField adds a signature field for incremental signing.
func (w *IncrementalPdfFileWriter) AddSignatureField(name string, pageNum int, rect *generic.Rectangle) (generic.Reference, *generic.DictionaryObject, error) {
	// Get the page
	page, err := w.Reader.GetPage(pageNum)
	if err != nil {
		return generic.Reference{}, nil, err
	}

	// Get page reference
	pageRef := w.getPageReference(pageNum)

	// Create signature field
	sigField := generic.NewDictionary()
	sigField.Set("Type", generic.NameObject("Annot"))
	sigField.Set("Subtype", generic.NameObject("Widget"))
	sigField.Set("FT", generic.NameObject("Sig"))
	sigField.Set("T", generic.NewTextString(name))
	sigField.Set("Rect", rect.ToArray())
	sigField.Set("F", generic.IntegerObject(132)) // Print + Locked
	sigField.Set("P", pageRef)

	sigFieldRef := w.AddObject(sigField)

	// Update AcroForm
	acroForm := w.Reader.AcroForm
	if acroForm == nil {
		acroForm = generic.NewDictionary()
		acroForm.Set("Fields", generic.ArrayObject{})
		acroForm.Set("SigFlags", generic.IntegerObject(0))

		acroFormRef := w.AddObject(acroForm)

		// Update Root
		root, _ := w.GetRoot()
		if root != nil {
			rootCopy := root.Clone().(*generic.DictionaryObject)
			rootCopy.Set("AcroForm", acroFormRef)
			w.UpdateObject(w.rootRef.ObjectNumber, rootCopy)
		}
	} else {
		acroForm = acroForm.Clone().(*generic.DictionaryObject)
	}

	// Add field to AcroForm
	fields := acroForm.GetArray("Fields")
	if fields == nil {
		fields = generic.ArrayObject{}
	}
	fields = append(fields, sigFieldRef)
	acroForm.Set("Fields", fields)

	// Update SigFlags
	sigFlags, _ := acroForm.GetInt("SigFlags")
	sigFlags |= 3 // SignaturesExist | AppendOnly
	acroForm.Set("SigFlags", generic.IntegerObject(sigFlags))

	// Update page annotations
	pageCopy := page.Clone().(*generic.DictionaryObject)
	annots := pageCopy.GetArray("Annots")
	if annots == nil {
		annots = generic.ArrayObject{}
	}
	annots = append(annots, sigFieldRef)
	pageCopy.Set("Annots", annots)

	// Find page object number and update
	pageObjNum := w.findPageObjectNumber(pageNum)
	if pageObjNum > 0 {
		w.UpdateObject(pageObjNum, pageCopy)
	}

	return sigFieldRef, sigField, nil
}

// getPageReference returns a reference to the given page.
func (w *IncrementalPdfFileWriter) getPageReference(pageNum int) generic.Reference {
	objNum := w.findPageObjectNumber(pageNum)
	if objNum > 0 {
		gen := 0
		if entry := w.Reader.XRef[objNum]; entry != nil {
			gen = entry.Generation
		}
		return generic.Reference{ObjectNumber: objNum, GenerationNumber: gen}
	}
	return generic.Reference{}
}

// findPageObjectNumber finds the object number for a page.
func (w *IncrementalPdfFileWriter) findPageObjectNumber(pageNum int) int {
	for objNum, entry := range w.Reader.XRef {
		if !entry.InUse {
			continue
		}
		obj, err := w.Reader.GetObject(objNum)
		if err != nil {
			continue
		}
		dict, ok := obj.(*generic.DictionaryObject)
		if !ok {
			continue
		}
		if dict.GetName("Type") == "Page" {
			if pageNum == 0 {
				return objNum
			}
			pageNum--
		}
	}
	return 0
}

// PrepareSignature prepares a signature placeholder.
func (w *IncrementalPdfFileWriter) PrepareSignature(sigFieldRef generic.Reference, sigField *generic.DictionaryObject, contentsSize int) (*SignaturePlaceholder, error) {
	// Create signature dictionary
	sigDict := generic.NewDictionary()
	sigDict.Set("Type", generic.NameObject("Sig"))
	sigDict.Set("Filter", generic.NameObject("Adobe.PPKLite"))
	sigDict.Set("SubFilter", generic.NameObject("adbe.pkcs7.detached"))

	// Contents placeholder (will be filled with actual signature)
	contentsPlaceholder := make([]byte, contentsSize)
	sigDict.Set("Contents", generic.NewHexString(contentsPlaceholder))

	// ByteRange placeholder
	sigDict.Set("ByteRange", generic.ArrayObject{
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
	})

	sigDictRef := w.AddObject(sigDict)

	// Update signature field to point to signature dictionary
	sigField.Set("V", sigDictRef)

	return &SignaturePlaceholder{
		SigDict:      sigDict,
		SigDictRef:   sigDictRef,
		ContentsSize: contentsSize,
	}, nil
}

// WriteWithSignature writes the PDF with a signature placeholder and returns info for signing.
func (w *IncrementalPdfFileWriter) WriteWithSignature(out io.Writer, placeholder *SignaturePlaceholder) (*SignatureInfo, error) {
	var buf bytes.Buffer

	// Write original PDF
	buf.Write(w.originalData)

	// Track object offsets
	offsets := make(map[ObjectKey]int64)

	// Get sorted keys
	keys := make([]ObjectKey, 0, len(w.Objects))
	for k := range w.Objects {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ObjectNumber < keys[j].ObjectNumber
	})

	// Write modified/new objects, tracking signature dictionary position
	var contentsOffset int64
	var byteRangeOffset int64

	for _, key := range keys {
		obj := w.Objects[key]
		offsets[key] = int64(buf.Len())

		if key.ObjectNumber == placeholder.SigDictRef.ObjectNumber {
			// Write object header
			fmt.Fprintf(&buf, "%d %d obj\n", key.ObjectNumber, obj.GenerationNumber)
			fmt.Fprintf(&buf, "<<\n")

			// Write dictionary entries, tracking special ones
			for _, dictKey := range placeholder.SigDict.Keys() {
				val := placeholder.SigDict.Get(dictKey)
				fmt.Fprintf(&buf, "/%s ", dictKey)

				if dictKey == "ByteRange" {
					byteRangeOffset = int64(buf.Len())
					fmt.Fprintf(&buf, "[%010d %010d %010d %010d]", 0, 0, 0, 0)
				} else if dictKey == "Contents" {
					contentsOffset = int64(buf.Len())
					buf.WriteByte('<')
					for i := 0; i < placeholder.ContentsSize; i++ {
						buf.WriteString("00")
					}
					buf.WriteByte('>')
				} else {
					val.Write(&buf)
				}
				buf.WriteByte('\n')
			}

			fmt.Fprintf(&buf, ">>\nendobj\n")
		} else {
			obj.Write(&buf)
			buf.WriteByte('\n')
		}
	}

	// Write xref
	xrefOffset := int64(buf.Len())
	fmt.Fprintf(&buf, "xref\n")

	for _, key := range keys {
		fmt.Fprintf(&buf, "%d 1\n", key.ObjectNumber)
		obj := w.Objects[key]
		fmt.Fprintf(&buf, "%010d %05d n \n", offsets[key], obj.GenerationNumber)
	}

	// Write trailer
	trailer := generic.NewDictionary()
	w.populateTrailer(trailer)

	fmt.Fprintf(&buf, "trailer\n")
	trailer.Write(&buf)
	fmt.Fprintf(&buf, "\nstartxref\n%d\n%%%%EOF\n", xrefOffset)

	// Calculate byte ranges
	contentsStart := contentsOffset + 1 // After '<'
	contentsEnd := contentsStart + int64(placeholder.ContentsSize*2)

	// ByteRange must exclude the entire <...> contents, including both delimiters.
	byteRange := [4]int64{
		0,
		contentsOffset,
		contentsEnd + 1,
		int64(buf.Len()) - contentsEnd - 1,
	}

	// Update byte range in buffer
	byteRangeStr := fmt.Sprintf("[%010d %010d %010d %010d]",
		byteRange[0], byteRange[1], byteRange[2], byteRange[3])
	copy(buf.Bytes()[byteRangeOffset:], []byte(byteRangeStr))

	_, err := out.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}

	return &SignatureInfo{
		Data:           buf.Bytes(),
		ByteRange:      byteRange,
		ContentsOffset: contentsStart,
		ContentsSize:   placeholder.ContentsSize,
	}, nil
}
