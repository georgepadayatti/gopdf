// Package embed provides utilities for handling embedded files in PDFs.
package embed

import (
	"crypto/md5"
	"errors"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/filters"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors
var (
	ErrNoEmbeddedFile = errors.New("file spec does not have an embedded file stream")
	ErrFlatNameTree   = errors.New("only flat name trees are supported right now")
)

// EmbeddedFileParams contains parameters for embedded file metadata.
type EmbeddedFileParams struct {
	// EmbedSize records the file size of the embedded file.
	// This value is computed over the file content before PDF filters are applied.
	EmbedSize bool

	// EmbedChecksum adds an MD5 checksum of the file contents.
	// This value is computed over the file content before PDF filters are applied.
	EmbedChecksum bool

	// CreationDate records the creation date of the embedded file.
	CreationDate *time.Time

	// ModificationDate records the modification date of the embedded file.
	ModificationDate *time.Time
}

// DefaultEmbeddedFileParams returns default embedded file parameters.
func DefaultEmbeddedFileParams() *EmbeddedFileParams {
	return &EmbeddedFileParams{
		EmbedSize:     true,
		EmbedChecksum: true,
	}
}

// EmbeddedFileObject represents an embedded file stream.
type EmbeddedFileObject struct {
	*generic.StreamObject
	Params   *EmbeddedFileParams
	MimeType string
}

// NewEmbeddedFileFromData creates an embedded file object from file data.
func NewEmbeddedFileFromData(data []byte, compress bool, params *EmbeddedFileParams, mimeType string) *EmbeddedFileObject {
	if params == nil {
		params = DefaultEmbeddedFileParams()
	}

	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("EmbeddedFile"))

	if mimeType != "" {
		dict.Set("Subtype", generic.NameObject(mimeType))
	}

	stream := generic.NewStream(dict, data)

	if compress {
		encoded, err := filters.EncodeStream(data, []string{"FlateDecode"}, nil)
		if err == nil {
			stream.EncodedData = encoded
			stream.Dictionary.Set("Filter", generic.NameObject("FlateDecode"))
		}
	}

	return &EmbeddedFileObject{
		StreamObject: stream,
		Params:       params,
		MimeType:     mimeType,
	}
}

// ApplyParams applies the embedded file parameters to the stream dictionary.
func (e *EmbeddedFileObject) ApplyParams() {
	if e.Params == nil {
		return
	}

	paramDict := generic.NewDictionary()
	hasParams := false

	if e.Params.EmbedSize {
		paramDict.Set("Size", generic.IntegerObject(len(e.Data)))
		hasParams = true
	}

	if e.Params.EmbedChecksum {
		checksum := md5.Sum(e.Data)
		paramDict.Set("CheckSum", generic.NewHexString(checksum[:]))
		hasParams = true
	}

	if e.Params.CreationDate != nil {
		paramDict.Set("CreationDate", generic.NewTextString(formatPdfDate(*e.Params.CreationDate)))
		hasParams = true
	}

	if e.Params.ModificationDate != nil {
		paramDict.Set("ModDate", generic.NewTextString(formatPdfDate(*e.Params.ModificationDate)))
		hasParams = true
	}

	if hasParams {
		e.Dictionary.Set("Params", paramDict)
	}
}

// RelatedFileSpec represents a related file construct in PDF.
type RelatedFileSpec struct {
	// Name of the related file.
	Name string

	// EmbeddedData is a reference to the embedded file stream.
	EmbeddedData *EmbeddedFileObject
}

// FileSpec represents an embedded file description in a PDF.
type FileSpec struct {
	// FileSpecString is a path-like file specification string, or URL.
	// For backwards compatibility, this string should be encodable in PDFDocEncoding.
	FileSpecString string

	// FileName is a path-like Unicode file name.
	FileName string

	// EmbeddedData is a reference to a stream object containing the file's data.
	EmbeddedData *EmbeddedFileObject

	// Description is a textual description of the file.
	Description string

	// AFRelationship is the associated file relationship specifier.
	AFRelationship string

	// FRelatedFiles contains related files with PDFDocEncoded names.
	FRelatedFiles []RelatedFileSpec

	// UFRelatedFiles contains related files with Unicode-encoded names.
	UFRelatedFiles []RelatedFileSpec
}

// NewFileSpec creates a new file specification.
func NewFileSpec(fileSpecString string, embeddedData *EmbeddedFileObject) *FileSpec {
	return &FileSpec{
		FileSpecString: fileSpecString,
		EmbeddedData:   embeddedData,
	}
}

// AsPdfObject converts the file spec to a PDF dictionary.
func (f *FileSpec) AsPdfObject(embeddedRef generic.Reference) *generic.DictionaryObject {
	result := generic.NewDictionary()
	result.Set("Type", generic.NameObject("Filespec"))
	result.Set("F", generic.NewTextString(f.FileSpecString))

	if f.FileName != "" {
		result.Set("UF", generic.NewTextString(f.FileName))
	}

	if f.EmbeddedData != nil {
		efDict := generic.NewDictionary()
		efDict.Set("F", embeddedRef)

		if f.FileName != "" {
			efDict.Set("UF", embeddedRef)
		}

		result.Set("EF", efDict)
	}

	if f.Description != "" {
		result.Set("Desc", generic.NewTextString(f.Description))
	}

	if f.AFRelationship != "" {
		result.Set("AFRelationship", generic.NameObject(f.AFRelationship))
	}

	// Handle related files
	if len(f.FRelatedFiles) > 0 || len(f.UFRelatedFiles) > 0 {
		rf := generic.NewDictionary()

		if len(f.FRelatedFiles) > 0 {
			rf.Set("F", formatRelatedFiles(f.FRelatedFiles))
		}

		if len(f.UFRelatedFiles) > 0 && f.FileName != "" {
			rf.Set("UF", formatRelatedFiles(f.UFRelatedFiles))
		}

		result.Set("RF", rf)
	}

	return result
}

// formatRelatedFiles formats related files as a PDF array.
func formatRelatedFiles(files []RelatedFileSpec) generic.ArrayObject {
	arr := make(generic.ArrayObject, 0, len(files)*2)
	for _, rfs := range files {
		arr = append(arr, generic.NewTextString(rfs.Name))
		// Note: The reference would need to be added by the writer
		// This is a simplified implementation
	}
	return arr
}

// EmbeddedFileWriter provides methods for embedding files in PDFs.
type EmbeddedFileWriter struct {
	objects    []generic.PdfObject
	nextObjNum int
}

// NewEmbeddedFileWriter creates a new embedded file writer.
func NewEmbeddedFileWriter(startObjNum int) *EmbeddedFileWriter {
	return &EmbeddedFileWriter{
		objects:    make([]generic.PdfObject, 0),
		nextObjNum: startObjNum,
	}
}

// AddObject adds an object and returns its reference.
func (w *EmbeddedFileWriter) AddObject(obj generic.PdfObject) generic.Reference {
	objNum := w.nextObjNum
	w.nextObjNum++
	w.objects = append(w.objects, obj)
	return generic.Reference{ObjectNumber: objNum, GenerationNumber: 0}
}

// EmbedFile creates the embedded file objects and returns them with their references.
func (w *EmbeddedFileWriter) EmbedFile(spec *FileSpec) (*generic.DictionaryObject, generic.Reference, generic.Reference, error) {
	if spec.EmbeddedData == nil {
		return nil, generic.Reference{}, generic.Reference{}, ErrNoEmbeddedFile
	}

	// Apply parameters to the embedded file
	spec.EmbeddedData.ApplyParams()

	// Add the embedded file stream
	efStreamRef := w.AddObject(spec.EmbeddedData.StreamObject)

	// Create and add the file spec dictionary
	specObj := spec.AsPdfObject(efStreamRef)
	specObjRef := w.AddObject(specObj)

	return specObj, specObjRef, efStreamRef, nil
}

// GetObjects returns all objects added to the writer.
func (w *EmbeddedFileWriter) GetObjects() []generic.PdfObject {
	return w.objects
}

// CreateNamesDict creates or updates the Names dictionary for embedded files.
func CreateNamesDict(existingNames *generic.DictionaryObject, fileSpecString string, specRef generic.Reference) *generic.DictionaryObject {
	if existingNames == nil {
		existingNames = generic.NewDictionary()
	}

	// Get or create EmbeddedFiles entry
	var efNameTree *generic.DictionaryObject
	if ef := existingNames.GetDict("EmbeddedFiles"); ef != nil {
		efNameTree = ef
	} else {
		efNameTree = generic.NewDictionary()
		existingNames.Set("EmbeddedFiles", efNameTree)
	}

	// Get or create Names array (flat tree)
	var namesArr generic.ArrayObject
	if arr := efNameTree.GetArray("Names"); arr != nil {
		namesArr = arr
	} else {
		namesArr = generic.ArrayObject{}
	}

	// Add the new entry
	namesArr = append(namesArr, generic.NewTextString(fileSpecString))
	namesArr = append(namesArr, specRef)
	efNameTree.Set("Names", namesArr)

	return existingNames
}

// formatPdfDate formats a time as a PDF date string.
func formatPdfDate(t time.Time) string {
	_, offset := t.Zone()
	offsetHours := offset / 3600
	offsetMinutes := (offset % 3600) / 60

	sign := "+"
	if offset < 0 {
		sign = "-"
		offsetHours = -offsetHours
		offsetMinutes = -offsetMinutes
	}

	return "D:" + t.Format("20060102150405") + sign +
		padZero(offsetHours) + "'" + padZero(offsetMinutes) + "'"
}

func padZero(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// Common MIME types for embedded files
const (
	MimeTypePDF    = "application/pdf"
	MimeTypeXML    = "application/xml"
	MimeTypeText   = "text/plain"
	MimeTypeHTML   = "text/html"
	MimeTypeJPEG   = "image/jpeg"
	MimeTypePNG    = "image/png"
	MimeTypeZIP    = "application/zip"
	MimeTypeJSON   = "application/json"
	MimeTypeBinary = "application/octet-stream"
)

// Common AF relationships
const (
	AFRelationshipSource           = "Source"
	AFRelationshipData             = "Data"
	AFRelationshipAlternative      = "Alternative"
	AFRelationshipSupplement       = "Supplement"
	AFRelationshipEncryptedPayload = "EncryptedPayload"
	AFRelationshipFormData         = "FormData"
	AFRelationshipSchema           = "Schema"
	AFRelationshipUnspecified      = "Unspecified"
)
