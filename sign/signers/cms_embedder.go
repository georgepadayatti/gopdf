// Package signers provides CMS embedding for PDF signatures.
package signers

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors for CMS embedding.
var (
	ErrNoFieldName            = errors.New("field name required when existing_fields_only is false")
	ErrNoEmptySignatureFields = errors.New("no empty signature fields found")
	ErrMultipleEmptyFields    = errors.New("multiple empty signature fields found - specify field name")
	ErrSignatureFieldFilled   = errors.New("signature field is already filled")
	ErrDocumentNotWritten     = errors.New("document not written - call WriteDocument first")
	ErrInvalidByteRange       = errors.New("invalid byte range")
	ErrSignatureTooLarge      = errors.New("signature too large for allocated space")
)

// FieldMDPAction specifies the action for FieldMDP.
type FieldMDPAction string

const (
	// FieldMDPActionAll locks all fields.
	FieldMDPActionAll FieldMDPAction = "All"
	// FieldMDPActionInclude locks only specified fields.
	FieldMDPActionInclude FieldMDPAction = "Include"
	// FieldMDPActionExclude locks all except specified fields.
	FieldMDPActionExclude FieldMDPAction = "Exclude"
)

// FieldMDPSpec specifies field-level modification permissions.
type FieldMDPSpec struct {
	// Action specifies the field lock action.
	Action FieldMDPAction

	// Fields are the field names affected by the action.
	Fields []string
}

// NewFieldMDPSpec creates a new FieldMDPSpec.
func NewFieldMDPSpec(action FieldMDPAction, fields []string) *FieldMDPSpec {
	return &FieldMDPSpec{
		Action: action,
		Fields: fields,
	}
}

// AsTransformParams returns the transform parameters dictionary.
func (s *FieldMDPSpec) AsTransformParams() *generic.DictionaryObject {
	params := generic.NewDictionary()
	params.Set("Type", generic.NameObject("TransformParams"))
	params.Set("Action", generic.NameObject(string(s.Action)))
	params.Set("V", generic.NameObject("1.2"))

	if len(s.Fields) > 0 {
		fieldsArray := generic.ArrayObject{}
		for _, f := range s.Fields {
			fieldsArray = append(fieldsArray, generic.NewTextString(f))
		}
		params.Set("Fields", fieldsArray)
	}

	return params
}

// SigMDPSetup contains DocMDP setup parameters for signatures.
type SigMDPSetup struct {
	// MDAlgorithm is the message digest algorithm for the signature reference dictionary.
	MDAlgorithm string

	// Certify indicates whether this is a certification signature.
	// A document can have at most one certification signature, and it must be first.
	Certify bool

	// FieldLock contains field lock information for the signature reference dictionary.
	FieldLock *FieldMDPSpec

	// DocMDPPerms contains DocMDP permissions for the signature reference dictionary.
	DocMDPPerms *MDPPermission
}

// NewSigMDPSetup creates a new SigMDPSetup with defaults.
func NewSigMDPSetup(mdAlgorithm string) *SigMDPSetup {
	return &SigMDPSetup{
		MDAlgorithm: mdAlgorithm,
	}
}

// AsCertification configures as a certification signature.
func (s *SigMDPSetup) AsCertification(perms MDPPermission) *SigMDPSetup {
	s.Certify = true
	s.DocMDPPerms = &perms
	return s
}

// WithFieldLock adds field lock specification.
func (s *SigMDPSetup) WithFieldLock(spec *FieldMDPSpec) *SigMDPSetup {
	s.FieldLock = spec
	return s
}

// CreateDocMDPReferenceDictionary creates a DocMDP reference dictionary.
func CreateDocMDPReferenceDictionary(permission MDPPermission) *generic.DictionaryObject {
	transformParams := generic.NewDictionary()
	transformParams.Set("Type", generic.NameObject("TransformParams"))
	transformParams.Set("V", generic.NameObject("1.2"))
	transformParams.Set("P", generic.IntegerObject(int(permission)))

	refDict := generic.NewDictionary()
	refDict.Set("Type", generic.NameObject("SigRef"))
	refDict.Set("TransformMethod", generic.NameObject("DocMDP"))
	refDict.Set("TransformParams", transformParams)

	return refDict
}

// CreateFieldMDPReferenceDictionary creates a FieldMDP reference dictionary.
func CreateFieldMDPReferenceDictionary(spec *FieldMDPSpec, dataRef generic.PdfObject) *generic.DictionaryObject {
	refDict := generic.NewDictionary()
	refDict.Set("Type", generic.NameObject("SigRef"))
	refDict.Set("TransformMethod", generic.NameObject("FieldMDP"))
	refDict.Set("Data", dataRef)
	refDict.Set("TransformParams", spec.AsTransformParams())

	return refDict
}

// SigAppearanceSetup contains signature appearance configuration.
type SigAppearanceSetup struct {
	// Timestamp is the timestamp to show in the appearance.
	Timestamp time.Time

	// Name is the signer name to show in the appearance.
	Name string

	// TextParams are additional text interpolation parameters.
	TextParams map[string]string

	// TimestampFormat is the format for displaying timestamps.
	TimestampFormat string
}

// NewSigAppearanceSetup creates a new appearance setup.
func NewSigAppearanceSetup(timestamp time.Time, name string) *SigAppearanceSetup {
	return &SigAppearanceSetup{
		Timestamp:       timestamp,
		Name:            name,
		TimestampFormat: "2006-01-02 15:04:05",
	}
}

// WithTextParam adds a text parameter.
func (s *SigAppearanceSetup) WithTextParam(key, value string) *SigAppearanceSetup {
	if s.TextParams == nil {
		s.TextParams = make(map[string]string)
	}
	s.TextParams[key] = value
	return s
}

// WithTimestampFormat sets the timestamp format.
func (s *SigAppearanceSetup) WithTimestampFormat(format string) *SigAppearanceSetup {
	s.TimestampFormat = format
	return s
}

// GetTextParams returns all text parameters for the appearance.
func (s *SigAppearanceSetup) GetTextParams() map[string]string {
	params := make(map[string]string)
	if s.Name != "" {
		params["signer"] = s.Name
	}
	params["ts"] = s.Timestamp.Format(s.TimestampFormat)
	for k, v := range s.TextParams {
		params[k] = v
	}
	return params
}

// SigObjSetup describes the signature dictionary to embed.
type SigObjSetup struct {
	// SigDict is the signature dictionary to embed.
	SigDict *generic.DictionaryObject

	// ContentsSize is the size to allocate for the signature.
	ContentsSize int

	// MDPSetup contains optional DocMDP settings.
	MDPSetup *SigMDPSetup

	// AppearanceSetup contains optional appearance settings.
	AppearanceSetup *SigAppearanceSetup
}

// NewSigObjSetup creates a new signature object setup.
func NewSigObjSetup(sigDict *generic.DictionaryObject, contentsSize int) *SigObjSetup {
	return &SigObjSetup{
		SigDict:      sigDict,
		ContentsSize: contentsSize,
	}
}

// WithMDPSetup adds MDP configuration.
func (s *SigObjSetup) WithMDPSetup(mdp *SigMDPSetup) *SigObjSetup {
	s.MDPSetup = mdp
	return s
}

// WithAppearance adds appearance configuration.
func (s *SigObjSetup) WithAppearance(appearance *SigAppearanceSetup) *SigObjSetup {
	s.AppearanceSetup = appearance
	return s
}

// SigIOSetup contains I/O settings for writing signed PDF documents.
type SigIOSetup struct {
	// MDAlgorithm is the message digest algorithm to compute document hash.
	MDAlgorithm crypto.Hash

	// InPlace signs the input in-place if true.
	InPlace bool

	// ChunkSize is the buffer size for feeding data to the digest function.
	ChunkSize int

	// Output is the output stream (nil means create new buffer).
	Output io.Writer
}

// DefaultChunkSize is the default chunk size for digest computation.
const DefaultChunkSize = 4096

// NewSigIOSetup creates a new I/O setup with defaults.
func NewSigIOSetup(mdAlgorithm crypto.Hash) *SigIOSetup {
	return &SigIOSetup{
		MDAlgorithm: mdAlgorithm,
		ChunkSize:   DefaultChunkSize,
	}
}

// WithOutput sets the output writer.
func (s *SigIOSetup) WithOutput(output io.Writer) *SigIOSetup {
	s.Output = output
	return s
}

// WithInPlace enables in-place signing.
func (s *SigIOSetup) WithInPlace() *SigIOSetup {
	s.InPlace = true
	return s
}

// PreparedByteRangeDigest contains the document digest and byte range info.
type PreparedByteRangeDigest struct {
	// Digest is the computed document hash.
	Digest []byte

	// ByteRange contains the byte range offsets [start1, len1, start2, len2].
	ByteRange []int64

	// Algorithm is the hash algorithm used.
	Algorithm crypto.Hash
}

// NewPreparedByteRangeDigest creates a new prepared digest.
func NewPreparedByteRangeDigest(digest []byte, byteRange []int64, algorithm crypto.Hash) *PreparedByteRangeDigest {
	return &PreparedByteRangeDigest{
		Digest:    digest,
		ByteRange: byteRange,
		Algorithm: algorithm,
	}
}

// SignatureContents computes the data that should be signed.
func (p *PreparedByteRangeDigest) SignatureContents(document []byte) []byte {
	if len(p.ByteRange) != 4 {
		return nil
	}

	result := make([]byte, 0, p.ByteRange[1]+p.ByteRange[3])
	result = append(result, document[p.ByteRange[0]:p.ByteRange[0]+p.ByteRange[1]]...)
	result = append(result, document[p.ByteRange[2]:p.ByteRange[2]+p.ByteRange[3]]...)
	return result
}

// PdfCMSEmbedder handles embedding CMS objects into PDF signature fields.
type PdfCMSEmbedder struct {
	// NewFieldBox is the box for new signature fields.
	NewFieldBox *generic.Rectangle

	// NewFieldPage is the page number for new signature fields.
	NewFieldPage int
}

// NewPdfCMSEmbedder creates a new CMS embedder.
func NewPdfCMSEmbedder() *PdfCMSEmbedder {
	return &PdfCMSEmbedder{
		NewFieldPage: 0,
	}
}

// WithNewFieldBox sets the box for new signature fields.
func (e *PdfCMSEmbedder) WithNewFieldBox(box *generic.Rectangle) *PdfCMSEmbedder {
	e.NewFieldBox = box
	return e
}

// WithNewFieldPage sets the page for new signature fields.
func (e *PdfCMSEmbedder) WithNewFieldPage(page int) *PdfCMSEmbedder {
	e.NewFieldPage = page
	return e
}

// EmbedSignatureInBytes embeds a signature into PDF bytes at the specified byte range.
func EmbedSignatureInBytes(pdfBytes []byte, byteRange []int64, signature []byte) ([]byte, error) {
	if len(byteRange) != 4 {
		return nil, ErrInvalidByteRange
	}

	// Calculate the position for the signature
	sigStart := byteRange[0] + byteRange[1]
	sigEnd := byteRange[2]
	availableSpace := sigEnd - sigStart - 2 // Exclude < and > markers

	// Encode signature as hex
	hexSig := fmt.Sprintf("%X", signature)

	// Check if signature fits
	if int64(len(hexSig)) > availableSpace {
		return nil, fmt.Errorf("%w: need %d bytes, have %d", ErrSignatureTooLarge, len(hexSig), availableSpace)
	}

	// Pad with zeros
	paddingNeeded := int(availableSpace) - len(hexSig)
	paddedHex := hexSig + strings.Repeat("0", paddingNeeded)

	// Create result
	result := make([]byte, len(pdfBytes))
	copy(result, pdfBytes)

	// Insert signature (after the '<' character)
	copy(result[sigStart+1:], []byte(paddedHex))

	return result, nil
}

// CMSEmbeddingResult contains the result of a CMS embedding operation.
type CMSEmbeddingResult struct {
	// SignedDocument is the signed PDF document.
	SignedDocument []byte

	// ByteRange is the byte range that was signed.
	ByteRange []int64

	// Digest is the document digest.
	Digest []byte
}

// ComputeByteRangeDigest computes the digest for a byte range in a PDF document.
func ComputeByteRangeDigest(document []byte, byteRange []int64, algorithm crypto.Hash) ([]byte, error) {
	if len(byteRange) != 4 {
		return nil, ErrInvalidByteRange
	}

	h := algorithm.New()

	// Hash first part
	start1 := byteRange[0]
	end1 := byteRange[0] + byteRange[1]
	if start1 < 0 || end1 > int64(len(document)) {
		return nil, fmt.Errorf("byte range part 1 out of bounds: [%d:%d]", start1, end1)
	}
	h.Write(document[start1:end1])

	// Hash second part
	start2 := byteRange[2]
	end2 := byteRange[2] + byteRange[3]
	if start2 < 0 || end2 > int64(len(document)) {
		return nil, fmt.Errorf("byte range part 2 out of bounds: [%d:%d]", start2, end2)
	}
	h.Write(document[start2:end2])

	return h.Sum(nil), nil
}

// SignatureObjectBuilder helps build signature dictionary objects.
type SignatureObjectBuilder struct {
	sigDict *generic.DictionaryObject
}

// NewSignatureObjectBuilder creates a new signature object builder.
func NewSignatureObjectBuilder() *SignatureObjectBuilder {
	sigDict := generic.NewDictionary()
	sigDict.Set("Type", generic.NameObject("Sig"))
	sigDict.Set("Filter", generic.NameObject("Adobe.PPKLite"))
	sigDict.Set("SubFilter", generic.NameObject("adbe.pkcs7.detached"))

	return &SignatureObjectBuilder{
		sigDict: sigDict,
	}
}

// WithSubFilter sets the SubFilter.
func (b *SignatureObjectBuilder) WithSubFilter(subFilter string) *SignatureObjectBuilder {
	b.sigDict.Set("SubFilter", generic.NameObject(subFilter))
	return b
}

// WithReason sets the reason for signing.
func (b *SignatureObjectBuilder) WithReason(reason string) *SignatureObjectBuilder {
	b.sigDict.Set("Reason", generic.NewTextString(reason))
	return b
}

// WithLocation sets the signing location.
func (b *SignatureObjectBuilder) WithLocation(location string) *SignatureObjectBuilder {
	b.sigDict.Set("Location", generic.NewTextString(location))
	return b
}

// WithContactInfo sets the contact info.
func (b *SignatureObjectBuilder) WithContactInfo(contactInfo string) *SignatureObjectBuilder {
	b.sigDict.Set("ContactInfo", generic.NewTextString(contactInfo))
	return b
}

// WithName sets the signer name.
func (b *SignatureObjectBuilder) WithName(name string) *SignatureObjectBuilder {
	b.sigDict.Set("Name", generic.NewTextString(name))
	return b
}

// WithSigningTime sets the signing time.
func (b *SignatureObjectBuilder) WithSigningTime(t time.Time) *SignatureObjectBuilder {
	b.sigDict.Set("M", generic.NewTextString(FormatPDFDate(t)))
	return b
}

// WithContentsPlaceholder sets the contents placeholder.
func (b *SignatureObjectBuilder) WithContentsPlaceholder(size int) *SignatureObjectBuilder {
	placeholder := bytes.Repeat([]byte{0}, size)
	b.sigDict.Set("Contents", generic.NewHexString(placeholder))
	return b
}

// WithByteRangePlaceholder sets the byte range placeholder.
func (b *SignatureObjectBuilder) WithByteRangePlaceholder() *SignatureObjectBuilder {
	b.sigDict.Set("ByteRange", generic.ArrayObject{
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
	})
	return b
}

// Build returns the constructed signature dictionary.
func (b *SignatureObjectBuilder) Build() *generic.DictionaryObject {
	return b.sigDict
}

// FormatPDFDate formats a time as a PDF date string.
func FormatPDFDate(t time.Time) string {
	_, offset := t.Zone()
	offsetHours := offset / 3600
	offsetMinutes := (offset % 3600) / 60

	sign := "+"
	if offset < 0 {
		sign = "-"
		offsetHours = -offsetHours
		offsetMinutes = -offsetMinutes
	}

	return fmt.Sprintf("D:%04d%02d%02d%02d%02d%02d%s%02d'%02d'",
		t.Year(), int(t.Month()), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
		sign, offsetHours, offsetMinutes)
}

// ParsePDFDate parses a PDF date string.
func ParsePDFDate(s string) (time.Time, error) {
	// PDF date format: D:YYYYMMDDHHmmSS+HH'mm'
	if len(s) < 2 || s[:2] != "D:" {
		return time.Time{}, fmt.Errorf("invalid PDF date format: %s", s)
	}

	s = s[2:] // Remove "D:" prefix

	if len(s) == 0 {
		return time.Time{}, fmt.Errorf("invalid PDF date format: empty date")
	}

	// Remove quotes from timezone
	s = strings.ReplaceAll(s, "'", "")

	// Parse with various possible lengths
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
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse PDF date: %s", s)
}

// DocumentTimestampBuilder builds document timestamp dictionaries.
type DocumentTimestampBuilder struct {
	*SignatureObjectBuilder
}

// NewDocumentTimestampBuilder creates a new document timestamp builder.
func NewDocumentTimestampBuilder() *DocumentTimestampBuilder {
	builder := NewSignatureObjectBuilder()
	builder.sigDict.Set("Type", generic.NameObject("DocTimeStamp"))
	builder.sigDict.Set("SubFilter", generic.NameObject("ETSI.RFC3161"))
	return &DocumentTimestampBuilder{builder}
}
