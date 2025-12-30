// Package signers provides low-level building blocks for ByteRange digests in PDF files.
package signers

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/sign/fields"
)

// SigAuthType represents the method of user authentication.
type SigAuthType string

const (
	// SigAuthTypePassword indicates password authentication.
	SigAuthTypePassword SigAuthType = "password"
	// SigAuthTypePIN indicates PIN authentication.
	SigAuthTypePIN SigAuthType = "pin"
	// SigAuthTypeFingerprint indicates fingerprint authentication.
	SigAuthTypeFingerprint SigAuthType = "fingerprint"
)

// ByteRangeArrayPlaceholderLength is the length of the ByteRange placeholder.
const ByteRangeArrayPlaceholderLength = 60

// SigByteRangeObject handles ByteRange arrays in signature dictionaries.
type SigByteRangeObject struct {
	filled             bool
	rangeObjectOffset  int64
	FirstRegionLen     int64
	SecondRegionOffset int64
	SecondRegionLen    int64
}

// NewSigByteRangeObject creates a new ByteRange object.
func NewSigByteRangeObject() *SigByteRangeObject {
	return &SigByteRangeObject{
		rangeObjectOffset: -1,
	}
}

// FillOffsets fills in the actual byte range values.
func (s *SigByteRangeObject) FillOffsets(stream io.WriteSeeker, sigStart, sigEnd, eof int64) error {
	if s.filled {
		return fmt.Errorf("offsets already filled")
	}
	if s.rangeObjectOffset < 0 {
		return fmt.Errorf("could not determine where to write /ByteRange value")
	}

	oldPos, err := stream.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	s.FirstRegionLen = sigStart
	s.SecondRegionOffset = sigEnd
	s.SecondRegionLen = eof - sigEnd

	// Write to the placeholder position
	if _, err := stream.Seek(s.rangeObjectOffset, io.SeekStart); err != nil {
		return err
	}

	if err := s.WriteToStream(stream); err != nil {
		return err
	}

	if _, err := stream.Seek(oldPos, io.SeekStart); err != nil {
		return err
	}

	s.filled = true
	return nil
}

// WriteToStream writes the ByteRange array to the stream.
func (s *SigByteRangeObject) WriteToStream(stream io.Writer) error {
	if s.rangeObjectOffset < 0 {
		// First call - get position and write placeholder
		if seeker, ok := stream.(io.Seeker); ok {
			pos, err := seeker.Seek(0, io.SeekCurrent)
			if err == nil {
				s.rangeObjectOffset = pos
			}
		}
		// Write empty placeholder
		placeholder := "[]" + strings.Repeat(" ", ByteRangeArrayPlaceholderLength)
		_, err := stream.Write([]byte(placeholder))
		return err
	}

	// Write actual values
	stringRepr := fmt.Sprintf("[%d %d %d %d]", 0, s.FirstRegionLen, s.SecondRegionOffset, s.SecondRegionLen)
	if len(stringRepr) > ByteRangeArrayPlaceholderLength+2 {
		return fmt.Errorf("byte range string too long: %d > %d", len(stringRepr), ByteRangeArrayPlaceholderLength+2)
	}
	_, err := stream.Write([]byte(stringRepr))
	return err
}

// GetByteRange returns the byte range as an array [start1, len1, start2, len2].
func (s *SigByteRangeObject) GetByteRange() []int64 {
	return []int64{0, s.FirstRegionLen, s.SecondRegionOffset, s.SecondRegionLen}
}

// DERPlaceholder handles placeholders for DER content in signatures.
type DERPlaceholder struct {
	Value       []byte
	StartOffset int64
	EndOffset   int64
	hasOffsets  bool
}

// NewDERPlaceholder creates a new DER placeholder.
func NewDERPlaceholder(bytesReserved int) *DERPlaceholder {
	if bytesReserved <= 0 {
		bytesReserved = 16 * 1024 // 16 KiB default
	}
	return &DERPlaceholder{
		Value: make([]byte, bytesReserved),
	}
}

// WriteToStream writes the placeholder to the stream.
func (d *DERPlaceholder) WriteToStream(stream io.Writer) error {
	start := int64(0)
	if seeker, ok := stream.(io.Seeker); ok {
		pos, err := seeker.Seek(0, io.SeekCurrent)
		if err == nil {
			start = pos
		}
	}

	hexValue := hex.EncodeToString(d.Value)
	data := "<" + strings.ToUpper(hexValue) + ">"
	n, err := stream.Write([]byte(data))
	if err != nil {
		return err
	}

	if !d.hasOffsets {
		d.StartOffset = start
		d.EndOffset = start + int64(n)
		d.hasOffsets = true
	}

	return nil
}

// Offsets returns the start and end offsets of the placeholder.
func (d *DERPlaceholder) Offsets() (int64, int64, error) {
	if !d.hasOffsets {
		return 0, 0, fmt.Errorf("no offsets available")
	}
	return d.StartOffset, d.EndOffset, nil
}

// BuildProps contains entries in a signature build properties dictionary.
// See Adobe PDF Signature Build Dictionary Specification.
type BuildProps struct {
	// Name is the application's name.
	Name string

	// Revision is the application's revision ID string (REx entry).
	Revision string
}

// NewBuildProps creates new build properties.
func NewBuildProps(name string) *BuildProps {
	return &BuildProps{
		Name: name,
	}
}

// WithRevision sets the revision.
func (b *BuildProps) WithRevision(revision string) *BuildProps {
	b.Revision = revision
	return b
}

// AsPdfObject renders the build properties as a PDF dictionary.
func (b *BuildProps) AsPdfObject() *generic.DictionaryObject {
	props := generic.NewDictionary()
	props.Set("Name", generic.NameObject("/"+b.Name))
	if b.Revision != "" {
		props.Set("REx", generic.NewTextString(b.Revision))
	}
	return props
}

// PdfSignedData is a generic class for signature dictionaries in PDFs.
type PdfSignedData struct {
	*generic.DictionaryObject
	Contents  *DERPlaceholder
	ByteRange *SigByteRangeObject
	DataKey   string
}

// NewPdfSignedData creates a new PDF signed data dictionary.
func NewPdfSignedData(objType string, subFilter fields.SigSeedSubFilter, timestamp *time.Time, bytesReserved int) *PdfSignedData {
	dict := generic.NewDictionary()

	contents := NewDERPlaceholder(bytesReserved)
	byteRange := NewSigByteRangeObject()

	dict.Set("Type", generic.NameObject(objType))
	dict.Set("Filter", generic.NameObject("Adobe.PPKLite"))
	dict.Set("SubFilter", generic.NameObject(string(subFilter)))

	if timestamp != nil {
		dict.Set("M", generic.NewTextString(FormatPDFDate(*timestamp)))
	}

	return &PdfSignedData{
		DictionaryObject: dict,
		Contents:         contents,
		ByteRange:        byteRange,
		DataKey:          "Contents",
	}
}

// SignatureObject represents a placeholder for a regular PDF signature.
type SignatureObject struct {
	*PdfSignedData
}

// SignatureObjectOptions contains options for creating a signature object.
type SignatureObjectOptions struct {
	Timestamp     *time.Time
	SubFilter     fields.SigSeedSubFilter
	Name          string
	Location      string
	Reason        string
	ContactInfo   string
	AppBuildProps *BuildProps
	PropAuthTime  int
	PropAuthType  *SigAuthType
	BytesReserved int
}

// DefaultSignatureObjectOptions returns default options.
func DefaultSignatureObjectOptions() *SignatureObjectOptions {
	return &SignatureObjectOptions{
		SubFilter:     DefaultSigSubFilter,
		BytesReserved: 16 * 1024,
	}
}

// NewSignatureObject creates a new signature object placeholder.
func NewSignatureObject(opts *SignatureObjectOptions) *SignatureObject {
	if opts == nil {
		opts = DefaultSignatureObjectOptions()
	}

	signedData := NewPdfSignedData("/Sig", opts.SubFilter, opts.Timestamp, opts.BytesReserved)

	if opts.Name != "" {
		signedData.Set("Name", generic.NewTextString(opts.Name))
	}
	if opts.Location != "" {
		signedData.Set("Location", generic.NewTextString(opts.Location))
	}
	if opts.Reason != "" {
		signedData.Set("Reason", generic.NewTextString(opts.Reason))
	}
	if opts.ContactInfo != "" {
		signedData.Set("ContactInfo", generic.NewTextString(opts.ContactInfo))
	}
	if opts.AppBuildProps != nil {
		propBuild := generic.NewDictionary()
		propBuild.Set("App", opts.AppBuildProps.AsPdfObject())
		signedData.Set("Prop_Build", propBuild)
	}
	if opts.PropAuthTime > 0 {
		signedData.Set("Prop_AuthTime", generic.IntegerObject(opts.PropAuthTime))
	}
	if opts.PropAuthType != nil {
		signedData.Set("Prop_AuthType", generic.NameObject(string(*opts.PropAuthType)))
	}

	return &SignatureObject{
		PdfSignedData: signedData,
	}
}

// DocumentTimestampObject represents a placeholder for a document timestamp.
type DocumentTimestampObject struct {
	*PdfSignedData
}

// NewDocumentTimestampObject creates a new document timestamp placeholder.
func NewDocumentTimestampObject(bytesReserved int) *DocumentTimestampObject {
	if bytesReserved <= 0 {
		bytesReserved = 16 * 1024
	}

	signedData := NewPdfSignedData("/DocTimeStamp", fields.SubFilterETSIRFC3161, nil, bytesReserved)

	return &DocumentTimestampObject{
		PdfSignedData: signedData,
	}
}

// FillReservedRegion writes hex-encoded contents to the reserved region.
func FillReservedRegion(output io.WriteSeeker, start, end int64, contentBytes []byte) ([]byte, error) {
	contentHex := strings.ToUpper(hex.EncodeToString(contentBytes))

	bytesReserved := end - start - 2 // Exclude < and >
	length := int64(len(contentHex))

	if length > bytesReserved {
		return nil, fmt.Errorf("final ByteRange payload larger than expected: allocated %d bytes, but contents required %d bytes", bytesReserved, length)
	}

	// Seek to position after '<'
	if _, err := output.Seek(start+1, io.SeekStart); err != nil {
		return nil, err
	}

	// Write hex content
	if _, err := output.Write([]byte(contentHex)); err != nil {
		return nil, err
	}

	// Return content with padding
	padding := make([]byte, int(bytesReserved)/2-len(contentBytes))
	result := append(contentBytes, padding...)
	return result, nil
}

// FillWithCMS writes a CMS object to the reserved region.
func FillWithCMS(output io.WriteSeeker, start, end int64, cmsData []byte) ([]byte, error) {
	return FillReservedRegion(output, start, end, cmsData)
}

// ExtendedPreparedByteRangeDigest extends PreparedByteRangeDigest with fill methods.
type ExtendedPreparedByteRangeDigest struct {
	*PreparedByteRangeDigest
}

// NewExtendedPreparedByteRangeDigest creates an extended prepared digest.
func NewExtendedPreparedByteRangeDigest(digest []byte, reservedStart, reservedEnd int64) *ExtendedPreparedByteRangeDigest {
	byteRange := []int64{0, reservedStart, reservedEnd, 0}

	return &ExtendedPreparedByteRangeDigest{
		PreparedByteRangeDigest: &PreparedByteRangeDigest{
			Digest:    digest,
			ByteRange: byteRange,
		},
	}
}

// FillWithCMS writes a CMS object to the reserved region.
func (p *ExtendedPreparedByteRangeDigest) FillWithCMS(output io.WriteSeeker, cmsData []byte) ([]byte, error) {
	if len(p.ByteRange) != 4 {
		return nil, ErrInvalidByteRange
	}
	start := p.ByteRange[1] // End of first region = start of signature
	end := p.ByteRange[2]   // Start of second region = end of signature
	return FillWithCMS(output, start, end, cmsData)
}

// ReservedRegionStart returns the start of the reserved region.
func (p *ExtendedPreparedByteRangeDigest) ReservedRegionStart() int64 {
	if len(p.ByteRange) >= 2 {
		return p.ByteRange[1]
	}
	return 0
}

// ReservedRegionEnd returns the end of the reserved region.
func (p *ExtendedPreparedByteRangeDigest) ReservedRegionEnd() int64 {
	if len(p.ByteRange) >= 3 {
		return p.ByteRange[2]
	}
	return 0
}
