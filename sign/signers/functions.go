// Package signers provides high-level API entry points for PDF signing.
package signers

import (
	"errors"
	"io"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/embed"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
	"github.com/georgepadayatti/gopdf/sign/fields"
	"github.com/georgepadayatti/gopdf/sign/timestamps"
)

// Common errors
var (
	ErrSigningFailed      = errors.New("signing failed")
	ErrInvalidFieldSpec   = errors.New("specifying a signature field spec is not meaningful when existing_fields_only=true")
	ErrNoSignatureField   = errors.New("signature field not found")
	ErrFieldAlreadySigned = errors.New("signature field is already signed")
	ErrSignerRequired     = errors.New("signer is required")
	ErrWriterRequired     = errors.New("PDF writer is required")
	ErrMetadataRequired   = errors.New("signature metadata is required")
)

// SigningError represents an error during the signing process.
type SigningError struct {
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *SigningError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap returns the underlying error.
func (e *SigningError) Unwrap() error {
	return e.Cause
}

// NewSigningError creates a new SigningError.
func NewSigningError(message string, cause error) *SigningError {
	return &SigningError{
		Message: message,
		Cause:   cause,
	}
}

// SignPdfOptions contains options for signing a PDF.
type SignPdfOptions struct {
	// Timestamper provides timestamps for the signature.
	Timestamper timestamps.Timestamper

	// NewFieldSpec specifies the properties of a new signature field if one is to be created.
	NewFieldSpec *fields.SigFieldSpec

	// ExistingFieldsOnly if true, never create a new empty signature field.
	ExistingFieldsOnly bool

	// BytesReserved is the number of bytes to reserve for the CMS object.
	// If not specified, an estimate is made based on a dummy signature.
	BytesReserved int

	// InPlace signs the input in-place.
	InPlace bool

	// Output is the writer for the signed output.
	// If nil, output is written to a new buffer.
	Output io.Writer
}

// DefaultSignPdfOptions returns default signing options.
func DefaultSignPdfOptions() *SignPdfOptions {
	return &SignPdfOptions{
		ExistingFieldsOnly: false,
		BytesReserved:      0,
		InPlace:            false,
	}
}

// SignPdf is a convenience wrapper around PdfSigner.SignPdf.
// It signs a PDF document and returns the signed output.
func SignPdf(
	pdfWriter *writer.IncrementalPdfFileWriter,
	metadata *SignatureMetadata,
	signer Signer,
	opts *SignPdfOptions,
) ([]byte, error) {
	if opts == nil {
		opts = DefaultSignPdfOptions()
	}

	// Validate options
	if opts.NewFieldSpec != nil && opts.ExistingFieldsOnly {
		return nil, ErrInvalidFieldSpec
	}

	if signer == nil {
		return nil, ErrSignerRequired
	}

	if metadata == nil {
		return nil, ErrMetadataRequired
	}

	if pdfWriter == nil {
		return nil, ErrWriterRequired
	}

	// Create PDF signer
	pdfSigner := NewPdfSigner(signer, metadata)

	// Determine bytes to reserve
	bytesReserved := opts.BytesReserved
	if bytesReserved <= 0 {
		bytesReserved = signer.GetSignatureSize()
	}

	// If timestamper is provided, add extra space for timestamp token
	if opts.Timestamper != nil {
		bytesReserved += 8192 // Extra space for timestamp
	}

	// Sign the PDF using the underlying reader
	return pdfSigner.SignPdf(pdfWriter.Reader)
}

// SignPdfFromReader is a convenience function to sign a PDF from a reader.
func SignPdfFromReader(
	pdfReader *reader.PdfFileReader,
	metadata *SignatureMetadata,
	signer Signer,
	opts *SignPdfOptions,
) ([]byte, error) {
	if opts == nil {
		opts = DefaultSignPdfOptions()
	}

	if signer == nil {
		return nil, ErrSignerRequired
	}

	if metadata == nil {
		return nil, ErrMetadataRequired
	}

	if pdfReader == nil {
		return nil, errors.New("PDF reader is required")
	}

	// Create PDF signer
	pdfSigner := NewPdfSigner(signer, metadata)

	// Sign the PDF
	return pdfSigner.SignPdf(pdfReader)
}

// SignPdfBytes signs PDF data and returns the signed PDF bytes.
func SignPdfBytes(
	pdfData []byte,
	metadata *SignatureMetadata,
	signer Signer,
	opts *SignPdfOptions,
) ([]byte, error) {
	// Parse PDF
	pdfReader, err := reader.NewPdfFileReaderFromBytes(pdfData)
	if err != nil {
		return nil, NewSigningError("failed to parse PDF", err)
	}

	return SignPdfFromReader(pdfReader, metadata, signer, opts)
}

// EmbedPayloadWithCMSOptions contains options for embedding a payload with CMS.
type EmbedPayloadWithCMSOptions struct {
	// Extension is the file extension for the CMS attachment (default: ".sig").
	Extension string

	// FileName is the Unicode file name (optional).
	FileName string

	// FileSpecDescription is the description for the main file spec.
	FileSpecDescription string

	// CMSFileSpecDescription is the description for the CMS file spec.
	CMSFileSpecDescription string

	// AFRelationship is the associated file relationship for the main file.
	AFRelationship string

	// CMSAFRelationship is the associated file relationship for the CMS file.
	CMSAFRelationship string
}

// DefaultEmbedPayloadWithCMSOptions returns default options.
func DefaultEmbedPayloadWithCMSOptions() *EmbedPayloadWithCMSOptions {
	return &EmbedPayloadWithCMSOptions{
		Extension: ".sig",
	}
}

// EmbedPayloadWithCMS embeds data as an embedded file stream into a PDF,
// and associates it with a CMS object.
//
// The CMS object is also embedded as a file and associated with the original
// payload through a related file relationship.
//
// This can be used to bundle (non-PDF) detached signatures with PDF attachments.
func EmbedPayloadWithCMS(
	pdfWriter *writer.PdfFileWriter,
	fileSpecString string,
	payload *embed.EmbeddedFileObject,
	cmsData []byte,
	opts *EmbedPayloadWithCMSOptions,
) error {
	if opts == nil {
		opts = DefaultEmbedPayloadWithCMSOptions()
	}

	if pdfWriter == nil {
		return errors.New("PDF writer is required")
	}

	if payload == nil {
		return errors.New("payload is required")
	}

	if len(cmsData) == 0 {
		return errors.New("CMS data is required")
	}

	// Create embedded file object for the CMS signature
	now := time.Now()
	cmsParams := &embed.EmbeddedFileParams{
		EmbedSize:        true,
		EmbedChecksum:    true,
		CreationDate:     &now,
		ModificationDate: &now,
	}

	cmsEfObj := embed.NewEmbeddedFileFromData(cmsData, false, cmsParams, "application/pkcs7-mime")

	// Replace extension in file spec string
	cmsDataF := replaceExtension(fileSpecString, opts.Extension)

	// Deal with Unicode file names
	var cmsDataUF string
	var ufRelatedFiles []embed.RelatedFileSpec

	if opts.FileName != "" {
		cmsDataUF = replaceExtension(opts.FileName, opts.Extension)
		ufRelatedFiles = []embed.RelatedFileSpec{
			{Name: cmsDataUF, EmbeddedData: cmsEfObj},
		}
	}

	// Create file spec for the main payload
	spec := &embed.FileSpec{
		FileSpecString: fileSpecString,
		FileName:       opts.FileName,
		EmbeddedData:   payload,
		Description:    opts.FileSpecDescription,
		AFRelationship: opts.AFRelationship,
		FRelatedFiles: []embed.RelatedFileSpec{
			{Name: cmsDataF, EmbeddedData: cmsEfObj},
		},
		UFRelatedFiles: ufRelatedFiles,
	}

	// Embed the main file
	// Use the number of existing objects + 1 as the starting object number
	embedWriter := embed.NewEmbeddedFileWriter(len(pdfWriter.Objects) + 1)
	_, _, _, err := embedWriter.EmbedFile(spec)
	if err != nil {
		return NewSigningError("failed to embed main file", err)
	}

	// Create file spec for the CMS attachment
	cmsSpec := &embed.FileSpec{
		FileSpecString: cmsDataF,
		FileName:       cmsDataUF,
		EmbeddedData:   cmsEfObj,
		Description:    opts.CMSFileSpecDescription,
		AFRelationship: opts.CMSAFRelationship,
	}

	// Embed the CMS file
	_, _, _, err = embedWriter.EmbedFile(cmsSpec)
	if err != nil {
		return NewSigningError("failed to embed CMS file", err)
	}

	return nil
}

// replaceExtension replaces the file extension in a path.
func replaceExtension(path, newExt string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[:i] + newExt
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	return path + newExt
}

// QuickSign provides a simplified interface for signing a PDF.
type QuickSign struct {
	Signer      Signer
	Metadata    *SignatureMetadata
	Timestamper timestamps.Timestamper
}

// NewQuickSign creates a new QuickSign helper.
func NewQuickSign(signer Signer, fieldName string) *QuickSign {
	return &QuickSign{
		Signer:   signer,
		Metadata: NewSignatureMetadata(fieldName),
	}
}

// WithReason sets the signature reason.
func (q *QuickSign) WithReason(reason string) *QuickSign {
	q.Metadata.Reason = reason
	return q
}

// WithLocation sets the signature location.
func (q *QuickSign) WithLocation(location string) *QuickSign {
	q.Metadata.Location = location
	return q
}

// WithTimestamper sets the timestamper.
func (q *QuickSign) WithTimestamper(ts timestamps.Timestamper) *QuickSign {
	q.Timestamper = ts
	return q
}

// Sign signs the PDF bytes and returns the signed output.
func (q *QuickSign) Sign(pdfData []byte) ([]byte, error) {
	opts := DefaultSignPdfOptions()
	if q.Timestamper != nil {
		opts.Timestamper = q.Timestamper
	}
	return SignPdfBytes(pdfData, q.Metadata, q.Signer, opts)
}

// SignReader signs a PDF from a reader.
func (q *QuickSign) SignReader(pdfReader *reader.PdfFileReader) ([]byte, error) {
	opts := DefaultSignPdfOptions()
	if q.Timestamper != nil {
		opts.Timestamper = q.Timestamper
	}
	return SignPdfFromReader(pdfReader, q.Metadata, q.Signer, opts)
}
