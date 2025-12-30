// Package signers provides PDF signing functionality.
package signers

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
	"github.com/georgepadayatti/gopdf/pdf/reader"
	"github.com/georgepadayatti/gopdf/pdf/writer"
	"github.com/georgepadayatti/gopdf/sign/cms"
)

// SigDSSPlacementPreference indicates where to perform DSS updates.
type SigDSSPlacementPreference int

const (
	// DSSPlacementWithSignature updates DSS in the signature revision.
	DSSPlacementWithSignature SigDSSPlacementPreference = iota
	// DSSPlacementSeparateRevision updates DSS in a separate revision.
	DSSPlacementSeparateRevision
	// DSSPlacementBeforeTimestamp updates DSS before adding timestamps.
	DSSPlacementBeforeTimestamp
)

// GeneralDSSContentSettings controls DSS creation and updating.
type GeneralDSSContentSettings struct {
	// IncludeVRI controls whether to create VRI dictionary entries.
	IncludeVRI bool

	// SkipIfUnneeded skips DSS write if no new information.
	SkipIfUnneeded bool
}

// NewGeneralDSSContentSettings creates default DSS content settings.
func NewGeneralDSSContentSettings() *GeneralDSSContentSettings {
	return &GeneralDSSContentSettings{
		IncludeVRI:     true,
		SkipIfUnneeded: true,
	}
}

// DSSContentSettings specifies DSS content for signature validation.
type DSSContentSettings struct {
	*GeneralDSSContentSettings

	// PlacementPreference controls when DSS is updated.
	PlacementPreference SigDSSPlacementPreference

	// Certificates to include in DSS.
	Certificates []*x509.Certificate

	// CRLs to include in DSS.
	CRLs [][]byte

	// OCSPs to include in DSS.
	OCSPs [][]byte
}

// NewDSSContentSettings creates default DSS content settings.
func NewDSSContentSettings() *DSSContentSettings {
	return &DSSContentSettings{
		GeneralDSSContentSettings: NewGeneralDSSContentSettings(),
		PlacementPreference:       DSSPlacementSeparateRevision,
	}
}

// TimestampDSSContentSettings specifies DSS settings for timestamps.
type TimestampDSSContentSettings struct {
	*GeneralDSSContentSettings

	// UpdateBeforeTS updates DSS before timestamping.
	UpdateBeforeTS bool
}

// NewTimestampDSSContentSettings creates default timestamp DSS settings.
func NewTimestampDSSContentSettings() *TimestampDSSContentSettings {
	return &TimestampDSSContentSettings{
		GeneralDSSContentSettings: NewGeneralDSSContentSettings(),
		UpdateBeforeTS:            false,
	}
}

// Signer is the interface for signing operations.
type Signer interface {
	// Sign signs the given data and returns the CMS signature.
	Sign(data []byte) ([]byte, error)
	// GetCertificate returns the signing certificate.
	GetCertificate() *x509.Certificate
	// GetCertificateChain returns the certificate chain.
	GetCertificateChain() []*x509.Certificate
	// GetSignatureSize returns the estimated signature size.
	GetSignatureSize() int
}

// SimpleSigner implements Signer using a certificate and private key.
type SimpleSigner struct {
	Certificate *x509.Certificate
	CertChain   []*x509.Certificate
	PrivateKey  crypto.Signer
	Algorithm   cms.SignatureAlgorithm
}

// NewSimpleSigner creates a new SimpleSigner.
func NewSimpleSigner(cert *x509.Certificate, key crypto.Signer, alg cms.SignatureAlgorithm) *SimpleSigner {
	return &SimpleSigner{
		Certificate: cert,
		PrivateKey:  key,
		Algorithm:   alg,
	}
}

// SetCertificateChain sets the certificate chain.
func (s *SimpleSigner) SetCertificateChain(chain []*x509.Certificate) {
	s.CertChain = chain
}

// Sign implements Signer.
func (s *SimpleSigner) Sign(data []byte) ([]byte, error) {
	builder := cms.NewCMSBuilder(s.Certificate, s.PrivateKey, s.Algorithm)
	builder.SetCertificateChain(s.CertChain)
	return builder.Sign(data)
}

// GetCertificate implements Signer.
func (s *SimpleSigner) GetCertificate() *x509.Certificate {
	return s.Certificate
}

// GetCertificateChain implements Signer.
func (s *SimpleSigner) GetCertificateChain() []*x509.Certificate {
	return s.CertChain
}

// GetSignatureSize implements Signer.
func (s *SimpleSigner) GetSignatureSize() int {
	// Estimate based on certificate size and chain
	size := 8192 // Base size for CMS structure
	size += len(s.Certificate.Raw)
	for _, cert := range s.CertChain {
		size += len(cert.Raw)
	}
	return size
}

// SignatureMetadata contains metadata for the signature.
type SignatureMetadata struct {
	FieldName   string
	Reason      string
	Location    string
	ContactInfo string
	Name        string
	SubFilter   string // e.g., "adbe.pkcs7.detached", "ETSI.CAdES.detached"
}

// NewSignatureMetadata creates new signature metadata.
func NewSignatureMetadata(fieldName string) *SignatureMetadata {
	return &SignatureMetadata{
		FieldName: fieldName,
		SubFilter: "adbe.pkcs7.detached",
	}
}

// PdfSigner signs PDF documents.
type PdfSigner struct {
	Signer            Signer
	Metadata          *SignatureMetadata
	SignatureFieldBox *generic.Rectangle
	PageNumber        int
}

// NewPdfSigner creates a new PDF signer.
func NewPdfSigner(signer Signer, metadata *SignatureMetadata) *PdfSigner {
	return &PdfSigner{
		Signer:     signer,
		Metadata:   metadata,
		PageNumber: 0, // First page by default
	}
}

// SetSignatureAppearance sets the visible signature appearance.
func (p *PdfSigner) SetSignatureAppearance(page int, rect *generic.Rectangle) {
	p.PageNumber = page
	p.SignatureFieldBox = rect
}

// SignPdf signs a PDF file.
func (p *PdfSigner) SignPdf(pdfReader *reader.PdfFileReader) ([]byte, error) {
	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	// Determine signature field rectangle
	rect := p.SignatureFieldBox
	if rect == nil {
		// Invisible signature
		rect = &generic.Rectangle{LLX: 0, LLY: 0, URX: 0, URY: 0}
	}

	// Add signature field
	sigFieldRef, sigField, err := incWriter.AddSignatureField(
		p.Metadata.FieldName,
		p.PageNumber,
		rect,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add signature field: %w", err)
	}

	// Prepare signature placeholder
	contentsSize := p.Signer.GetSignatureSize()
	placeholder, err := incWriter.PrepareSignature(sigFieldRef, sigField, contentsSize)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signature: %w", err)
	}

	// Add signature metadata
	if p.Metadata.Reason != "" {
		placeholder.SigDict.Set("Reason", generic.NewTextString(p.Metadata.Reason))
	}
	if p.Metadata.Location != "" {
		placeholder.SigDict.Set("Location", generic.NewTextString(p.Metadata.Location))
	}
	if p.Metadata.ContactInfo != "" {
		placeholder.SigDict.Set("ContactInfo", generic.NewTextString(p.Metadata.ContactInfo))
	}
	if p.Metadata.Name != "" {
		placeholder.SigDict.Set("Name", generic.NewTextString(p.Metadata.Name))
	}
	placeholder.SigDict.Set("M", generic.NewTextString(formatPdfDate(time.Now())))

	// Set SubFilter based on metadata
	subFilter := "adbe.pkcs7.detached"
	if p.Metadata.SubFilter != "" {
		subFilter = p.Metadata.SubFilter
	}
	placeholder.SigDict.Set("SubFilter", generic.NameObject(subFilter))

	// Write PDF with placeholder
	var buf bytes.Buffer
	sigInfo, err := incWriter.WriteWithSignature(&buf, placeholder)
	if err != nil {
		return nil, fmt.Errorf("failed to write PDF with placeholder: %w", err)
	}

	// Get data to sign
	dataToSign := sigInfo.GetDataToSign()

	// Sign the data
	signature, err := p.Signer.Sign(dataToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Check signature size
	if len(signature) > contentsSize {
		return nil, fmt.Errorf("signature too large: %d > %d", len(signature), contentsSize)
	}

	// Embed signature
	signedPdf := sigInfo.EmbedSignature(signature)

	return signedPdf, nil
}

// SignNewPdf creates and signs a new PDF document.
func (p *PdfSigner) SignNewPdf(content []byte) ([]byte, error) {
	// Create a simple PDF with one page
	pdfWriter := writer.NewPdfFileWriter("1.7")

	// Add a page
	mediaBox := &generic.Rectangle{LLX: 0, LLY: 0, URX: 612, URY: 792} // Letter size
	pdfWriter.AddPage(mediaBox, content)

	// Write PDF to buffer
	var buf bytes.Buffer
	if err := pdfWriter.Write(&buf); err != nil {
		return nil, fmt.Errorf("failed to write PDF: %w", err)
	}

	// Read it back
	pdfReader, err := reader.NewPdfFileReaderFromBytes(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to read PDF: %w", err)
	}

	// Sign it
	return p.SignPdf(pdfReader)
}

// SignExistingField signs an existing signature field.
func (p *PdfSigner) SignExistingField(pdfReader *reader.PdfFileReader, fieldName string) ([]byte, error) {
	// Find the signature field
	sigFields, err := pdfReader.GetSignatureFields()
	if err != nil {
		return nil, fmt.Errorf("failed to get signature fields: %w", err)
	}

	var targetField *generic.DictionaryObject
	for _, field := range sigFields {
		if nameObj := field.Get("T"); nameObj != nil {
			if str, ok := nameObj.(*generic.StringObject); ok {
				if str.Text() == fieldName {
					targetField = field
					break
				}
			}
		}
	}

	if targetField == nil {
		return nil, fmt.Errorf("signature field '%s' not found", fieldName)
	}

	// Check if field is already signed
	if targetField.Has("V") {
		return nil, fmt.Errorf("signature field '%s' is already signed", fieldName)
	}

	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	// Prepare signature
	contentsSize := p.Signer.GetSignatureSize()

	// Create signature dictionary
	sigDict := generic.NewDictionary()
	sigDict.Set("Type", generic.NameObject("Sig"))
	sigDict.Set("Filter", generic.NameObject("Adobe.PPKLite"))
	sigDict.Set("SubFilter", generic.NameObject(p.Metadata.SubFilter))
	sigDict.Set("M", generic.NewTextString(formatPdfDate(time.Now())))

	if p.Metadata.Reason != "" {
		sigDict.Set("Reason", generic.NewTextString(p.Metadata.Reason))
	}
	if p.Metadata.Location != "" {
		sigDict.Set("Location", generic.NewTextString(p.Metadata.Location))
	}
	if p.Metadata.ContactInfo != "" {
		sigDict.Set("ContactInfo", generic.NewTextString(p.Metadata.ContactInfo))
	}
	if p.Metadata.Name != "" {
		sigDict.Set("Name", generic.NewTextString(p.Metadata.Name))
	}

	// Contents placeholder
	contentsPlaceholder := make([]byte, contentsSize)
	sigDict.Set("Contents", generic.NewHexString(contentsPlaceholder))
	sigDict.Set("ByteRange", generic.ArrayObject{
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
		generic.IntegerObject(0),
	})

	sigDictRef := incWriter.AddObject(sigDict)

	// Update field to point to signature
	fieldCopy := targetField.Clone().(*generic.DictionaryObject)
	fieldCopy.Set("V", sigDictRef)

	// Find field object number and update
	// (This is simplified - real implementation would need to track the field reference)

	placeholder := &writer.SignaturePlaceholder{
		SigDict:      sigDict,
		SigDictRef:   sigDictRef,
		ContentsSize: contentsSize,
	}

	// Write PDF with placeholder
	var buf bytes.Buffer
	sigInfo, err := incWriter.WriteWithSignature(&buf, placeholder)
	if err != nil {
		return nil, fmt.Errorf("failed to write PDF: %w", err)
	}

	// Sign
	signature, err := p.Signer.Sign(sigInfo.GetDataToSign())
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return sigInfo.EmbedSignature(signature), nil
}

// ExternalSigner supports signing with an external service.
type ExternalSigner struct {
	Certificate *x509.Certificate
	CertChain   []*x509.Certificate
	SignFunc    func(digest []byte) ([]byte, error)
	Algorithm   cms.SignatureAlgorithm
}

// NewExternalSigner creates a new external signer.
func NewExternalSigner(cert *x509.Certificate, signFunc func(digest []byte) ([]byte, error), alg cms.SignatureAlgorithm) *ExternalSigner {
	return &ExternalSigner{
		Certificate: cert,
		SignFunc:    signFunc,
		Algorithm:   alg,
	}
}

// Sign implements Signer.
func (s *ExternalSigner) Sign(data []byte) ([]byte, error) {
	// Hash the data first
	h := crypto.SHA256.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Call external signing function
	signature, err := s.SignFunc(digest)
	if err != nil {
		return nil, err
	}

	// Build CMS structure around the signature
	// This is simplified - full implementation would build complete CMS
	return signature, nil
}

// GetCertificate implements Signer.
func (s *ExternalSigner) GetCertificate() *x509.Certificate {
	return s.Certificate
}

// GetCertificateChain implements Signer.
func (s *ExternalSigner) GetCertificateChain() []*x509.Certificate {
	return s.CertChain
}

// GetSignatureSize implements Signer.
func (s *ExternalSigner) GetSignatureSize() int {
	size := 8192
	size += len(s.Certificate.Raw)
	for _, cert := range s.CertChain {
		size += len(cert.Raw)
	}
	return size
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

	return fmt.Sprintf("D:%04d%02d%02d%02d%02d%02d%s%02d'%02d'",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
		sign, offsetHours, offsetMinutes)
}

// TimeStamper provides timestamp tokens for signatures.
type TimeStamper interface {
	// GetTimestamp returns a timestamp token for the given digest.
	GetTimestamp(digest []byte, algorithm cms.SignatureAlgorithm) ([]byte, error)
}

// PdfTimeStamper adds document timestamps to PDFs.
type PdfTimeStamper struct {
	TimeStamper TimeStamper
	DSSSettings *TimestampDSSContentSettings
}

// NewPdfTimeStamper creates a new PDF timestamper.
func NewPdfTimeStamper(ts TimeStamper) *PdfTimeStamper {
	return &PdfTimeStamper{
		TimeStamper: ts,
		DSSSettings: NewTimestampDSSContentSettings(),
	}
}

// AddDocumentTimestamp adds a document timestamp to a PDF.
func (t *PdfTimeStamper) AddDocumentTimestamp(pdfReader *reader.PdfFileReader) ([]byte, error) {
	// Create incremental writer
	incWriter := writer.NewIncrementalPdfFileWriter(pdfReader)

	// Create document timestamp field (reuse signature field mechanism)
	fieldName := fmt.Sprintf("DocTimestamp_%d", time.Now().Unix())
	rect := &generic.Rectangle{LLX: 0, LLY: 0, URX: 0, URY: 0} // Invisible

	// Use AddSignatureField but configure for timestamp
	sigFieldRef, sigField, err := incWriter.AddSignatureField(fieldName, 0, rect)
	if err != nil {
		return nil, fmt.Errorf("failed to add timestamp field: %w", err)
	}

	// Prepare signature placeholder
	// Document timestamps are typically smaller than full signatures
	contentsSize := 8192
	placeholder, err := incWriter.PrepareSignature(sigFieldRef, sigField, contentsSize)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare timestamp: %w", err)
	}

	// Set type to DocTimeStamp
	placeholder.SigDict.Set("Type", generic.NameObject("DocTimeStamp"))
	placeholder.SigDict.Set("SubFilter", generic.NameObject("ETSI.RFC3161"))

	// Write PDF with placeholder
	var buf bytes.Buffer
	sigInfo, err := incWriter.WriteWithSignature(&buf, placeholder)
	if err != nil {
		return nil, fmt.Errorf("failed to write PDF: %w", err)
	}

	// Get data to timestamp
	dataToSign := sigInfo.GetDataToSign()

	// Hash the data
	h := crypto.SHA256.New()
	h.Write(dataToSign)
	digest := h.Sum(nil)

	// Get timestamp token
	tsToken, err := t.TimeStamper.GetTimestamp(digest, cms.SHA256WithRSA)
	if err != nil {
		return nil, fmt.Errorf("failed to get timestamp: %w", err)
	}

	// Check size
	if len(tsToken) > contentsSize {
		return nil, fmt.Errorf("timestamp too large: %d > %d", len(tsToken), contentsSize)
	}

	// Embed timestamp
	signedPdf := sigInfo.EmbedSignature(tsToken)

	return signedPdf, nil
}

// PreSignValidationStatus contains validation status before signing.
type PreSignValidationStatus struct {
	// SignerCertValid indicates if signer certificate is valid.
	SignerCertValid bool

	// ChainValid indicates if certificate chain is valid.
	ChainValid bool

	// ValidationPath is the validated certificate path.
	ValidationPath []*x509.Certificate

	// ValidationTime is the time at which validation was performed.
	ValidationTime time.Time

	// Errors encountered during validation.
	Errors []error

	// Warnings during validation.
	Warnings []string
}

// PostSignInstructions contains instructions for post-signing operations.
type PostSignInstructions struct {
	// AddTimestamp indicates whether to add a document timestamp.
	AddTimestamp bool

	// UpdateDSS indicates whether to update the DSS.
	UpdateDSS bool

	// DSSSettings contains DSS update settings.
	DSSSettings *DSSContentSettings

	// TimestampSettings contains timestamp settings.
	TimestampSettings *TimestampDSSContentSettings
}

// NewPostSignInstructions creates default post-sign instructions.
func NewPostSignInstructions() *PostSignInstructions {
	return &PostSignInstructions{
		AddTimestamp:      false,
		UpdateDSS:         false,
		DSSSettings:       NewDSSContentSettings(),
		TimestampSettings: NewTimestampDSSContentSettings(),
	}
}

// PdfSigningSession represents an ongoing PDF signing operation.
type PdfSigningSession struct {
	// PdfSigner is the signer to use.
	PdfSigner *PdfSigner

	// PdfReader is the PDF being signed.
	PdfReader *reader.PdfFileReader

	// PreSignStatus is the pre-signing validation status.
	PreSignStatus *PreSignValidationStatus

	// PostSignInstructions for operations after signing.
	PostSignInstructions *PostSignInstructions

	// SignedData is the signed PDF data (after signing).
	SignedData []byte
}

// NewPdfSigningSession creates a new signing session.
func NewPdfSigningSession(signer *PdfSigner, pdfReader *reader.PdfFileReader) *PdfSigningSession {
	return &PdfSigningSession{
		PdfSigner:            signer,
		PdfReader:            pdfReader,
		PostSignInstructions: NewPostSignInstructions(),
	}
}

// ValidatePreSign performs pre-signing validation.
func (s *PdfSigningSession) ValidatePreSign() *PreSignValidationStatus {
	status := &PreSignValidationStatus{
		ValidationTime: time.Now(),
	}

	cert := s.PdfSigner.Signer.GetCertificate()
	if cert == nil {
		status.Errors = append(status.Errors, fmt.Errorf("no signing certificate"))
		return status
	}

	// Check certificate validity
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		status.Errors = append(status.Errors, fmt.Errorf("certificate not valid at current time"))
	} else {
		status.SignerCertValid = true
	}

	// Build certificate path
	chain := s.PdfSigner.Signer.GetCertificateChain()
	status.ValidationPath = append([]*x509.Certificate{cert}, chain...)
	status.ChainValid = len(status.Errors) == 0

	s.PreSignStatus = status
	return status
}

// Sign performs the signing operation.
func (s *PdfSigningSession) Sign() ([]byte, error) {
	signedData, err := s.PdfSigner.SignPdf(s.PdfReader)
	if err != nil {
		return nil, err
	}
	s.SignedData = signedData
	return signedData, nil
}

// ProcessPostSign processes post-signing instructions.
func (s *PdfSigningSession) ProcessPostSign(timestamper *PdfTimeStamper) ([]byte, error) {
	if s.SignedData == nil {
		return nil, fmt.Errorf("no signed data - call Sign() first")
	}

	result := s.SignedData

	// Add timestamp if requested
	if s.PostSignInstructions.AddTimestamp && timestamper != nil {
		pdfReader, err := reader.NewPdfFileReaderFromBytes(result)
		if err != nil {
			return nil, fmt.Errorf("failed to read signed PDF: %w", err)
		}

		result, err = timestamper.AddDocumentTimestamp(pdfReader)
		if err != nil {
			return nil, fmt.Errorf("failed to add timestamp: %w", err)
		}
	}

	return result, nil
}

// MDPPermission represents document modification permissions.
type MDPPermission int

const (
	// MDPNoChanges allows no changes after signing.
	MDPNoChanges MDPPermission = 1
	// MDPFormFilling allows form filling after signing.
	MDPFormFilling MDPPermission = 2
	// MDPAnnotations allows annotations and form filling after signing.
	MDPAnnotations MDPPermission = 3
)

// String returns the string representation.
func (p MDPPermission) String() string {
	switch p {
	case MDPNoChanges:
		return "no_changes"
	case MDPFormFilling:
		return "form_filling"
	case MDPAnnotations:
		return "annotations"
	default:
		return "unknown"
	}
}

// SigCertificationLevel represents the certification level for a signature.
type SigCertificationLevel int

const (
	// SigCertNone is a regular approval signature.
	SigCertNone SigCertificationLevel = iota
	// SigCertNoChanges is a certification signature allowing no changes.
	SigCertNoChanges
	// SigCertFormFilling is a certification allowing form filling.
	SigCertFormFilling
	// SigCertAnnotations is a certification allowing annotations.
	SigCertAnnotations
)

// EnhancedSignatureMetadata contains comprehensive signature metadata.
type EnhancedSignatureMetadata struct {
	*SignatureMetadata

	// SigningTime is the claimed signing time.
	SigningTime time.Time

	// CertificationLevel for certification signatures.
	CertificationLevel SigCertificationLevel

	// MDPPermissions for document modifications.
	MDPPermissions MDPPermission

	// EmbedTimestamp embeds a timestamp in the signature.
	EmbedTimestamp bool

	// UseAdES enables CAdES/PAdES-style signatures.
	UseAdES bool

	// DSSSettings for DSS creation.
	DSSSettings *DSSContentSettings

	// CommitmentType is the CAdES commitment type OID.
	CommitmentType []int

	// SignaturePolicyID is the signature policy OID.
	SignaturePolicyID []int
}

// NewEnhancedSignatureMetadata creates enhanced signature metadata.
func NewEnhancedSignatureMetadata(fieldName string) *EnhancedSignatureMetadata {
	return &EnhancedSignatureMetadata{
		SignatureMetadata:  NewSignatureMetadata(fieldName),
		CertificationLevel: SigCertNone,
		DSSSettings:        NewDSSContentSettings(),
	}
}

// WithReason sets the signature reason.
func (m *EnhancedSignatureMetadata) WithReason(reason string) *EnhancedSignatureMetadata {
	m.Reason = reason
	return m
}

// WithLocation sets the signature location.
func (m *EnhancedSignatureMetadata) WithLocation(location string) *EnhancedSignatureMetadata {
	m.Location = location
	return m
}

// WithContactInfo sets contact information.
func (m *EnhancedSignatureMetadata) WithContactInfo(contactInfo string) *EnhancedSignatureMetadata {
	m.ContactInfo = contactInfo
	return m
}

// WithName sets the signer name.
func (m *EnhancedSignatureMetadata) WithName(name string) *EnhancedSignatureMetadata {
	m.Name = name
	return m
}

// AsCertification configures the signature as a certification signature.
func (m *EnhancedSignatureMetadata) AsCertification(level SigCertificationLevel) *EnhancedSignatureMetadata {
	m.CertificationLevel = level
	return m
}

// WithTimestamp enables embedded timestamps.
func (m *EnhancedSignatureMetadata) WithTimestamp() *EnhancedSignatureMetadata {
	m.EmbedTimestamp = true
	return m
}

// WithAdES enables AdES-style signatures.
func (m *EnhancedSignatureMetadata) WithAdES() *EnhancedSignatureMetadata {
	m.UseAdES = true
	m.SubFilter = "ETSI.CAdES.detached"
	return m
}
