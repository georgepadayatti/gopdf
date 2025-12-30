// Package fields provides signature field management utilities.
package fields

import (
	"errors"
	"fmt"

	"github.com/georgepadayatti/gopdf/pdf/form"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors
var (
	ErrNoSignatureField   = errors.New("no signature field found")
	ErrFieldAlreadySigned = errors.New("signature field is already signed")
	ErrInvalidFieldSpec   = errors.New("invalid signature field specification")
)

// SignatureFormField represents a signature form field.
type SignatureFormField struct {
	Name      string
	FullName  string
	Value     *generic.DictionaryObject // Signature dictionary if signed
	Rect      *generic.Rectangle
	Page      int
	FieldRef  *generic.Reference
	FieldDict *generic.DictionaryObject
	SeedValue *SigSeedValueSpec
	LockSpec  *SigFieldLockSpec
}

// IsSigned returns true if the signature field has been signed.
func (f *SignatureFormField) IsSigned() bool {
	return f.Value != nil
}

// SigFieldSpec specifies a signature field to create.
type SigFieldSpec struct {
	// SigFieldName is the name of the signature field.
	SigFieldName string

	// OnPage is the page number (0-indexed) for visible signatures.
	OnPage int

	// Box defines the signature rectangle for visible signatures.
	Box *generic.Rectangle

	// SeedValueDict specifies seed value constraints.
	SeedValueDict *SigSeedValueSpec

	// FieldMDPSpec specifies field modification detection.
	FieldMDPSpec *FieldMDPSpec

	// DocMDPPerms specifies document modification permissions.
	DocMDPPerms *form.MDPPerm

	// InvisibleSig indicates this is an invisible signature.
	InvisibleSig bool
}

// SigSeedValueSpec represents signature seed value constraints.
type SigSeedValueSpec struct {
	Flags              SigSeedValFlags
	Reasons            []string
	TimestampServerURL string
	TimestampRequired  bool
	CertConstraints    *SigCertConstraints
	SubFilters         []SigSeedSubFilter
	DigestMethods      []string
	AddRevInfo         *bool
	SeedSignatureType  *SeedSignatureType
	LockDocument       *SeedLockDocument
	Appearance         string
}

// SigSeedValFlags represents signature seed value flags.
type SigSeedValFlags uint32

const (
	SigSeedFlagFilter           SigSeedValFlags = 1 << 0
	SigSeedFlagSubFilter        SigSeedValFlags = 1 << 1
	SigSeedFlagV                SigSeedValFlags = 1 << 2
	SigSeedFlagReasons          SigSeedValFlags = 1 << 3
	SigSeedFlagLegalAttestation SigSeedValFlags = 1 << 4
	SigSeedFlagAddRevInfo       SigSeedValFlags = 1 << 5
	SigSeedFlagDigestMethod     SigSeedValFlags = 1 << 6
	SigSeedFlagLockDocument     SigSeedValFlags = 1 << 7
	SigSeedFlagAppearanceFilter SigSeedValFlags = 1 << 8
)

// SigSeedSubFilter represents allowed subfilter values.
type SigSeedSubFilter string

const (
	SubFilterAdobePKCS7Detached SigSeedSubFilter = "adbe.pkcs7.detached"
	SubFilterAdobePKCS7SHA1     SigSeedSubFilter = "adbe.pkcs7.sha1"
	SubFilterETSICAdESDetached  SigSeedSubFilter = "ETSI.CAdES.detached"
	SubFilterETSIRFC3161        SigSeedSubFilter = "ETSI.RFC3161"
)

// SeedSignatureType indicates the intended signature type.
type SeedSignatureType struct {
	MDPPerm *form.MDPPerm
}

// IsCertification returns true if this is a certification signature type.
func (s *SeedSignatureType) IsCertification() bool {
	return s.MDPPerm != nil
}

// SeedLockDocument indicates document lock preference.
type SeedLockDocument int

const (
	SeedLockDocumentLock SeedLockDocument = iota
	SeedLockDocumentDoNotLock
	SeedLockDocumentSignerDiscretion
)

// SigCertConstraints represents certificate constraints.
type SigCertConstraints struct {
	Flags          SigCertConstraintFlags
	Subjects       [][]byte // DER-encoded subject names
	SubjectDN      []map[string]string
	KeyUsage       *KeyUsageConstraint
	Issuers        [][]byte // DER-encoded issuer names
	OIDConstraints []string
	URLType        CertURLType
	URL            string
}

// SigCertConstraintFlags represents certificate constraint flags.
type SigCertConstraintFlags uint32

const (
	CertFlagSubject   SigCertConstraintFlags = 1 << 0
	CertFlagIssuer    SigCertConstraintFlags = 1 << 1
	CertFlagOID       SigCertConstraintFlags = 1 << 2
	CertFlagSubjectDN SigCertConstraintFlags = 1 << 3
	CertFlagReserved  SigCertConstraintFlags = 1 << 4
	CertFlagKeyUsage  SigCertConstraintFlags = 1 << 5
	CertFlagURL       SigCertConstraintFlags = 1 << 6
	CertFlagURLType   SigCertConstraintFlags = 1 << 7
)

// KeyUsageConstraint represents key usage constraints.
type KeyUsageConstraint struct {
	DigitalSignature bool
	NonRepudiation   bool
	KeyEncipherment  bool
	DataEncipherment bool
	KeyAgreement     bool
	KeyCertSign      bool
	CRLSign          bool
	EncipherOnly     bool
	DecipherOnly     bool
}

// CertURLType represents URL type for certificate download.
type CertURLType int

const (
	CertURLTypeBrowser CertURLType = 0
	CertURLTypeASN1    CertURLType = 1
)

// SigFieldLockSpec represents signature field lock specification.
type SigFieldLockSpec struct {
	Action FieldMDPAction
	Fields []string
}

// FieldMDPSpec specifies field modification detection policy.
type FieldMDPSpec struct {
	Action FieldMDPAction
	Fields []string
}

// FieldMDPAction specifies the action type.
type FieldMDPAction string

const (
	FieldMDPActionAll     FieldMDPAction = "All"
	FieldMDPActionInclude FieldMDPAction = "Include"
	FieldMDPActionExclude FieldMDPAction = "Exclude"
)

// ToPdfObject converts SigSeedValueSpec to PDF dictionary.
func (s *SigSeedValueSpec) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("SV"))
	dict.Set("Ff", generic.IntegerObject(s.Flags))

	// Add subfilters
	if len(s.SubFilters) > 0 {
		sfs := make(generic.ArrayObject, len(s.SubFilters))
		for i, sf := range s.SubFilters {
			sfs[i] = generic.NameObject(string(sf))
		}
		dict.Set("SubFilter", sfs)
	}

	// Add digest methods
	if len(s.DigestMethods) > 0 {
		dms := make(generic.ArrayObject, len(s.DigestMethods))
		for i, dm := range s.DigestMethods {
			dms[i] = generic.NewLiteralString(dm)
		}
		dict.Set("DigestMethod", dms)
	}

	// Add reasons
	if len(s.Reasons) > 0 {
		reasons := make(generic.ArrayObject, len(s.Reasons))
		for i, r := range s.Reasons {
			reasons[i] = generic.NewLiteralString(r)
		}
		dict.Set("Reasons", reasons)
	}

	// Add timestamp info
	if s.TimestampServerURL != "" {
		tsDict := generic.NewDictionary()
		tsDict.Set("URL", generic.NewLiteralString(s.TimestampServerURL))
		if s.TimestampRequired {
			tsDict.Set("Ff", generic.IntegerObject(1))
		}
		dict.Set("TimeStamp", tsDict)
	}

	// Add revocation info preference
	if s.AddRevInfo != nil {
		dict.Set("AddRevInfo", generic.BooleanObject(*s.AddRevInfo))
	}

	// Add MDP preference
	if s.SeedSignatureType != nil && s.SeedSignatureType.MDPPerm != nil {
		dict.Set("MDP", generic.IntegerObject(*s.SeedSignatureType.MDPPerm))
	}

	// Add lock document preference
	if s.LockDocument != nil {
		switch *s.LockDocument {
		case SeedLockDocumentLock:
			dict.Set("LockDocument", generic.NameObject("true"))
		case SeedLockDocumentDoNotLock:
			dict.Set("LockDocument", generic.NameObject("false"))
		case SeedLockDocumentSignerDiscretion:
			dict.Set("LockDocument", generic.NameObject("auto"))
		}
	}

	return dict
}

// ToPdfObject converts FieldMDPSpec to PDF dictionary.
func (f *FieldMDPSpec) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("TransformParams"))
	dict.Set("P", generic.IntegerObject(2)) // Default permission
	dict.Set("V", generic.NameObject("1.2"))
	dict.Set("Action", generic.NameObject(string(f.Action)))

	if f.Action != FieldMDPActionAll && len(f.Fields) > 0 {
		fields := make(generic.ArrayObject, len(f.Fields))
		for i, field := range f.Fields {
			fields[i] = generic.NewLiteralString(field)
		}
		dict.Set("Fields", fields)
	}

	return dict
}

// ToPdfObject converts SigFieldLockSpec to PDF dictionary.
func (l *SigFieldLockSpec) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("SigFieldLock"))
	dict.Set("Action", generic.NameObject(string(l.Action)))

	if l.Action != FieldMDPActionAll && len(l.Fields) > 0 {
		fields := make(generic.ArrayObject, len(l.Fields))
		for i, field := range l.Fields {
			fields[i] = generic.NewLiteralString(field)
		}
		dict.Set("Fields", fields)
	}

	return dict
}

// SignatureFieldBuilder helps build signature fields.
type SignatureFieldBuilder struct {
	spec     SigFieldSpec
	acroForm *generic.DictionaryObject
}

// NewSignatureFieldBuilder creates a new signature field builder.
func NewSignatureFieldBuilder(name string) *SignatureFieldBuilder {
	return &SignatureFieldBuilder{
		spec: SigFieldSpec{
			SigFieldName: name,
		},
	}
}

// OnPage sets the page for a visible signature.
func (b *SignatureFieldBuilder) OnPage(page int) *SignatureFieldBuilder {
	b.spec.OnPage = page
	return b
}

// WithBox sets the rectangle for a visible signature.
func (b *SignatureFieldBuilder) WithBox(rect *generic.Rectangle) *SignatureFieldBuilder {
	b.spec.Box = rect
	return b
}

// Invisible marks this as an invisible signature.
func (b *SignatureFieldBuilder) Invisible() *SignatureFieldBuilder {
	b.spec.InvisibleSig = true
	return b
}

// WithSeedValue sets seed value constraints.
func (b *SignatureFieldBuilder) WithSeedValue(sv *SigSeedValueSpec) *SignatureFieldBuilder {
	b.spec.SeedValueDict = sv
	return b
}

// WithFieldMDP sets field MDP constraints.
func (b *SignatureFieldBuilder) WithFieldMDP(mdp *FieldMDPSpec) *SignatureFieldBuilder {
	b.spec.FieldMDPSpec = mdp
	return b
}

// WithDocMDP sets document MDP permission.
func (b *SignatureFieldBuilder) WithDocMDP(perm form.MDPPerm) *SignatureFieldBuilder {
	b.spec.DocMDPPerms = &perm
	return b
}

// Build returns the signature field specification.
func (b *SignatureFieldBuilder) Build() *SigFieldSpec {
	return &b.spec
}

// CreateSignatureField creates a signature field dictionary.
func CreateSignatureField(spec *SigFieldSpec) (*generic.DictionaryObject, error) {
	if spec.SigFieldName == "" {
		return nil, fmt.Errorf("%w: field name is required", ErrInvalidFieldSpec)
	}

	field := generic.NewDictionary()
	field.Set("FT", generic.NameObject("Sig"))
	field.Set("T", generic.NewLiteralString(spec.SigFieldName))
	field.Set("Ff", generic.IntegerObject(0))

	// Add rectangle if visible
	if !spec.InvisibleSig && spec.Box != nil {
		field.Set("Rect", spec.Box.ToArray())
	} else {
		// Invisible signature has zero-sized rect
		field.Set("Rect", generic.ArrayObject{
			generic.IntegerObject(0),
			generic.IntegerObject(0),
			generic.IntegerObject(0),
			generic.IntegerObject(0),
		})
	}

	// Add seed value if specified
	if spec.SeedValueDict != nil {
		field.Set("SV", spec.SeedValueDict.ToPdfObject())
	}

	// Add lock spec if specified
	if spec.FieldMDPSpec != nil {
		lockDict := generic.NewDictionary()
		lockDict.Set("Type", generic.NameObject("SigFieldLock"))
		lockDict.Set("Action", generic.NameObject(string(spec.FieldMDPSpec.Action)))
		if len(spec.FieldMDPSpec.Fields) > 0 {
			fields := make(generic.ArrayObject, len(spec.FieldMDPSpec.Fields))
			for i, f := range spec.FieldMDPSpec.Fields {
				fields[i] = generic.NewLiteralString(f)
			}
			lockDict.Set("Fields", fields)
		}
		field.Set("Lock", lockDict)
	}

	return field, nil
}

// VisibleSigSettings configures visible signature appearance.
type VisibleSigSettings struct {
	OnPage            int
	Box               *generic.Rectangle
	Background        []byte
	ShowText          bool
	ShowImage         bool
	ImagePath         string
	ImageData         []byte
	Stamp             bool
	BackgroundOpacity float64

	// Visual signature configuration
	SignerName       string
	Reason           string
	Location         string
	ContactInfo      string
	ImageAsWatermark bool        // If true, text is drawn over the image
	ImagePosition    string      // "left", "right", "above", "below", "background"
	ImageRatio       float64     // Ratio of image area (0.0 to 1.0)
	ImageOpacity     float64     // Image opacity (0.0 to 1.0)
	FontSize         float64     // Text font size
	FontName         string      // Text font name (e.g., "Helvetica")
	TextColor        [3]float64  // RGB text color (0.0 to 1.0)
	BorderWidth      float64     // Border width in points
	BorderColor      [3]float64  // RGB border color (0.0 to 1.0)
	Padding          float64     // Padding in points
}

// InvisibleSigSettings configures invisible signature.
type InvisibleSigSettings struct {
	// No visual representation
}

// EnumerateSignatureFields enumerates all signature fields in a document.
func EnumerateSignatureFields(acroFormDict *generic.DictionaryObject) ([]*SignatureFormField, error) {
	if acroFormDict == nil {
		return nil, form.ErrNoAcroForm
	}

	fieldsObj := acroFormDict.Get("Fields")
	if fieldsObj == nil {
		return nil, fmt.Errorf("no Fields array in AcroForm")
	}

	fields, ok := fieldsObj.(generic.ArrayObject)
	if !ok {
		return nil, fmt.Errorf("Fields is not an array")
	}

	var sigFields []*SignatureFormField

	enumerator := form.NewFieldEnumerator().WithType(form.FieldTypeSignature)
	results, err := enumerator.EnumerateFields(fields, "", nil)
	if err != nil {
		return nil, err
	}

	for _, result := range results {
		sigField := &SignatureFormField{
			FullName:  result.FullName,
			FieldRef:  result.FieldRef,
			FieldDict: result.Field,
		}

		// Get value (signature dictionary) if signed
		if result.Value != nil {
			if valDict, ok := result.Value.(*generic.DictionaryObject); ok {
				sigField.Value = valDict
			}
		}

		// Get rectangle
		if result.Field != nil {
			rectObj := result.Field.Get("Rect")
			if rectObj != nil {
				if rectArr, ok := rectObj.(generic.ArrayObject); ok && len(rectArr) == 4 {
					sigField.Rect = arrayToRect(rectArr)
				}
			}
		}

		sigFields = append(sigFields, sigField)
	}

	return sigFields, nil
}

func arrayToRect(arr generic.ArrayObject) *generic.Rectangle {
	if len(arr) != 4 {
		return nil
	}
	return &generic.Rectangle{
		LLX: getFloat(arr[0]),
		LLY: getFloat(arr[1]),
		URX: getFloat(arr[2]),
		URY: getFloat(arr[3]),
	}
}

func getFloat(obj generic.PdfObject) float64 {
	switch v := obj.(type) {
	case generic.IntegerObject:
		return float64(v)
	case generic.RealObject:
		return float64(v)
	case *generic.IntegerObject:
		return float64(*v)
	case *generic.RealObject:
		return float64(*v)
	default:
		return 0
	}
}

// FindEmptySignatureField finds an empty signature field by name.
func FindEmptySignatureField(acroFormDict *generic.DictionaryObject, name string) (*SignatureFormField, error) {
	fields, err := EnumerateSignatureFields(acroFormDict)
	if err != nil {
		return nil, err
	}

	for _, field := range fields {
		if field.FullName == name && !field.IsSigned() {
			return field, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrNoSignatureField, name)
}

// EnsureSigFlags ensures proper SigFlags are set on the AcroForm.
func EnsureSigFlags(acroFormDict *generic.DictionaryObject, flags int) {
	currentFlags := 0
	if flagsObj := acroFormDict.Get("SigFlags"); flagsObj != nil {
		if f, ok := flagsObj.(generic.IntegerObject); ok {
			currentFlags = int(f)
		}
	}

	newFlags := currentFlags | flags
	acroFormDict.Set("SigFlags", generic.IntegerObject(newFlags))
}

// DefaultVisibleSigSettings returns default settings for visible signatures.
func DefaultVisibleSigSettings() *VisibleSigSettings {
	return &VisibleSigSettings{
		ShowText:         true,
		ShowImage:        false,
		ImagePosition:    "left",
		ImageRatio:       0.3,
		ImageOpacity:     1.0,
		FontSize:         10.0,
		FontName:         "Helvetica",
		TextColor:        [3]float64{0, 0, 0},
		BorderWidth:      0,
		BorderColor:      [3]float64{0, 0, 0},
		Padding:          5.0,
	}
}

// NewVisibleSigSettingsWithImage creates visible signature settings with an image.
func NewVisibleSigSettingsWithImage(imageData []byte, signerName string, box *generic.Rectangle) *VisibleSigSettings {
	settings := DefaultVisibleSigSettings()
	settings.ImageData = imageData
	settings.ShowImage = true
	settings.SignerName = signerName
	settings.Box = box
	return settings
}

// ParseImagePosition parses an image position string.
func ParseImagePosition(s string) string {
	switch s {
	case "left", "right", "above", "below", "background":
		return s
	default:
		return "left"
	}
}
