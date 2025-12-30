// Package form provides PDF form field handling utilities.
package form

import (
	"errors"
	"fmt"
	"strings"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors
var (
	ErrNoAcroForm        = errors.New("no AcroForm present in document")
	ErrFieldNotFound     = errors.New("form field not found")
	ErrFieldTypeMismatch = errors.New("form field type mismatch")
	ErrMultipleAnnots    = errors.New("form field has multiple annotations")
	ErrCircularReference = errors.New("circular reference in form tree")
)

// FieldType represents the type of a form field.
type FieldType string

// Field types
const (
	FieldTypeButton    FieldType = "/Btn"
	FieldTypeText      FieldType = "/Tx"
	FieldTypeChoice    FieldType = "/Ch"
	FieldTypeSignature FieldType = "/Sig"
)

// FieldFlags represents form field flags.
type FieldFlags uint32

// Common field flags
const (
	FieldFlagReadOnly FieldFlags = 1 << 0
	FieldFlagRequired FieldFlags = 1 << 1
	FieldFlagNoExport FieldFlags = 1 << 2
)

// Text field flags
const (
	TextFieldMultiline   FieldFlags = 1 << 12
	TextFieldPassword    FieldFlags = 1 << 13
	TextFieldFileSelect  FieldFlags = 1 << 20
	TextFieldDoNotSpell  FieldFlags = 1 << 22
	TextFieldDoNotScroll FieldFlags = 1 << 23
	TextFieldComb        FieldFlags = 1 << 24
	TextFieldRichText    FieldFlags = 1 << 25
)

// Button field flags
const (
	ButtonFieldNoToggleToOff  FieldFlags = 1 << 14
	ButtonFieldRadio          FieldFlags = 1 << 15
	ButtonFieldPushbutton     FieldFlags = 1 << 16
	ButtonFieldRadiosInUnison FieldFlags = 1 << 25
)

// FormField represents a PDF form field.
type FormField struct {
	Name       string
	FullName   string
	FieldType  FieldType
	Flags      FieldFlags
	Value      interface{}
	Parent     *FormField
	Children   []*FormField
	Reference  *generic.Reference
	Dictionary *generic.DictionaryObject
}

// IsFilled returns true if the field has a value.
func (f *FormField) IsFilled() bool {
	return f.Value != nil
}

// IsReadOnly returns true if the field is read-only.
func (f *FormField) IsReadOnly() bool {
	return f.Flags&FieldFlagReadOnly != 0
}

// GetAnnotation gets the annotation dictionary for this field.
func GetSingleFieldAnnotation(field *generic.DictionaryObject) (*generic.DictionaryObject, error) {
	// Check if /Kids exists
	kidsObj := field.Get("Kids")
	if kidsObj != nil {
		kids, ok := kidsObj.(generic.ArrayObject)
		if !ok || len(kids) != 1 {
			return nil, ErrMultipleAnnots
		}
		// Get the single child
		childRef, ok := kids[0].(*generic.Reference)
		if !ok {
			return nil, ErrMultipleAnnots
		}
		// TODO: Dereference the reference to get the dictionary
		_ = childRef
		return nil, fmt.Errorf("reference dereferencing not implemented")
	}
	// Field is combined with its annotation
	return field, nil
}

// GetAnnotationRect gets the rectangle dimensions of an annotation.
func GetAnnotationRect(annot *generic.DictionaryObject) (width, height float64, err error) {
	rectObj := annot.Get("Rect")
	if rectObj == nil {
		return 0, 0, nil
	}

	rect, ok := rectObj.(generic.ArrayObject)
	if !ok || len(rect) != 4 {
		return 0, 0, fmt.Errorf("invalid Rect array")
	}

	x1 := getFloat(rect[0])
	y1 := getFloat(rect[1])
	x2 := getFloat(rect[2])
	y2 := getFloat(rect[3])

	width = abs(x2 - x1)
	height = abs(y2 - y1)
	return width, height, nil
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
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

// FieldEnumerator helps enumerate form fields.
type FieldEnumerator struct {
	targetType   FieldType
	filledStatus *bool
	withName     string
	refsSeen     map[string]bool
}

// NewFieldEnumerator creates a new field enumerator.
func NewFieldEnumerator() *FieldEnumerator {
	return &FieldEnumerator{
		refsSeen: make(map[string]bool),
	}
}

// WithType filters by field type.
func (e *FieldEnumerator) WithType(ft FieldType) *FieldEnumerator {
	e.targetType = ft
	return e
}

// WithName filters by field name.
func (e *FieldEnumerator) WithName(name string) *FieldEnumerator {
	e.withName = name
	return e
}

// FilledOnly returns only filled fields.
func (e *FieldEnumerator) FilledOnly() *FieldEnumerator {
	filled := true
	e.filledStatus = &filled
	return e
}

// EmptyOnly returns only empty fields.
func (e *FieldEnumerator) EmptyOnly() *FieldEnumerator {
	filled := false
	e.filledStatus = &filled
	return e
}

// EnumerateResult represents a field enumeration result.
type EnumerateResult struct {
	FullName string
	Value    generic.PdfObject
	FieldRef *generic.Reference
	Field    *generic.DictionaryObject
}

// EnumerateFields enumerates form fields from a field list.
func (e *FieldEnumerator) EnumerateFields(
	fieldList generic.ArrayObject,
	parentName string,
	parents []*generic.DictionaryObject,
) ([]EnumerateResult, error) {
	var results []EnumerateResult

	for _, fieldRefObj := range fieldList {
		fieldRef, ok := fieldRefObj.(*generic.Reference)
		if !ok {
			continue
		}

		// Check for circular reference
		refKey := fmt.Sprintf("%d:0", fieldRef.ObjectNumber)
		if e.refsSeen[refKey] {
			return nil, ErrCircularReference
		}
		e.refsSeen[refKey] = true

		// Get the field dictionary (would need PDF reader context)
		// For now, skip fields that need dereferencing
		field, ok := fieldRefObj.(*generic.DictionaryObject)
		if !ok {
			continue
		}

		// Get field name
		nameObj := field.Get("T")
		if nameObj == nil {
			continue
		}
		fieldName := ""
		if strObj, ok := nameObj.(*generic.StringObject); ok {
			fieldName = string(strObj.Value)
		}

		// Build fully qualified name
		fqName := fieldName
		if parentName != "" {
			fqName = parentName + "." + fieldName
		}

		// Check if this is the requested field
		explicitlyRequested := e.withName != "" && fqName == e.withName
		childRequested := explicitlyRequested || (e.withName != "" && strings.HasPrefix(e.withName, fqName+"."))

		// Find field type (inheritable)
		var fieldType FieldType
		currentPath := append([]*generic.DictionaryObject{field}, parents...)
		for _, parentField := range currentPath {
			ftObj := parentField.Get("FT")
			if ftObj != nil {
				if ftName, ok := ftObj.(generic.NameObject); ok {
					fieldType = FieldType("/" + string(ftName))
					break
				}
			}
		}

		// Check if matches target type
		if e.targetType == "" || fieldType == e.targetType {
			// Get field value
			valueObj := field.Get("V")
			filled := valueObj != nil

			// Check status filter
			statusMatch := e.filledStatus == nil || *e.filledStatus == filled
			nameMatch := e.withName == "" || explicitlyRequested

			if statusMatch && nameMatch {
				results = append(results, EnumerateResult{
					FullName: fqName,
					Value:    valueObj,
					FieldRef: fieldRef,
					Field:    field,
				})
			}
		} else if explicitlyRequested {
			return nil, fmt.Errorf("%w: field %s is %s, not %s",
				ErrFieldTypeMismatch, fqName, fieldType, e.targetType)
		}

		// Descend into children if needed
		if e.withName == "" || (childRequested && !explicitlyRequested) {
			kidsObj := field.Get("Kids")
			if kidsObj != nil {
				if kids, ok := kidsObj.(generic.ArrayObject); ok {
					childResults, err := e.EnumerateFields(kids, fqName, currentPath)
					if err != nil {
						return nil, err
					}
					results = append(results, childResults...)
				}
			}
		}
	}

	return results, nil
}

// AcroForm represents a PDF AcroForm.
type AcroForm struct {
	Fields          generic.ArrayObject
	NeedAppearances bool
	SigFlags        int
	DR              *generic.DictionaryObject
	DA              string
}

// ParseAcroForm parses an AcroForm dictionary.
func ParseAcroForm(dict *generic.DictionaryObject) (*AcroForm, error) {
	if dict == nil {
		return nil, ErrNoAcroForm
	}

	form := &AcroForm{}

	// Get Fields array
	if fieldsObj := dict.Get("Fields"); fieldsObj != nil {
		if fields, ok := fieldsObj.(generic.ArrayObject); ok {
			form.Fields = fields
		}
	}

	// Get NeedAppearances
	if naObj := dict.Get("NeedAppearances"); naObj != nil {
		if na, ok := naObj.(generic.BooleanObject); ok {
			form.NeedAppearances = bool(na)
		}
	}

	// Get SigFlags
	if sfObj := dict.Get("SigFlags"); sfObj != nil {
		if sf, ok := sfObj.(generic.IntegerObject); ok {
			form.SigFlags = int(sf)
		}
	}

	// Get DA (default appearance)
	if daObj := dict.Get("DA"); daObj != nil {
		if da, ok := daObj.(*generic.StringObject); ok {
			form.DA = string(da.Value)
		}
	}

	// Get DR (default resources)
	if drObj := dict.Get("DR"); drObj != nil {
		if dr, ok := drObj.(*generic.DictionaryObject); ok {
			form.DR = dr
		}
	}

	return form, nil
}

// SigFlags values
const (
	SigFlagSignaturesExist = 1 << 0
	SigFlagAppendOnly      = 1 << 1
)

// HasSignatures returns true if the form has existing signatures.
func (f *AcroForm) HasSignatures() bool {
	return f.SigFlags&SigFlagSignaturesExist != 0
}

// IsAppendOnly returns true if the document is append-only.
func (f *AcroForm) IsAppendOnly() bool {
	return f.SigFlags&SigFlagAppendOnly != 0
}

// TextFieldSpec specifies a text field to create.
type TextFieldSpec struct {
	Name         string
	Page         int
	Rect         *generic.Rectangle
	Flags        FieldFlags
	DefaultValue string
	MaxLen       int
}

// SignatureFieldSpec specifies a signature field to create.
type SignatureFieldSpec struct {
	Name      string
	Page      int
	Rect      *generic.Rectangle
	Flags     FieldFlags
	SeedValue *SigSeedValue
}

// SigSeedValue represents signature seed value constraints.
type SigSeedValue struct {
	Flags             SigSeedValFlags
	Reasons           []string
	TimestampURL      string
	TimestampRequired bool
	SubFilters        []string
	DigestMethods     []string
	AddRevInfo        *bool
	LockDocument      *bool
}

// SigSeedValFlags are signature seed value flags.
type SigSeedValFlags uint32

const (
	SigSeedFlagFilter       SigSeedValFlags = 1 << 0
	SigSeedFlagSubFilter    SigSeedValFlags = 1 << 1
	SigSeedFlagV            SigSeedValFlags = 1 << 2
	SigSeedFlagReasons      SigSeedValFlags = 1 << 3
	SigSeedFlagLegalAttest  SigSeedValFlags = 1 << 4
	SigSeedFlagAddRevInfo   SigSeedValFlags = 1 << 5
	SigSeedFlagDigestMethod SigSeedValFlags = 1 << 6
	SigSeedFlagLockDocument SigSeedValFlags = 1 << 7
	SigSeedFlagAppearance   SigSeedValFlags = 1 << 8
)

// ToPdfObject converts SigSeedValue to a PDF dictionary.
func (s *SigSeedValue) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("SV"))
	dict.Set("Ff", generic.IntegerObject(s.Flags))

	if len(s.Reasons) > 0 {
		reasons := make(generic.ArrayObject, len(s.Reasons))
		for i, r := range s.Reasons {
			reasons[i] = generic.NewLiteralString(r)
		}
		dict.Set("Reasons", reasons)
	}

	if s.TimestampURL != "" {
		tsDict := generic.NewDictionary()
		tsDict.Set("URL", generic.NewLiteralString(s.TimestampURL))
		if s.TimestampRequired {
			tsDict.Set("Ff", generic.IntegerObject(1))
		}
		dict.Set("TimeStamp", tsDict)
	}

	if len(s.SubFilters) > 0 {
		sfs := make(generic.ArrayObject, len(s.SubFilters))
		for i, sf := range s.SubFilters {
			sfs[i] = generic.NameObject(sf)
		}
		dict.Set("SubFilter", sfs)
	}

	if len(s.DigestMethods) > 0 {
		dms := make(generic.ArrayObject, len(s.DigestMethods))
		for i, dm := range s.DigestMethods {
			dms[i] = generic.NewLiteralString(dm)
		}
		dict.Set("DigestMethod", dms)
	}

	if s.AddRevInfo != nil {
		dict.Set("AddRevInfo", generic.BooleanObject(*s.AddRevInfo))
	}

	return dict
}

// FieldMDPAction specifies the action for FieldMDP.
type FieldMDPAction string

const (
	FieldMDPActionAll     FieldMDPAction = "All"
	FieldMDPActionInclude FieldMDPAction = "Include"
	FieldMDPActionExclude FieldMDPAction = "Exclude"
)

// FieldMDPSpec represents field modification detection policy.
type FieldMDPSpec struct {
	Action FieldMDPAction
	Fields []string
}

// ToPdfObject converts FieldMDPSpec to a PDF dictionary.
func (f *FieldMDPSpec) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("TransformParams"))
	dict.Set("Action", generic.NameObject(string(f.Action)))
	dict.Set("V", generic.NameObject("1.2"))

	if f.Action != FieldMDPActionAll && len(f.Fields) > 0 {
		fields := make(generic.ArrayObject, len(f.Fields))
		for i, field := range f.Fields {
			fields[i] = generic.NewLiteralString(field)
		}
		dict.Set("Fields", fields)
	}

	return dict
}

// MDPPerm represents Document MDP permission level.
type MDPPerm int

const (
	MDPPermNoChanges MDPPerm = 1
	MDPPermFillForms MDPPerm = 2
	MDPPermAnnotate  MDPPerm = 3
)

// String returns the string representation of MDPPerm.
func (p MDPPerm) String() string {
	switch p {
	case MDPPermNoChanges:
		return "No changes allowed"
	case MDPPermFillForms:
		return "Fill forms and sign"
	case MDPPermAnnotate:
		return "Annotate, fill forms and sign"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}
