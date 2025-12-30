package form

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestFieldType(t *testing.T) {
	tests := []struct {
		ft       FieldType
		expected string
	}{
		{FieldTypeButton, "/Btn"},
		{FieldTypeText, "/Tx"},
		{FieldTypeChoice, "/Ch"},
		{FieldTypeSignature, "/Sig"},
	}

	for _, tt := range tests {
		if string(tt.ft) != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.ft)
		}
	}
}

func TestFieldFlags(t *testing.T) {
	flags := FieldFlagReadOnly | FieldFlagRequired

	if flags&FieldFlagReadOnly == 0 {
		t.Error("ReadOnly flag should be set")
	}
	if flags&FieldFlagRequired == 0 {
		t.Error("Required flag should be set")
	}
	if flags&FieldFlagNoExport != 0 {
		t.Error("NoExport flag should not be set")
	}
}

func TestFormFieldIsFilled(t *testing.T) {
	field := &FormField{Name: "test"}
	if field.IsFilled() {
		t.Error("Empty field should not be filled")
	}

	field.Value = "some value"
	if !field.IsFilled() {
		t.Error("Field with value should be filled")
	}
}

func TestFormFieldIsReadOnly(t *testing.T) {
	field := &FormField{Name: "test", Flags: 0}
	if field.IsReadOnly() {
		t.Error("Field without ReadOnly flag should not be read-only")
	}

	field.Flags = FieldFlagReadOnly
	if !field.IsReadOnly() {
		t.Error("Field with ReadOnly flag should be read-only")
	}
}

func TestGetAnnotationRect(t *testing.T) {
	dict := generic.NewDictionary()
	dict.Set("Rect", generic.ArrayObject{
		generic.RealObject(100),
		generic.RealObject(200),
		generic.RealObject(300),
		generic.RealObject(400),
	})

	width, height, err := GetAnnotationRect(dict)
	if err != nil {
		t.Fatalf("GetAnnotationRect failed: %v", err)
	}

	if width != 200 {
		t.Errorf("Expected width 200, got %f", width)
	}
	if height != 200 {
		t.Errorf("Expected height 200, got %f", height)
	}
}

func TestGetAnnotationRectMissing(t *testing.T) {
	dict := generic.NewDictionary()

	width, height, err := GetAnnotationRect(dict)
	if err != nil {
		t.Fatalf("GetAnnotationRect failed: %v", err)
	}

	if width != 0 || height != 0 {
		t.Error("Missing Rect should return 0, 0")
	}
}

func TestFieldEnumerator(t *testing.T) {
	enumerator := NewFieldEnumerator().
		WithType(FieldTypeSignature).
		EmptyOnly().
		WithName("Signature1")

	if enumerator.targetType != FieldTypeSignature {
		t.Error("Target type not set")
	}
	if enumerator.withName != "Signature1" {
		t.Error("With name not set")
	}
	if enumerator.filledStatus == nil || *enumerator.filledStatus {
		t.Error("Filled status not set to false")
	}
}

func TestParseAcroFormEmpty(t *testing.T) {
	_, err := ParseAcroForm(nil)
	if err != ErrNoAcroForm {
		t.Errorf("Expected ErrNoAcroForm, got %v", err)
	}
}

func TestParseAcroFormBasic(t *testing.T) {
	dict := generic.NewDictionary()
	dict.Set("Fields", generic.ArrayObject{})
	dict.Set("SigFlags", generic.IntegerObject(3))
	dict.Set("NeedAppearances", generic.BooleanObject(true))
	dict.Set("DA", generic.NewLiteralString("/Helv 0 Tf 0 g"))

	form, err := ParseAcroForm(dict)
	if err != nil {
		t.Fatalf("ParseAcroForm failed: %v", err)
	}

	if form.SigFlags != 3 {
		t.Errorf("Expected SigFlags 3, got %d", form.SigFlags)
	}
	if !form.NeedAppearances {
		t.Error("Expected NeedAppearances to be true")
	}
	if form.DA != "/Helv 0 Tf 0 g" {
		t.Errorf("Expected DA '/Helv 0 Tf 0 g', got '%s'", form.DA)
	}
}

func TestAcroFormHasSignatures(t *testing.T) {
	form := &AcroForm{SigFlags: SigFlagSignaturesExist}
	if !form.HasSignatures() {
		t.Error("Form should have signatures")
	}

	form.SigFlags = 0
	if form.HasSignatures() {
		t.Error("Form should not have signatures")
	}
}

func TestAcroFormIsAppendOnly(t *testing.T) {
	form := &AcroForm{SigFlags: SigFlagAppendOnly}
	if !form.IsAppendOnly() {
		t.Error("Form should be append-only")
	}

	form.SigFlags = 0
	if form.IsAppendOnly() {
		t.Error("Form should not be append-only")
	}
}

func TestSigSeedValueToPdfObject(t *testing.T) {
	addRevInfo := true
	sv := &SigSeedValue{
		Flags:         SigSeedFlagReasons | SigSeedFlagDigestMethod,
		Reasons:       []string{"Approval", "Review"},
		DigestMethods: []string{"SHA256", "SHA384"},
		AddRevInfo:    &addRevInfo,
	}

	dict := sv.ToPdfObject()

	// Check type
	typeObj := dict.Get("Type")
	if typeObj != generic.NameObject("SV") {
		t.Error("Expected Type SV")
	}

	// Check flags
	flagsObj := dict.Get("Ff")
	if flagsObj != generic.IntegerObject(SigSeedFlagReasons|SigSeedFlagDigestMethod) {
		t.Error("Flags mismatch")
	}

	// Check reasons
	reasonsObj := dict.Get("Reasons")
	reasons, ok := reasonsObj.(generic.ArrayObject)
	if !ok || len(reasons) != 2 {
		t.Error("Expected 2 reasons")
	}

	// Check digest methods
	dmsObj := dict.Get("DigestMethod")
	dms, ok := dmsObj.(generic.ArrayObject)
	if !ok || len(dms) != 2 {
		t.Error("Expected 2 digest methods")
	}

	// Check AddRevInfo
	revInfoObj := dict.Get("AddRevInfo")
	if revInfoObj != generic.BooleanObject(true) {
		t.Error("Expected AddRevInfo true")
	}
}

func TestFieldMDPSpecToPdfObject(t *testing.T) {
	spec := &FieldMDPSpec{
		Action: FieldMDPActionInclude,
		Fields: []string{"Field1", "Field2"},
	}

	dict := spec.ToPdfObject()

	actionObj := dict.Get("Action")
	if actionObj != generic.NameObject("Include") {
		t.Error("Expected Action Include")
	}

	fieldsObj := dict.Get("Fields")
	fields, ok := fieldsObj.(generic.ArrayObject)
	if !ok || len(fields) != 2 {
		t.Error("Expected 2 fields")
	}
}

func TestFieldMDPSpecAllAction(t *testing.T) {
	spec := &FieldMDPSpec{
		Action: FieldMDPActionAll,
	}

	dict := spec.ToPdfObject()

	// Fields should not be present for All action
	if dict.Get("Fields") != nil {
		t.Error("Fields should not be present for All action")
	}
}

func TestMDPPermString(t *testing.T) {
	tests := []struct {
		perm     MDPPerm
		expected string
	}{
		{MDPPermNoChanges, "No changes allowed"},
		{MDPPermFillForms, "Fill forms and sign"},
		{MDPPermAnnotate, "Annotate, fill forms and sign"},
		{MDPPerm(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		if tt.perm.String() != tt.expected {
			t.Errorf("Expected '%s', got '%s'", tt.expected, tt.perm.String())
		}
	}
}

func TestAbsFunction(t *testing.T) {
	if abs(-5) != 5 {
		t.Error("abs(-5) should be 5")
	}
	if abs(5) != 5 {
		t.Error("abs(5) should be 5")
	}
	if abs(0) != 0 {
		t.Error("abs(0) should be 0")
	}
}

func TestGetFloat(t *testing.T) {
	tests := []struct {
		obj      generic.PdfObject
		expected float64
	}{
		{generic.IntegerObject(42), 42.0},
		{generic.RealObject(3.14), 3.14},
	}

	for _, tt := range tests {
		result := getFloat(tt.obj)
		if result != tt.expected {
			t.Errorf("Expected %f, got %f", tt.expected, result)
		}
	}
}
