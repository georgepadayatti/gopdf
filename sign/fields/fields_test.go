package fields

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/form"
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestSignatureFormFieldIsSigned(t *testing.T) {
	field := &SignatureFormField{Name: "Sig1"}
	if field.IsSigned() {
		t.Error("Empty field should not be signed")
	}

	field.Value = generic.NewDictionary()
	if !field.IsSigned() {
		t.Error("Field with value should be signed")
	}
}

func TestSigSeedSubFilter(t *testing.T) {
	tests := []struct {
		sf       SigSeedSubFilter
		expected string
	}{
		{SubFilterAdobePKCS7Detached, "adbe.pkcs7.detached"},
		{SubFilterAdobePKCS7SHA1, "adbe.pkcs7.sha1"},
		{SubFilterETSICAdESDetached, "ETSI.CAdES.detached"},
		{SubFilterETSIRFC3161, "ETSI.RFC3161"},
	}

	for _, tt := range tests {
		if string(tt.sf) != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.sf)
		}
	}
}

func TestSeedSignatureTypeIsCertification(t *testing.T) {
	sst := &SeedSignatureType{}
	if sst.IsCertification() {
		t.Error("Should not be certification without MDPPerm")
	}

	perm := form.MDPPermNoChanges
	sst.MDPPerm = &perm
	if !sst.IsCertification() {
		t.Error("Should be certification with MDPPerm")
	}
}

func TestSignatureFieldBuilder(t *testing.T) {
	rect := &generic.Rectangle{LLX: 100, LLY: 100, URX: 300, URY: 150}

	spec := NewSignatureFieldBuilder("Signature1").
		OnPage(0).
		WithBox(rect).
		WithDocMDP(form.MDPPermFillForms).
		Build()

	if spec.SigFieldName != "Signature1" {
		t.Errorf("Expected name 'Signature1', got '%s'", spec.SigFieldName)
	}
	if spec.OnPage != 0 {
		t.Errorf("Expected page 0, got %d", spec.OnPage)
	}
	if spec.Box != rect {
		t.Error("Box not set correctly")
	}
	if spec.DocMDPPerms == nil || *spec.DocMDPPerms != form.MDPPermFillForms {
		t.Error("DocMDPPerms not set correctly")
	}
}

func TestSignatureFieldBuilderInvisible(t *testing.T) {
	spec := NewSignatureFieldBuilder("InvisibleSig").
		Invisible().
		Build()

	if !spec.InvisibleSig {
		t.Error("Should be invisible")
	}
}

func TestSignatureFieldBuilderWithSeedValue(t *testing.T) {
	sv := &SigSeedValueSpec{
		Reasons: []string{"Approval"},
	}

	spec := NewSignatureFieldBuilder("Sig").
		WithSeedValue(sv).
		Build()

	if spec.SeedValueDict != sv {
		t.Error("SeedValueDict not set correctly")
	}
}

func TestCreateSignatureFieldEmpty(t *testing.T) {
	spec := &SigFieldSpec{}
	_, err := CreateSignatureField(spec)
	if err == nil {
		t.Error("Should fail with empty field name")
	}
}

func TestCreateSignatureFieldBasic(t *testing.T) {
	spec := &SigFieldSpec{
		SigFieldName: "TestSig",
		InvisibleSig: true,
	}

	field, err := CreateSignatureField(spec)
	if err != nil {
		t.Fatalf("CreateSignatureField failed: %v", err)
	}

	// Check FT
	ftObj := field.Get("FT")
	if ftObj != generic.NameObject("Sig") {
		t.Error("Expected FT Sig")
	}

	// Check T (name)
	tObj := field.Get("T")
	if strObj, ok := tObj.(*generic.StringObject); !ok || string(strObj.Value) != "TestSig" {
		t.Error("Expected T TestSig")
	}

	// Check Rect (should be zeros for invisible)
	rectObj := field.Get("Rect")
	rect, ok := rectObj.(generic.ArrayObject)
	if !ok || len(rect) != 4 {
		t.Error("Expected Rect array with 4 elements")
	}
}

func TestCreateSignatureFieldVisible(t *testing.T) {
	spec := &SigFieldSpec{
		SigFieldName: "VisibleSig",
		Box:          &generic.Rectangle{LLX: 100, LLY: 100, URX: 200, URY: 150},
	}

	field, err := CreateSignatureField(spec)
	if err != nil {
		t.Fatalf("CreateSignatureField failed: %v", err)
	}

	rectObj := field.Get("Rect")
	rect, ok := rectObj.(generic.ArrayObject)
	if !ok || len(rect) != 4 {
		t.Error("Expected Rect array with 4 elements")
	}
}

func TestCreateSignatureFieldWithSeedValue(t *testing.T) {
	addRevInfo := true
	spec := &SigFieldSpec{
		SigFieldName: "SigWithSeed",
		SeedValueDict: &SigSeedValueSpec{
			Flags:      SigSeedFlagReasons,
			Reasons:    []string{"Approval"},
			AddRevInfo: &addRevInfo,
		},
	}

	field, err := CreateSignatureField(spec)
	if err != nil {
		t.Fatalf("CreateSignatureField failed: %v", err)
	}

	svObj := field.Get("SV")
	if svObj == nil {
		t.Error("Expected SV dictionary")
	}
}

func TestCreateSignatureFieldWithLock(t *testing.T) {
	spec := &SigFieldSpec{
		SigFieldName: "SigWithLock",
		FieldMDPSpec: &FieldMDPSpec{
			Action: FieldMDPActionInclude,
			Fields: []string{"Field1", "Field2"},
		},
	}

	field, err := CreateSignatureField(spec)
	if err != nil {
		t.Fatalf("CreateSignatureField failed: %v", err)
	}

	lockObj := field.Get("Lock")
	if lockObj == nil {
		t.Error("Expected Lock dictionary")
	}
}

func TestSigSeedValueSpecToPdfObject(t *testing.T) {
	addRevInfo := true
	lockDoc := SeedLockDocumentLock
	perm := form.MDPPermNoChanges

	spec := &SigSeedValueSpec{
		Flags:              SigSeedFlagReasons | SigSeedFlagDigestMethod,
		Reasons:            []string{"Approval", "Review"},
		TimestampServerURL: "http://timestamp.example.com",
		TimestampRequired:  true,
		SubFilters:         []SigSeedSubFilter{SubFilterAdobePKCS7Detached},
		DigestMethods:      []string{"SHA256"},
		AddRevInfo:         &addRevInfo,
		SeedSignatureType:  &SeedSignatureType{MDPPerm: &perm},
		LockDocument:       &lockDoc,
	}

	dict := spec.ToPdfObject()

	// Check Type
	if dict.Get("Type") != generic.NameObject("SV") {
		t.Error("Expected Type SV")
	}

	// Check Reasons
	reasonsObj := dict.Get("Reasons")
	reasons, ok := reasonsObj.(generic.ArrayObject)
	if !ok || len(reasons) != 2 {
		t.Error("Expected 2 reasons")
	}

	// Check TimeStamp
	tsObj := dict.Get("TimeStamp")
	if tsObj == nil {
		t.Error("Expected TimeStamp dictionary")
	}

	// Check SubFilter
	sfObj := dict.Get("SubFilter")
	if sfObj == nil {
		t.Error("Expected SubFilter array")
	}

	// Check DigestMethod
	dmObj := dict.Get("DigestMethod")
	if dmObj == nil {
		t.Error("Expected DigestMethod array")
	}

	// Check AddRevInfo
	if dict.Get("AddRevInfo") != generic.BooleanObject(true) {
		t.Error("Expected AddRevInfo true")
	}

	// Check MDP
	mdpObj := dict.Get("MDP")
	if mdpObj == nil {
		t.Error("Expected MDP")
	}

	// Check LockDocument
	lockDocObj := dict.Get("LockDocument")
	if lockDocObj != generic.NameObject("true") {
		t.Error("Expected LockDocument true")
	}
}

func TestSigSeedValueSpecLockDocumentValues(t *testing.T) {
	tests := []struct {
		lockDoc  SeedLockDocument
		expected generic.NameObject
	}{
		{SeedLockDocumentLock, generic.NameObject("true")},
		{SeedLockDocumentDoNotLock, generic.NameObject("false")},
		{SeedLockDocumentSignerDiscretion, generic.NameObject("auto")},
	}

	for _, tt := range tests {
		spec := &SigSeedValueSpec{
			LockDocument: &tt.lockDoc,
		}
		dict := spec.ToPdfObject()
		if dict.Get("LockDocument") != tt.expected {
			t.Errorf("Expected %v, got %v", tt.expected, dict.Get("LockDocument"))
		}
	}
}

func TestFieldMDPSpecToPdfObject(t *testing.T) {
	spec := &FieldMDPSpec{
		Action: FieldMDPActionInclude,
		Fields: []string{"Field1", "Field2"},
	}

	dict := spec.ToPdfObject()

	if dict.Get("Type") != generic.NameObject("TransformParams") {
		t.Error("Expected Type TransformParams")
	}
	if dict.Get("Action") != generic.NameObject("Include") {
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

func TestSigFieldLockSpecToPdfObject(t *testing.T) {
	spec := &SigFieldLockSpec{
		Action: FieldMDPActionExclude,
		Fields: []string{"SecretField"},
	}

	dict := spec.ToPdfObject()

	if dict.Get("Type") != generic.NameObject("SigFieldLock") {
		t.Error("Expected Type SigFieldLock")
	}
	if dict.Get("Action") != generic.NameObject("Exclude") {
		t.Error("Expected Action Exclude")
	}
}

func TestEnsureSigFlags(t *testing.T) {
	dict := generic.NewDictionary()

	// Initial flags should be 0
	EnsureSigFlags(dict, form.SigFlagSignaturesExist)

	flagsObj := dict.Get("SigFlags")
	if flagsObj != generic.IntegerObject(form.SigFlagSignaturesExist) {
		t.Error("SigFlags should be 1")
	}

	// Add more flags
	EnsureSigFlags(dict, form.SigFlagAppendOnly)

	flagsObj = dict.Get("SigFlags")
	expectedFlags := form.SigFlagSignaturesExist | form.SigFlagAppendOnly
	if flagsObj != generic.IntegerObject(expectedFlags) {
		t.Errorf("SigFlags should be %d", expectedFlags)
	}
}

func TestArrayToRect(t *testing.T) {
	arr := generic.ArrayObject{
		generic.RealObject(100),
		generic.RealObject(200),
		generic.RealObject(300),
		generic.RealObject(400),
	}

	rect := arrayToRect(arr)
	if rect == nil {
		t.Fatal("rect should not be nil")
	}

	if rect.LLX != 100 || rect.LLY != 200 || rect.URX != 300 || rect.URY != 400 {
		t.Error("Rectangle values incorrect")
	}
}

func TestArrayToRectInvalid(t *testing.T) {
	arr := generic.ArrayObject{generic.RealObject(100)}
	rect := arrayToRect(arr)
	if rect != nil {
		t.Error("Invalid array should return nil")
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

func TestEnumerateSignatureFieldsEmpty(t *testing.T) {
	_, err := EnumerateSignatureFields(nil)
	if err != form.ErrNoAcroForm {
		t.Errorf("Expected ErrNoAcroForm, got %v", err)
	}
}

func TestFindEmptySignatureFieldNotFound(t *testing.T) {
	dict := generic.NewDictionary()
	dict.Set("Fields", generic.ArrayObject{})

	_, err := FindEmptySignatureField(dict, "NonExistent")
	if err == nil {
		t.Error("Should return error for non-existent field")
	}
}
