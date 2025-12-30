package diff

import (
	"testing"
)

func TestVRIKeyPattern(t *testing.T) {
	validKeys := []string{
		"/ABCD1234567890ABCD1234567890ABCD12345678",
		"/0123456789ABCDEF0123456789ABCDEF01234567",
		"/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	invalidKeys := []string{
		"/ABC",                                      // Too short
		"/ABCD1234567890ABCD1234567890ABCD123456789", // Too long
		"/abcd1234567890abcd1234567890abcd12345678",  // Lowercase not allowed
		"ABCD1234567890ABCD1234567890ABCD12345678",   // Missing leading slash
		"/ABCD1234567890ABCD1234567890ABCD1234567!",  // Invalid character
	}

	for _, key := range validKeys {
		if !VRIKeyPattern.MatchString(key) {
			t.Errorf("expected %q to match VRI key pattern", key)
		}
		if !IsVRIKey(key) {
			t.Errorf("IsVRIKey(%q) should be true", key)
		}
	}

	for _, key := range invalidKeys {
		if VRIKeyPattern.MatchString(key) {
			t.Errorf("expected %q to NOT match VRI key pattern", key)
		}
		if IsVRIKey(key) {
			t.Errorf("IsVRIKey(%q) should be false", key)
		}
	}
}

func TestFormFieldAlwaysModifiable(t *testing.T) {
	modifiable := []string{"/Ff", "/Type"}
	notModifiable := []string{"/V", "/AP", "/AS", "/Other"}

	for _, key := range modifiable {
		if !FormFieldAlwaysModifiable[key] {
			t.Errorf("%q should be in FormFieldAlwaysModifiable", key)
		}
		if !IsFormFieldAlwaysModifiable(key) {
			t.Errorf("IsFormFieldAlwaysModifiable(%q) should be true", key)
		}
	}

	for _, key := range notModifiable {
		if FormFieldAlwaysModifiable[key] {
			t.Errorf("%q should NOT be in FormFieldAlwaysModifiable", key)
		}
		if IsFormFieldAlwaysModifiable(key) {
			t.Errorf("IsFormFieldAlwaysModifiable(%q) should be false", key)
		}
	}
}

func TestValueUpdateKeys(t *testing.T) {
	updateKeys := []string{"/Ff", "/Type", "/AP", "/AS", "/V", "/F", "/DA", "/Q"}
	notUpdateKeys := []string{"/Other", "/Lock", "/SV"}

	for _, key := range updateKeys {
		if !ValueUpdateKeys[key] {
			t.Errorf("%q should be in ValueUpdateKeys", key)
		}
		if !IsValueUpdateKey(key) {
			t.Errorf("IsValueUpdateKey(%q) should be true", key)
		}
	}

	for _, key := range notUpdateKeys {
		if ValueUpdateKeys[key] {
			t.Errorf("%q should NOT be in ValueUpdateKeys", key)
		}
		if IsValueUpdateKey(key) {
			t.Errorf("IsValueUpdateKey(%q) should be false", key)
		}
	}
}

func TestAcroFormExemptStrictComparison(t *testing.T) {
	exempt := []string{"/Fields", "/DR", "/DA", "/Q", "/NeedAppearances"}
	notExempt := []string{"/Type", "/Other"}

	for _, key := range exempt {
		if !AcroFormExemptStrictComparison[key] {
			t.Errorf("%q should be in AcroFormExemptStrictComparison", key)
		}
		if !IsAcroFormExempt(key) {
			t.Errorf("IsAcroFormExempt(%q) should be true", key)
		}
	}

	for _, key := range notExempt {
		if AcroFormExemptStrictComparison[key] {
			t.Errorf("%q should NOT be in AcroFormExemptStrictComparison", key)
		}
		if IsAcroFormExempt(key) {
			t.Errorf("IsAcroFormExempt(%q) should be false", key)
		}
	}
}

func TestDSSExpectedKeys(t *testing.T) {
	expected := []string{"/Type", "/VRI", "/Certs", "/CRLs", "/OCSPs"}
	notExpected := []string{"/Other", "/Unknown"}

	for _, key := range expected {
		if !DSSExpectedKeys[key] {
			t.Errorf("%q should be in DSSExpectedKeys", key)
		}
		if !IsDSSExpectedKey(key) {
			t.Errorf("IsDSSExpectedKey(%q) should be true", key)
		}
	}

	for _, key := range notExpected {
		if DSSExpectedKeys[key] {
			t.Errorf("%q should NOT be in DSSExpectedKeys", key)
		}
		if IsDSSExpectedKey(key) {
			t.Errorf("IsDSSExpectedKey(%q) should be false", key)
		}
	}
}

func TestVRIExpectedKeys(t *testing.T) {
	expected := []string{"/Type", "/TU", "/TS", "/Cert", "/CRL", "/OCSP"}
	notExpected := []string{"/Other", "/Unknown"}

	for _, key := range expected {
		if !VRIExpectedKeys[key] {
			t.Errorf("%q should be in VRIExpectedKeys", key)
		}
		if !IsVRIExpectedKey(key) {
			t.Errorf("IsVRIExpectedKey(%q) should be true", key)
		}
	}

	for _, key := range notExpected {
		if VRIExpectedKeys[key] {
			t.Errorf("%q should NOT be in VRIExpectedKeys", key)
		}
		if IsVRIExpectedKey(key) {
			t.Errorf("IsVRIExpectedKey(%q) should be false", key)
		}
	}
}

func TestDSSStreamKeys(t *testing.T) {
	streamKeys := []string{"/Certs", "/CRLs", "/OCSPs"}
	notStreamKeys := []string{"/Type", "/VRI"}

	for _, key := range streamKeys {
		if !DSSStreamKeys[key] {
			t.Errorf("%q should be in DSSStreamKeys", key)
		}
	}

	for _, key := range notStreamKeys {
		if DSSStreamKeys[key] {
			t.Errorf("%q should NOT be in DSSStreamKeys", key)
		}
	}
}

func TestVRIStreamKeys(t *testing.T) {
	streamKeys := []string{"/Cert", "/CRL", "/OCSP"}
	notStreamKeys := []string{"/Type", "/TU", "/TS"}

	for _, key := range streamKeys {
		if !VRIStreamKeys[key] {
			t.Errorf("%q should be in VRIStreamKeys", key)
		}
	}

	for _, key := range notStreamKeys {
		if VRIStreamKeys[key] {
			t.Errorf("%q should NOT be in VRIStreamKeys", key)
		}
	}
}

func TestAppearanceKeys(t *testing.T) {
	apKeys := []string{"/N", "/R", "/D"}
	notApKeys := []string{"/Other", "/AP"}

	for _, key := range apKeys {
		if !AppearanceKeys[key] {
			t.Errorf("%q should be in AppearanceKeys", key)
		}
	}

	for _, key := range notApKeys {
		if AppearanceKeys[key] {
			t.Errorf("%q should NOT be in AppearanceKeys", key)
		}
	}
}

func TestSignatureFieldType(t *testing.T) {
	if SigFieldTypeSignature != "/Sig" {
		t.Errorf("SigFieldTypeSignature should be /Sig, got %s", SigFieldTypeSignature)
	}
	if SigFieldTypeDocTimeStamp != "/DocTimeStamp" {
		t.Errorf("SigFieldTypeDocTimeStamp should be /DocTimeStamp, got %s", SigFieldTypeDocTimeStamp)
	}
}

func TestAnnotationFlagBits(t *testing.T) {
	// Test that flag bits are correct powers of 2
	expectedFlags := map[AnnotationFlagBits]int{
		AnnotFlagInvisible:       1,
		AnnotFlagHidden:          2,
		AnnotFlagPrint:           4,
		AnnotFlagNoZoom:          8,
		AnnotFlagNoRotate:        16,
		AnnotFlagNoView:          32,
		AnnotFlagReadOnly:        64,
		AnnotFlagLocked:          128,
		AnnotFlagToggleNoView:    256,
		AnnotFlagLockedContents:  512,
	}

	for flag, expected := range expectedFlags {
		if int(flag) != expected {
			t.Errorf("flag %d should be %d", flag, expected)
		}
	}
}

func TestFormFieldFlagBits(t *testing.T) {
	expectedFlags := map[FormFieldFlagBits]int{
		FieldFlagReadOnly: 1,
		FieldFlagRequired: 2,
		FieldFlagNoExport: 4,
	}

	for flag, expected := range expectedFlags {
		if int(flag) != expected {
			t.Errorf("flag %d should be %d", flag, expected)
		}
	}
}

func TestSignatureFieldKeys(t *testing.T) {
	sigKeys := []string{"/Lock", "/SV"}
	for _, key := range sigKeys {
		if !SignatureFieldKeys[key] {
			t.Errorf("%q should be in SignatureFieldKeys", key)
		}
	}
}
