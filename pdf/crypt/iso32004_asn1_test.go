package crypt

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestISO32004OIDDefinitions(t *testing.T) {
	t.Run("OIDPdfMacIntegrityInfo", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{1, 0, 32004, 1, 0}
		if !OIDPdfMacIntegrityInfo.Equal(expected) {
			t.Errorf("OIDPdfMacIntegrityInfo = %v, want %v", OIDPdfMacIntegrityInfo, expected)
		}
	})

	t.Run("OIDPdfMacWrapKDF", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{1, 0, 32004, 1, 1}
		if !OIDPdfMacWrapKDF.Equal(expected) {
			t.Errorf("OIDPdfMacWrapKDF = %v, want %v", OIDPdfMacWrapKDF, expected)
		}
	})

	t.Run("OIDPdfMacData", func(t *testing.T) {
		expected := asn1.ObjectIdentifier{1, 0, 32004, 1, 2}
		if !OIDPdfMacData.Equal(expected) {
			t.Errorf("OIDPdfMacData = %v, want %v", OIDPdfMacData, expected)
		}
	})

	t.Run("OIDStrings", func(t *testing.T) {
		if OIDPdfMacIntegrityInfo.String() != OIDStringPdfMacIntegrityInfo {
			t.Errorf("OID string mismatch: %v != %v", OIDPdfMacIntegrityInfo.String(), OIDStringPdfMacIntegrityInfo)
		}
		if OIDPdfMacWrapKDF.String() != OIDStringPdfMacWrapKDF {
			t.Errorf("OID string mismatch: %v != %v", OIDPdfMacWrapKDF.String(), OIDStringPdfMacWrapKDF)
		}
		if OIDPdfMacData.String() != OIDStringPdfMacData {
			t.Errorf("OID string mismatch: %v != %v", OIDPdfMacData.String(), OIDStringPdfMacData)
		}
	})
}

func TestIsISO32004OID(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{"PdfMacIntegrityInfo", OIDPdfMacIntegrityInfo, true},
		{"PdfMacWrapKDF", OIDPdfMacWrapKDF, true},
		{"PdfMacData", OIDPdfMacData, true},
		{"OtherISO32004", asn1.ObjectIdentifier{1, 0, 32004, 1, 99}, true},
		{"ContentType", OIDContentType, false},
		{"MessageDigest", OIDMessageDigest, false},
		{"SHA256", OIDSHA256, false},
		{"Empty", asn1.ObjectIdentifier{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsISO32004OID(tt.oid)
			if got != tt.want {
				t.Errorf("IsISO32004OID(%v) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}

func TestGetISO32004OIDName(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		wantName string
		wantOk   bool
	}{
		{"PdfMacIntegrityInfo", OIDPdfMacIntegrityInfo, ISO32004ContentType, true},
		{"PdfMacWrapKDF", OIDPdfMacWrapKDF, ISO32004KDFType, true},
		{"PdfMacData", OIDPdfMacData, ISO32004AttributeType, true},
		{"Unknown", asn1.ObjectIdentifier{1, 2, 3}, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotOk := GetISO32004OIDName(tt.oid)
			if gotName != tt.wantName || gotOk != tt.wantOk {
				t.Errorf("GetISO32004OIDName(%v) = (%q, %v), want (%q, %v)",
					tt.oid, gotName, gotOk, tt.wantName, tt.wantOk)
			}
		})
	}
}

func TestPdfMacIntegrityInfoStruct(t *testing.T) {
	t.Run("NewPdfMacIntegrityInfo", func(t *testing.T) {
		dataDigest := []byte{0x01, 0x02, 0x03}
		sigDigest := []byte{0x04, 0x05, 0x06}

		info := NewPdfMacIntegrityInfo(dataDigest, sigDigest)

		if info.Version != ISO32004Version {
			t.Errorf("Version = %d, want %d", info.Version, ISO32004Version)
		}
		if !bytes.Equal(info.DataDigest, dataDigest) {
			t.Error("DataDigest mismatch")
		}
		if !bytes.Equal(info.SignatureDigest, sigDigest) {
			t.Error("SignatureDigest mismatch")
		}
	})

	t.Run("NewPdfMacIntegrityInfo_NoSignature", func(t *testing.T) {
		dataDigest := []byte{0x01, 0x02, 0x03}

		info := NewPdfMacIntegrityInfo(dataDigest, nil)

		if info.Version != ISO32004Version {
			t.Errorf("Version = %d, want %d", info.Version, ISO32004Version)
		}
		if !bytes.Equal(info.DataDigest, dataDigest) {
			t.Error("DataDigest mismatch")
		}
		if info.SignatureDigest != nil {
			t.Error("SignatureDigest should be nil")
		}
	})

	t.Run("HasSignatureDigest", func(t *testing.T) {
		infoWithSig := NewPdfMacIntegrityInfo([]byte{1}, []byte{2})
		infoWithoutSig := NewPdfMacIntegrityInfo([]byte{1}, nil)

		if !infoWithSig.HasSignatureDigest() {
			t.Error("HasSignatureDigest should return true")
		}
		if infoWithoutSig.HasSignatureDigest() {
			t.Error("HasSignatureDigest should return false")
		}
	})

	t.Run("Validate_Valid", func(t *testing.T) {
		info := NewPdfMacIntegrityInfo([]byte{1, 2, 3}, nil)
		if err := info.Validate(); err != nil {
			t.Errorf("Validate failed: %v", err)
		}
	})

	t.Run("Validate_EmptyDigest", func(t *testing.T) {
		info := &PdfMacIntegrityInfo{
			Version:    ISO32004Version,
			DataDigest: nil,
		}
		if err := info.Validate(); err == nil {
			t.Error("Validate should fail for empty dataDigest")
		}
	})

	t.Run("Validate_InvalidVersion", func(t *testing.T) {
		info := &PdfMacIntegrityInfo{
			Version:    1,
			DataDigest: []byte{1, 2, 3},
		}
		if err := info.Validate(); err == nil {
			t.Error("Validate should fail for invalid version")
		}
	})
}

func TestPdfMacIntegrityInfo_MarshalUnmarshal(t *testing.T) {
	t.Run("WithSignatureDigest", func(t *testing.T) {
		original := NewPdfMacIntegrityInfo(
			[]byte{0x01, 0x02, 0x03, 0x04},
			[]byte{0x05, 0x06, 0x07, 0x08},
		)

		data, err := MarshalPdfMacIntegrityInfo(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		parsed, err := ParsePdfMacIntegrityInfo(data)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}

		if parsed.Version != original.Version {
			t.Errorf("Version = %d, want %d", parsed.Version, original.Version)
		}
		if !bytes.Equal(parsed.DataDigest, original.DataDigest) {
			t.Error("DataDigest mismatch")
		}
		if !bytes.Equal(parsed.SignatureDigest, original.SignatureDigest) {
			t.Error("SignatureDigest mismatch")
		}
	})

	t.Run("WithoutSignatureDigest", func(t *testing.T) {
		original := NewPdfMacIntegrityInfo(
			[]byte{0x01, 0x02, 0x03, 0x04},
			nil,
		)

		data, err := MarshalPdfMacIntegrityInfo(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		parsed, err := ParsePdfMacIntegrityInfo(data)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}

		if parsed.Version != original.Version {
			t.Errorf("Version = %d, want %d", parsed.Version, original.Version)
		}
		if !bytes.Equal(parsed.DataDigest, original.DataDigest) {
			t.Error("DataDigest mismatch")
		}
		if len(parsed.SignatureDigest) != 0 {
			t.Error("SignatureDigest should be empty")
		}
	})

	t.Run("ParseInvalid", func(t *testing.T) {
		_, err := ParsePdfMacIntegrityInfo([]byte{0x00, 0x01})
		if err == nil {
			t.Error("Parse should fail for invalid data")
		}
	})

	t.Run("ParseWithTrailingData", func(t *testing.T) {
		info := NewPdfMacIntegrityInfo([]byte{1, 2, 3}, nil)
		data, _ := MarshalPdfMacIntegrityInfo(info)
		dataWithTrailing := append(data, 0xFF, 0xFF)

		_, err := ParsePdfMacIntegrityInfo(dataWithTrailing)
		if err == nil {
			t.Error("Parse should fail for data with trailing bytes")
		}
	})
}

func TestKdfAlgorithmId(t *testing.T) {
	t.Run("NewPdfMacKdfAlgorithmId", func(t *testing.T) {
		kdf := NewPdfMacKdfAlgorithmId()
		if !kdf.Algorithm.Equal(OIDPdfMacWrapKDF) {
			t.Errorf("Algorithm = %v, want %v", kdf.Algorithm, OIDPdfMacWrapKDF)
		}
	})

	t.Run("IsPdfMacKdf_True", func(t *testing.T) {
		kdf := NewPdfMacKdfAlgorithmId()
		if !kdf.IsPdfMacKdf() {
			t.Error("IsPdfMacKdf should return true")
		}
	})

	t.Run("IsPdfMacKdf_False", func(t *testing.T) {
		kdf := KdfAlgorithmId{Algorithm: OIDSHA256}
		if kdf.IsPdfMacKdf() {
			t.Error("IsPdfMacKdf should return false")
		}
	})

	t.Run("MarshalUnmarshal", func(t *testing.T) {
		original := NewPdfMacKdfAlgorithmId()

		data, err := asn1.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var parsed KdfAlgorithmId
		_, err = asn1.Unmarshal(data, &parsed)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if !parsed.Algorithm.Equal(original.Algorithm) {
			t.Error("Algorithm mismatch after unmarshal")
		}
	})
}

func TestPdfMacDataAttribute(t *testing.T) {
	t.Run("NewPdfMacDataAttribute", func(t *testing.T) {
		ci := ContentInfo{
			ContentType: OIDAuthenticatedData,
			Content:     asn1.RawValue{FullBytes: []byte{0x01, 0x02}},
		}

		attr := NewPdfMacDataAttribute(ci)

		if !attr.Type.Equal(OIDPdfMacData) {
			t.Errorf("Type = %v, want %v", attr.Type, OIDPdfMacData)
		}
		if len(attr.Values) != 1 {
			t.Errorf("len(Values) = %d, want 1", len(attr.Values))
		}
	})

	t.Run("IsPdfMacDataAttribute_True", func(t *testing.T) {
		attr := &CMSAttribute{Type: OIDPdfMacData}
		if !IsPdfMacDataAttribute(attr) {
			t.Error("IsPdfMacDataAttribute should return true")
		}
	})

	t.Run("IsPdfMacDataAttribute_False", func(t *testing.T) {
		attr := &CMSAttribute{Type: OIDContentType}
		if IsPdfMacDataAttribute(attr) {
			t.Error("IsPdfMacDataAttribute should return false")
		}
	})
}

func TestISO32004Registry(t *testing.T) {
	t.Run("NewISO32004Registry", func(t *testing.T) {
		reg := NewISO32004Registry()
		if reg == nil {
			t.Fatal("Registry is nil")
		}
	})

	t.Run("LookupContentType", func(t *testing.T) {
		reg := NewISO32004Registry()

		name, ok := reg.LookupContentType(OIDPdfMacIntegrityInfo)
		if !ok {
			t.Error("LookupContentType should find OIDPdfMacIntegrityInfo")
		}
		if name != ISO32004ContentType {
			t.Errorf("name = %q, want %q", name, ISO32004ContentType)
		}

		_, ok = reg.LookupContentType(OIDSHA256)
		if ok {
			t.Error("LookupContentType should not find OIDSHA256")
		}
	})

	t.Run("LookupKdfType", func(t *testing.T) {
		reg := NewISO32004Registry()

		name, ok := reg.LookupKdfType(OIDPdfMacWrapKDF)
		if !ok {
			t.Error("LookupKdfType should find OIDPdfMacWrapKDF")
		}
		if name != ISO32004KDFType {
			t.Errorf("name = %q, want %q", name, ISO32004KDFType)
		}

		_, ok = reg.LookupKdfType(OIDSHA256)
		if ok {
			t.Error("LookupKdfType should not find OIDSHA256")
		}
	})

	t.Run("LookupAttrType", func(t *testing.T) {
		reg := NewISO32004Registry()

		name, ok := reg.LookupAttrType(OIDPdfMacData)
		if !ok {
			t.Error("LookupAttrType should find OIDPdfMacData")
		}
		if name != ISO32004AttributeType {
			t.Errorf("name = %q, want %q", name, ISO32004AttributeType)
		}

		_, ok = reg.LookupAttrType(OIDSHA256)
		if ok {
			t.Error("LookupAttrType should not find OIDSHA256")
		}
	})

	t.Run("DefaultRegistry", func(t *testing.T) {
		if DefaultISO32004Registry == nil {
			t.Error("DefaultISO32004Registry is nil")
		}

		name, ok := DefaultISO32004Registry.LookupContentType(OIDPdfMacIntegrityInfo)
		if !ok || name != ISO32004ContentType {
			t.Error("DefaultISO32004Registry should have default registrations")
		}
	})
}

func TestISO32004Constants(t *testing.T) {
	t.Run("ContentType", func(t *testing.T) {
		if ISO32004ContentType != "pdf_mac_integrity_info" {
			t.Errorf("ISO32004ContentType = %q", ISO32004ContentType)
		}
	})

	t.Run("KDFType", func(t *testing.T) {
		if ISO32004KDFType != "pdf_mac_wrap_kdf" {
			t.Errorf("ISO32004KDFType = %q", ISO32004KDFType)
		}
	})

	t.Run("AttributeType", func(t *testing.T) {
		if ISO32004AttributeType != "pdf_mac_data" {
			t.Errorf("ISO32004AttributeType = %q", ISO32004AttributeType)
		}
	})

	t.Run("Version", func(t *testing.T) {
		if ISO32004Version != 0 {
			t.Errorf("ISO32004Version = %d", ISO32004Version)
		}
	})
}

func TestPdfMacIntegrityInfo_ASN1Structure(t *testing.T) {
	// Test that the ASN.1 structure matches ISO 32004 specification
	t.Run("VersionIsFirst", func(t *testing.T) {
		info := NewPdfMacIntegrityInfo([]byte{1, 2, 3}, nil)
		data, err := asn1.Marshal(*info)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		// Should be a SEQUENCE
		if data[0] != 0x30 {
			t.Errorf("Expected SEQUENCE tag (0x30), got 0x%02x", data[0])
		}
	})

	t.Run("OptionalSignatureDigest", func(t *testing.T) {
		// Without signature digest
		infoNoSig := NewPdfMacIntegrityInfo([]byte{1, 2, 3}, nil)
		dataNoSig, _ := asn1.Marshal(*infoNoSig)

		// With signature digest
		infoWithSig := NewPdfMacIntegrityInfo([]byte{1, 2, 3}, []byte{4, 5, 6})
		dataWithSig, _ := asn1.Marshal(*infoWithSig)

		// Data with signature should be longer
		if len(dataWithSig) <= len(dataNoSig) {
			t.Error("Data with signature digest should be longer")
		}
	})
}

func TestSetOfContentInfo(t *testing.T) {
	t.Run("EmptySet", func(t *testing.T) {
		var set SetOfContentInfo
		if len(set) != 0 {
			t.Errorf("Empty set should have length 0, got %d", len(set))
		}
	})

	t.Run("SingleItem", func(t *testing.T) {
		ci := ContentInfo{
			ContentType: OIDAuthenticatedData,
		}
		set := SetOfContentInfo{ci}
		if len(set) != 1 {
			t.Errorf("Set should have length 1, got %d", len(set))
		}
	})

	t.Run("MultipleItems", func(t *testing.T) {
		ci1 := ContentInfo{ContentType: OIDAuthenticatedData}
		ci2 := ContentInfo{ContentType: OIDPdfMacIntegrityInfo}
		set := SetOfContentInfo{ci1, ci2}
		if len(set) != 2 {
			t.Errorf("Set should have length 2, got %d", len(set))
		}
	})
}
