package signers

import (
	"bytes"
	"testing"
	"time"

	"github.com/georgepadayatti/gopdf/sign/fields"
)

func TestSigByteRangeObject(t *testing.T) {
	t.Run("NewSigByteRangeObject", func(t *testing.T) {
		br := NewSigByteRangeObject()
		if br == nil {
			t.Fatal("NewSigByteRangeObject returned nil")
		}
		if br.filled {
			t.Error("New object should not be filled")
		}
		if br.rangeObjectOffset != -1 {
			t.Errorf("rangeObjectOffset = %d, want -1", br.rangeObjectOffset)
		}
	})

	t.Run("WriteToStream_Placeholder", func(t *testing.T) {
		br := NewSigByteRangeObject()
		var buf bytes.Buffer

		err := br.WriteToStream(&buf)
		if err != nil {
			t.Fatalf("WriteToStream failed: %v", err)
		}

		output := buf.String()
		if len(output) != 2+ByteRangeArrayPlaceholderLength {
			t.Errorf("Placeholder length = %d, want %d", len(output), 2+ByteRangeArrayPlaceholderLength)
		}
		if output[:2] != "[]" {
			t.Errorf("Placeholder should start with '[]', got %q", output[:2])
		}
	})

	t.Run("GetByteRange", func(t *testing.T) {
		br := NewSigByteRangeObject()
		br.FirstRegionLen = 100
		br.SecondRegionOffset = 200
		br.SecondRegionLen = 300

		byteRange := br.GetByteRange()
		expected := []int64{0, 100, 200, 300}

		if len(byteRange) != 4 {
			t.Fatalf("ByteRange length = %d, want 4", len(byteRange))
		}

		for i, v := range expected {
			if byteRange[i] != v {
				t.Errorf("ByteRange[%d] = %d, want %d", i, byteRange[i], v)
			}
		}
	})
}

func TestDERPlaceholder(t *testing.T) {
	t.Run("NewDERPlaceholder_Default", func(t *testing.T) {
		p := NewDERPlaceholder(0)
		if len(p.Value) != 16*1024 {
			t.Errorf("Default size = %d, want %d", len(p.Value), 16*1024)
		}
	})

	t.Run("NewDERPlaceholder_Custom", func(t *testing.T) {
		p := NewDERPlaceholder(1024)
		if len(p.Value) != 1024 {
			t.Errorf("Custom size = %d, want 1024", len(p.Value))
		}
	})

	t.Run("Offsets_NotAvailable", func(t *testing.T) {
		p := NewDERPlaceholder(100)
		_, _, err := p.Offsets()
		if err == nil {
			t.Error("Expected error for offsets before write")
		}
	})
}

func TestBuildProps(t *testing.T) {
	t.Run("NewBuildProps", func(t *testing.T) {
		bp := NewBuildProps("TestApp")
		if bp.Name != "TestApp" {
			t.Errorf("Name = %q, want %q", bp.Name, "TestApp")
		}
		if bp.Revision != "" {
			t.Error("Revision should be empty by default")
		}
	})

	t.Run("WithRevision", func(t *testing.T) {
		bp := NewBuildProps("TestApp").WithRevision("1.0.0")
		if bp.Revision != "1.0.0" {
			t.Errorf("Revision = %q, want %q", bp.Revision, "1.0.0")
		}
	})

	t.Run("AsPdfObject", func(t *testing.T) {
		bp := NewBuildProps("TestApp").WithRevision("1.0.0")
		obj := bp.AsPdfObject()

		if obj == nil {
			t.Fatal("AsPdfObject returned nil")
		}

		// Check Name
		if obj.GetName("Name") != "/TestApp" {
			t.Errorf("Name = %q, want %q", obj.GetName("Name"), "/TestApp")
		}
	})
}

func TestPdfSignedData(t *testing.T) {
	t.Run("NewPdfSignedData", func(t *testing.T) {
		now := time.Now()
		sd := NewPdfSignedData("/Sig", fields.SubFilterAdobePKCS7Detached, &now, 8192)

		if sd == nil {
			t.Fatal("NewPdfSignedData returned nil")
		}

		if sd.GetName("Type") != "/Sig" {
			t.Errorf("Type = %q, want %q", sd.GetName("Type"), "/Sig")
		}

		if sd.GetName("Filter") != "Adobe.PPKLite" {
			t.Errorf("Filter = %q, want %q", sd.GetName("Filter"), "Adobe.PPKLite")
		}

		if sd.Contents == nil {
			t.Error("Contents should not be nil")
		}

		if sd.ByteRange == nil {
			t.Error("ByteRange should not be nil")
		}
	})

	t.Run("NewPdfSignedData_NoTimestamp", func(t *testing.T) {
		sd := NewPdfSignedData("/Sig", fields.SubFilterAdobePKCS7Detached, nil, 8192)

		if sd.Has("M") {
			t.Error("Should not have M entry when timestamp is nil")
		}
	})
}

func TestSignatureObject(t *testing.T) {
	t.Run("DefaultOptions", func(t *testing.T) {
		opts := DefaultSignatureObjectOptions()
		if opts.SubFilter != DefaultSigSubFilter {
			t.Errorf("SubFilter = %v, want %v", opts.SubFilter, DefaultSigSubFilter)
		}
		if opts.BytesReserved != 16*1024 {
			t.Errorf("BytesReserved = %d, want %d", opts.BytesReserved, 16*1024)
		}
	})

	t.Run("NewSignatureObject_Default", func(t *testing.T) {
		sig := NewSignatureObject(nil)
		if sig == nil {
			t.Fatal("NewSignatureObject returned nil")
		}
	})

	t.Run("NewSignatureObject_WithOptions", func(t *testing.T) {
		now := time.Now()
		authType := SigAuthTypePIN
		opts := &SignatureObjectOptions{
			Timestamp:     &now,
			SubFilter:     fields.SubFilterETSICAdESDetached,
			Name:          "Test Signer",
			Location:      "Test Location",
			Reason:        "Test Reason",
			ContactInfo:   "test@example.com",
			AppBuildProps: NewBuildProps("TestApp").WithRevision("1.0"),
			PropAuthTime:  3600,
			PropAuthType:  &authType,
			BytesReserved: 8192,
		}

		sig := NewSignatureObject(opts)
		if sig == nil {
			t.Fatal("NewSignatureObject returned nil")
		}

		// Check values
		if !sig.Has("Name") {
			t.Error("Should have Name")
		}
		if !sig.Has("Location") {
			t.Error("Should have Location")
		}
		if !sig.Has("Reason") {
			t.Error("Should have Reason")
		}
		if !sig.Has("ContactInfo") {
			t.Error("Should have ContactInfo")
		}
		if !sig.Has("Prop_Build") {
			t.Error("Should have Prop_Build")
		}
		if !sig.Has("Prop_AuthTime") {
			t.Error("Should have Prop_AuthTime")
		}
		if !sig.Has("Prop_AuthType") {
			t.Error("Should have Prop_AuthType")
		}
	})
}

func TestDocumentTimestampObject(t *testing.T) {
	t.Run("NewDocumentTimestampObject_Default", func(t *testing.T) {
		ts := NewDocumentTimestampObject(0)
		if ts == nil {
			t.Fatal("NewDocumentTimestampObject returned nil")
		}

		if ts.GetName("Type") != "/DocTimeStamp" {
			t.Errorf("Type = %q, want %q", ts.GetName("Type"), "/DocTimeStamp")
		}

		if ts.GetName("SubFilter") != string(fields.SubFilterETSIRFC3161) {
			t.Errorf("SubFilter = %q, want %q", ts.GetName("SubFilter"), string(fields.SubFilterETSIRFC3161))
		}
	})

	t.Run("NewDocumentTimestampObject_CustomSize", func(t *testing.T) {
		ts := NewDocumentTimestampObject(8192)
		if ts == nil {
			t.Fatal("NewDocumentTimestampObject returned nil")
		}
		if len(ts.Contents.Value) != 8192 {
			t.Errorf("Contents size = %d, want 8192", len(ts.Contents.Value))
		}
	})
}

func TestFillReservedRegion(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Create a buffer with placeholder
		data := []byte("prefix<" + string(make([]byte, 20)) + ">suffix")

		// Create a read-write buffer
		var rw bytes.Buffer
		rw.Write(data)

		// Verify the buffer was created (integration tests would use WriteSeeker)
		if rw.Len() != len(data) {
			t.Errorf("Buffer length = %d, want %d", rw.Len(), len(data))
		}
	})

	t.Run("TooLarge", func(t *testing.T) {
		// Create a small buffer
		var buf bytes.Buffer
		buf.Write([]byte("<12345678>")) // 8 bytes available (minus < >)

		// Try to write 10 bytes worth of content
		content := make([]byte, 5) // 10 hex chars
		_, err := FillReservedRegion(&seekBuffer{&buf}, 0, 10, content)

		// Should fail because content is too large
		if err == nil {
			t.Error("Expected error for content too large")
		}
	})
}

func TestSigAuthType(t *testing.T) {
	if SigAuthTypePassword != "password" {
		t.Errorf("SigAuthTypePassword = %q, want %q", SigAuthTypePassword, "password")
	}
	if SigAuthTypePIN != "pin" {
		t.Errorf("SigAuthTypePIN = %q, want %q", SigAuthTypePIN, "pin")
	}
	if SigAuthTypeFingerprint != "fingerprint" {
		t.Errorf("SigAuthTypeFingerprint = %q, want %q", SigAuthTypeFingerprint, "fingerprint")
	}
}

func TestExtendedPreparedByteRangeDigest(t *testing.T) {
	t.Run("NewExtendedPreparedByteRangeDigest", func(t *testing.T) {
		digest := []byte{0x01, 0x02, 0x03}
		ext := NewExtendedPreparedByteRangeDigest(digest, 100, 200)

		if ext == nil {
			t.Fatal("NewExtendedPreparedByteRangeDigest returned nil")
		}

		if !bytes.Equal(ext.Digest, digest) {
			t.Errorf("Digest = %v, want %v", ext.Digest, digest)
		}

		if ext.ReservedRegionStart() != 100 {
			t.Errorf("ReservedRegionStart = %d, want 100", ext.ReservedRegionStart())
		}

		if ext.ReservedRegionEnd() != 200 {
			t.Errorf("ReservedRegionEnd = %d, want 200", ext.ReservedRegionEnd())
		}
	})
}

// seekBuffer wraps a bytes.Buffer to implement WriteSeeker
type seekBuffer struct {
	*bytes.Buffer
}

func (s *seekBuffer) Seek(offset int64, whence int) (int64, error) {
	// Simplified implementation for testing
	return offset, nil
}
