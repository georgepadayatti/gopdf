package signers

import (
	"crypto"
	"testing"
	"time"
)

func TestFieldMDPAction(t *testing.T) {
	tests := []struct {
		action   FieldMDPAction
		expected string
	}{
		{FieldMDPActionAll, "All"},
		{FieldMDPActionInclude, "Include"},
		{FieldMDPActionExclude, "Exclude"},
	}

	for _, tt := range tests {
		if string(tt.action) != tt.expected {
			t.Errorf("FieldMDPAction %v = %s, want %s", tt.action, string(tt.action), tt.expected)
		}
	}
}

func TestFieldMDPSpec(t *testing.T) {
	t.Run("NewFieldMDPSpec", func(t *testing.T) {
		spec := NewFieldMDPSpec(FieldMDPActionInclude, []string{"field1", "field2"})
		if spec.Action != FieldMDPActionInclude {
			t.Error("Action not set correctly")
		}
		if len(spec.Fields) != 2 {
			t.Errorf("Expected 2 fields, got %d", len(spec.Fields))
		}
	})

	t.Run("AsTransformParams", func(t *testing.T) {
		spec := NewFieldMDPSpec(FieldMDPActionInclude, []string{"field1"})
		params := spec.AsTransformParams()

		if params == nil {
			t.Fatal("AsTransformParams returned nil")
		}

		if params.Get("Type") == nil {
			t.Error("Type not set in transform params")
		}
		if params.Get("Action") == nil {
			t.Error("Action not set in transform params")
		}
		if params.Get("Fields") == nil {
			t.Error("Fields not set in transform params")
		}
	})

	t.Run("AsTransformParamsNoFields", func(t *testing.T) {
		spec := NewFieldMDPSpec(FieldMDPActionAll, nil)
		params := spec.AsTransformParams()

		if params.Get("Fields") != nil {
			t.Error("Fields should not be set for Action=All with no fields")
		}
	})
}

func TestSigMDPSetup(t *testing.T) {
	t.Run("NewSigMDPSetup", func(t *testing.T) {
		setup := NewSigMDPSetup("sha256")
		if setup.MDAlgorithm != "sha256" {
			t.Error("MDAlgorithm not set correctly")
		}
		if setup.Certify {
			t.Error("Certify should be false by default")
		}
	})

	t.Run("AsCertification", func(t *testing.T) {
		setup := NewSigMDPSetup("sha256").AsCertification(MDPFormFilling)
		if !setup.Certify {
			t.Error("Certify should be true")
		}
		if setup.DocMDPPerms == nil || *setup.DocMDPPerms != MDPFormFilling {
			t.Error("DocMDPPerms not set correctly")
		}
	})

	t.Run("WithFieldLock", func(t *testing.T) {
		spec := NewFieldMDPSpec(FieldMDPActionAll, nil)
		setup := NewSigMDPSetup("sha256").WithFieldLock(spec)
		if setup.FieldLock != spec {
			t.Error("FieldLock not set correctly")
		}
	})
}

func TestCreateDocMDPReferenceDictionary(t *testing.T) {
	dict := CreateDocMDPReferenceDictionary(MDPFormFilling)

	if dict == nil {
		t.Fatal("CreateDocMDPReferenceDictionary returned nil")
	}

	if dict.Get("Type") == nil {
		t.Error("Type not set")
	}
	if dict.Get("TransformMethod") == nil {
		t.Error("TransformMethod not set")
	}
	if dict.Get("TransformParams") == nil {
		t.Error("TransformParams not set")
	}
}

func TestCreateFieldMDPReferenceDictionary(t *testing.T) {
	spec := NewFieldMDPSpec(FieldMDPActionInclude, []string{"field1"})
	dict := CreateFieldMDPReferenceDictionary(spec, nil)

	if dict == nil {
		t.Fatal("CreateFieldMDPReferenceDictionary returned nil")
	}

	if dict.Get("Type") == nil {
		t.Error("Type not set")
	}
	if dict.Get("TransformMethod") == nil {
		t.Error("TransformMethod not set")
	}
	if dict.Get("TransformParams") == nil {
		t.Error("TransformParams not set")
	}
}

func TestSigAppearanceSetup(t *testing.T) {
	now := time.Now()

	t.Run("NewSigAppearanceSetup", func(t *testing.T) {
		setup := NewSigAppearanceSetup(now, "John Doe")
		if setup.Name != "John Doe" {
			t.Error("Name not set correctly")
		}
		if !setup.Timestamp.Equal(now) {
			t.Error("Timestamp not set correctly")
		}
	})

	t.Run("WithTextParam", func(t *testing.T) {
		setup := NewSigAppearanceSetup(now, "John Doe").
			WithTextParam("key1", "value1").
			WithTextParam("key2", "value2")

		if len(setup.TextParams) != 2 {
			t.Errorf("Expected 2 text params, got %d", len(setup.TextParams))
		}
		if setup.TextParams["key1"] != "value1" {
			t.Error("key1 not set correctly")
		}
	})

	t.Run("WithTimestampFormat", func(t *testing.T) {
		setup := NewSigAppearanceSetup(now, "John Doe").
			WithTimestampFormat("Jan 2, 2006")

		if setup.TimestampFormat != "Jan 2, 2006" {
			t.Error("TimestampFormat not set correctly")
		}
	})

	t.Run("GetTextParams", func(t *testing.T) {
		setup := NewSigAppearanceSetup(now, "John Doe").
			WithTextParam("extra", "value")

		params := setup.GetTextParams()
		if params["signer"] != "John Doe" {
			t.Error("signer not in params")
		}
		if params["ts"] == "" {
			t.Error("ts not in params")
		}
		if params["extra"] != "value" {
			t.Error("extra param not in params")
		}
	})
}

func TestSigObjSetup(t *testing.T) {
	t.Run("NewSigObjSetup", func(t *testing.T) {
		setup := NewSigObjSetup(nil, 8192)
		if setup.ContentsSize != 8192 {
			t.Error("ContentsSize not set correctly")
		}
	})

	t.Run("WithMDPSetup", func(t *testing.T) {
		mdp := NewSigMDPSetup("sha256")
		setup := NewSigObjSetup(nil, 8192).WithMDPSetup(mdp)
		if setup.MDPSetup != mdp {
			t.Error("MDPSetup not set correctly")
		}
	})

	t.Run("WithAppearance", func(t *testing.T) {
		appearance := NewSigAppearanceSetup(time.Now(), "John Doe")
		setup := NewSigObjSetup(nil, 8192).WithAppearance(appearance)
		if setup.AppearanceSetup != appearance {
			t.Error("AppearanceSetup not set correctly")
		}
	})
}

func TestSigIOSetup(t *testing.T) {
	t.Run("NewSigIOSetup", func(t *testing.T) {
		setup := NewSigIOSetup(crypto.SHA256)
		if setup.MDAlgorithm != crypto.SHA256 {
			t.Error("MDAlgorithm not set correctly")
		}
		if setup.ChunkSize != DefaultChunkSize {
			t.Errorf("ChunkSize not set to default: %d", setup.ChunkSize)
		}
	})

	t.Run("WithInPlace", func(t *testing.T) {
		setup := NewSigIOSetup(crypto.SHA256).WithInPlace()
		if !setup.InPlace {
			t.Error("InPlace should be true")
		}
	})
}

func TestPreparedByteRangeDigest(t *testing.T) {
	t.Run("NewPreparedByteRangeDigest", func(t *testing.T) {
		digest := []byte{1, 2, 3, 4}
		byteRange := []int64{0, 100, 200, 50}

		prepared := NewPreparedByteRangeDigest(digest, byteRange, crypto.SHA256)

		if len(prepared.Digest) != 4 {
			t.Error("Digest not set correctly")
		}
		if len(prepared.ByteRange) != 4 {
			t.Error("ByteRange not set correctly")
		}
		if prepared.Algorithm != crypto.SHA256 {
			t.Error("Algorithm not set correctly")
		}
	})

	t.Run("SignatureContents", func(t *testing.T) {
		document := make([]byte, 300)
		for i := range document {
			document[i] = byte(i % 256)
		}

		byteRange := []int64{0, 100, 200, 50}
		prepared := NewPreparedByteRangeDigest(nil, byteRange, crypto.SHA256)

		contents := prepared.SignatureContents(document)
		expectedLen := byteRange[1] + byteRange[3]
		if int64(len(contents)) != expectedLen {
			t.Errorf("Expected contents length %d, got %d", expectedLen, len(contents))
		}
	})

	t.Run("SignatureContentsInvalidByteRange", func(t *testing.T) {
		prepared := NewPreparedByteRangeDigest(nil, []int64{0, 100}, crypto.SHA256)
		contents := prepared.SignatureContents([]byte{})
		if contents != nil {
			t.Error("Expected nil for invalid byte range")
		}
	})
}

func TestPdfCMSEmbedder(t *testing.T) {
	t.Run("NewPdfCMSEmbedder", func(t *testing.T) {
		embedder := NewPdfCMSEmbedder()
		if embedder == nil {
			t.Fatal("NewPdfCMSEmbedder returned nil")
		}
		if embedder.NewFieldPage != 0 {
			t.Error("NewFieldPage should be 0 by default")
		}
	})

	t.Run("WithNewFieldPage", func(t *testing.T) {
		embedder := NewPdfCMSEmbedder().WithNewFieldPage(5)
		if embedder.NewFieldPage != 5 {
			t.Error("NewFieldPage not set correctly")
		}
	})
}

func TestEmbedSignatureInBytes(t *testing.T) {
	t.Run("ValidEmbedding", func(t *testing.T) {
		// Create a mock PDF with a signature placeholder
		// Format: <pre-sig><placeholder><post-sig>
		preSig := []byte("PDF content before signature")
		placeholder := []byte("<" + string(make([]byte, 100)) + ">")
		postSig := []byte("PDF content after signature")

		document := append(append(preSig, placeholder...), postSig...)

		byteRange := []int64{
			0,
			int64(len(preSig)),
			int64(len(preSig) + len(placeholder)),
			int64(len(postSig)),
		}

		signature := []byte{0x30, 0x82, 0x01, 0x00}

		result, err := EmbedSignatureInBytes(document, byteRange, signature)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if len(result) != len(document) {
			t.Errorf("Result length mismatch: %d vs %d", len(result), len(document))
		}
	})

	t.Run("InvalidByteRange", func(t *testing.T) {
		_, err := EmbedSignatureInBytes([]byte{}, []int64{0, 100}, []byte{})
		if err != ErrInvalidByteRange {
			t.Errorf("Expected ErrInvalidByteRange, got: %v", err)
		}
	})

	t.Run("SignatureTooLarge", func(t *testing.T) {
		document := []byte("test<00>end")
		byteRange := []int64{0, 4, 8, 3}
		signature := make([]byte, 100) // Too large

		_, err := EmbedSignatureInBytes(document, byteRange, signature)
		if err == nil {
			t.Error("Expected error for oversized signature")
		}
	})
}

func TestComputeByteRangeDigest(t *testing.T) {
	t.Run("ValidDigest", func(t *testing.T) {
		document := []byte("Hello<PLACEHOLDER>World")
		byteRange := []int64{0, 5, 18, 5}

		digest, err := ComputeByteRangeDigest(document, byteRange, crypto.SHA256)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if len(digest) != 32 { // SHA256 produces 32 bytes
			t.Errorf("Expected 32 byte digest, got %d", len(digest))
		}
	})

	t.Run("InvalidByteRange", func(t *testing.T) {
		_, err := ComputeByteRangeDigest([]byte{}, []int64{0, 100}, crypto.SHA256)
		if err != ErrInvalidByteRange {
			t.Errorf("Expected ErrInvalidByteRange, got: %v", err)
		}
	})

	t.Run("OutOfBoundsRange", func(t *testing.T) {
		document := []byte("short")
		byteRange := []int64{0, 100, 200, 50}

		_, err := ComputeByteRangeDigest(document, byteRange, crypto.SHA256)
		if err == nil {
			t.Error("Expected error for out of bounds range")
		}
	})
}

func TestSignatureObjectBuilder(t *testing.T) {
	t.Run("NewSignatureObjectBuilder", func(t *testing.T) {
		builder := NewSignatureObjectBuilder()
		if builder == nil {
			t.Fatal("NewSignatureObjectBuilder returned nil")
		}

		dict := builder.Build()
		if dict.Get("Type") == nil {
			t.Error("Type not set")
		}
		if dict.Get("Filter") == nil {
			t.Error("Filter not set")
		}
		if dict.Get("SubFilter") == nil {
			t.Error("SubFilter not set")
		}
	})

	t.Run("FluentBuilder", func(t *testing.T) {
		now := time.Now()

		dict := NewSignatureObjectBuilder().
			WithSubFilter("ETSI.CAdES.detached").
			WithReason("Test signing").
			WithLocation("Test location").
			WithContactInfo("test@example.com").
			WithName("John Doe").
			WithSigningTime(now).
			WithContentsPlaceholder(8192).
			WithByteRangePlaceholder().
			Build()

		if dict.Get("Reason") == nil {
			t.Error("Reason not set")
		}
		if dict.Get("Location") == nil {
			t.Error("Location not set")
		}
		if dict.Get("ContactInfo") == nil {
			t.Error("ContactInfo not set")
		}
		if dict.Get("Name") == nil {
			t.Error("Name not set")
		}
		if dict.Get("M") == nil {
			t.Error("M (signing time) not set")
		}
		if dict.Get("Contents") == nil {
			t.Error("Contents not set")
		}
		if dict.Get("ByteRange") == nil {
			t.Error("ByteRange not set")
		}
	})
}

func TestFormatPDFDate(t *testing.T) {
	// Use a fixed time for testing
	loc, _ := time.LoadLocation("America/New_York")
	testTime := time.Date(2024, 6, 15, 14, 30, 45, 0, loc)

	result := FormatPDFDate(testTime)

	// Should start with "D:"
	if len(result) < 2 || result[:2] != "D:" {
		t.Errorf("PDF date should start with 'D:', got: %s", result)
	}

	// Should contain the date parts
	if len(result) < 17 {
		t.Errorf("PDF date too short: %s", result)
	}
}

func TestParsePDFDate(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"D:20240615143045+05'00'", false},
		{"D:20240615143045-05'00'", false},
		{"D:20240615143045Z", false},
		{"D:20240615143045", false},
		{"D:202406151430", false},
		{"D:2024061514", false},
		{"D:20240615", false},
		{"invalid", true},
		{"D:", true},
	}

	for _, tt := range tests {
		_, err := ParsePDFDate(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ParsePDFDate(%s) expected error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ParsePDFDate(%s) error: %v", tt.input, err)
		}
	}
}

func TestDocumentTimestampBuilder(t *testing.T) {
	builder := NewDocumentTimestampBuilder()
	if builder == nil {
		t.Fatal("NewDocumentTimestampBuilder returned nil")
	}

	dict := builder.Build()

	// Check that Type is DocTimeStamp
	typeObj := dict.Get("Type")
	if typeObj == nil {
		t.Error("Type not set")
	}

	// Check that SubFilter is ETSI.RFC3161
	subFilter := dict.Get("SubFilter")
	if subFilter == nil {
		t.Error("SubFilter not set")
	}
}

func TestCMSEmbeddingResult(t *testing.T) {
	result := CMSEmbeddingResult{
		SignedDocument: []byte("signed document"),
		ByteRange:      []int64{0, 100, 200, 50},
		Digest:         []byte{1, 2, 3, 4},
	}

	if len(result.SignedDocument) == 0 {
		t.Error("SignedDocument is empty")
	}
	if len(result.ByteRange) != 4 {
		t.Error("ByteRange should have 4 elements")
	}
	if len(result.Digest) != 4 {
		t.Error("Digest length mismatch")
	}
}

func TestDefaultChunkSize(t *testing.T) {
	if DefaultChunkSize != 4096 {
		t.Errorf("DefaultChunkSize = %d, want 4096", DefaultChunkSize)
	}
}
