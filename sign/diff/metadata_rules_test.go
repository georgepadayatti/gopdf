package diff

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestDocInfoRule(t *testing.T) {
	rule := NewDocInfoRule()

	// Create old state without /Info
	oldTrailer := generic.NewDictionary()
	oldState := &RevisionState{
		Trailer: oldTrailer,
		Objects: make(map[int]generic.PdfObject),
	}

	// Create new state with /Info
	newTrailer := generic.NewDictionary()
	infoDict := generic.NewDictionary()
	infoDict.Set("Title", generic.NewTextString("Test Document"))
	newTrailer.Set("Info", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})

	newState := &RevisionState{
		Trailer: newTrailer,
		Objects: map[int]generic.PdfObject{
			1: infoDict,
		},
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("DocInfoRule.Apply returned error: %v", err)
	}

	if len(updates) != 1 {
		t.Errorf("Expected 1 update, got %d", len(updates))
	}
}

func TestDocInfoRuleNoInfo(t *testing.T) {
	rule := NewDocInfoRule()

	oldState := &RevisionState{
		Trailer: generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	newState := &RevisionState{
		Trailer: generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("DocInfoRule.Apply returned error: %v", err)
	}

	if len(updates) != 0 {
		t.Errorf("Expected 0 updates for no /Info, got %d", len(updates))
	}
}

func TestDocInfoRuleSameInfo(t *testing.T) {
	rule := NewDocInfoRule()

	infoDict := generic.NewDictionary()
	infoDict.Set("Title", generic.NewTextString("Test"))
	infoRef := generic.Reference{ObjectNumber: 1, GenerationNumber: 0}

	oldTrailer := generic.NewDictionary()
	oldTrailer.Set("Info", infoRef)
	oldState := &RevisionState{
		Trailer: oldTrailer,
		Objects: map[int]generic.PdfObject{1: infoDict},
	}

	newInfoDict := generic.NewDictionary()
	newInfoDict.Set("Title", generic.NewTextString("Updated Title"))

	newTrailer := generic.NewDictionary()
	newTrailer.Set("Info", infoRef)
	newState := &RevisionState{
		Trailer: newTrailer,
		Objects: map[int]generic.PdfObject{1: newInfoDict},
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("DocInfoRule.Apply returned error: %v", err)
	}

	if len(updates) != 1 {
		t.Errorf("Expected 1 update for modified /Info, got %d", len(updates))
	}
}

func TestMetadataUpdateRule(t *testing.T) {
	rule := NewMetadataUpdateRule()

	// Create valid XMP metadata
	xmpData := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about="">
      <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Test</dc:title>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>`)

	metadataStream := &generic.StreamObject{Data: xmpData}

	oldRoot := generic.NewDictionary()
	oldState := &RevisionState{
		Root:    oldRoot,
		Objects: make(map[int]generic.PdfObject),
	}

	newRoot := generic.NewDictionary()
	newRoot.Set("Metadata", generic.Reference{ObjectNumber: 5, GenerationNumber: 0})
	newState := &RevisionState{
		Root: newRoot,
		Objects: map[int]generic.PdfObject{
			5: metadataStream,
		},
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("MetadataUpdateRule.Apply returned error: %v", err)
	}

	if len(updates) != 1 {
		t.Errorf("Expected 1 update, got %d", len(updates))
	}
}

func TestMetadataUpdateRuleInvalidXML(t *testing.T) {
	rule := NewMetadataUpdateRule()
	rule.CheckXMLSyntax = true

	invalidXML := []byte(`<not valid xml >>>>`)
	metadataStream := &generic.StreamObject{Data: invalidXML}

	oldState := &RevisionState{
		Root:    generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	newRoot := generic.NewDictionary()
	newRoot.Set("Metadata", generic.Reference{ObjectNumber: 5, GenerationNumber: 0})
	newState := &RevisionState{
		Root: newRoot,
		Objects: map[int]generic.PdfObject{
			5: metadataStream,
		},
	}

	_, err := rule.Apply(oldState, newState)

	if err == nil {
		t.Error("Expected error for invalid XML, got nil")
	}
}

func TestMetadataUpdateRuleNoXMLCheck(t *testing.T) {
	rule := NewMetadataUpdateRule()
	rule.CheckXMLSyntax = false

	// Even with invalid content, should pass without XML check
	anyContent := []byte(`This is not XML at all!`)
	metadataStream := &generic.StreamObject{Data: anyContent}

	oldState := &RevisionState{
		Root:    generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	newRoot := generic.NewDictionary()
	newRoot.Set("Metadata", generic.Reference{ObjectNumber: 5, GenerationNumber: 0})
	newState := &RevisionState{
		Root: newRoot,
		Objects: map[int]generic.PdfObject{
			5: metadataStream,
		},
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("Expected no error when XML check is disabled, got: %v", err)
	}

	if len(updates) != 1 {
		t.Errorf("Expected 1 update, got %d", len(updates))
	}
}

func TestMetadataUpdateRuleStreamOverride(t *testing.T) {
	rule := NewMetadataUpdateRule()
	rule.AlwaysRefuseStreamOverride = true

	xmpData := []byte(`<?xml version="1.0"?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta>`)
	metadataStream := &generic.StreamObject{Data: xmpData}

	oldRoot := generic.NewDictionary()
	oldRoot.Set("Metadata", generic.Reference{ObjectNumber: 5, GenerationNumber: 0})
	oldState := &RevisionState{
		Root: oldRoot,
		Objects: map[int]generic.PdfObject{
			5: metadataStream,
		},
	}

	newMetadata := &generic.StreamObject{Data: xmpData}
	newRoot := generic.NewDictionary()
	newRoot.Set("Metadata", generic.Reference{ObjectNumber: 5, GenerationNumber: 0})
	newState := &RevisionState{
		Root: newRoot,
		Objects: map[int]generic.PdfObject{
			5: newMetadata,
		},
	}

	_, err := rule.Apply(oldState, newState)

	if err == nil {
		t.Error("Expected error when stream override is refused")
	}
}

func TestMetadataUpdateRuleNoMetadata(t *testing.T) {
	rule := NewMetadataUpdateRule()

	oldState := &RevisionState{
		Root:    generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	newState := &RevisionState{
		Root:    generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("Expected no error for no metadata, got: %v", err)
	}

	if len(updates) != 0 {
		t.Errorf("Expected 0 updates for no metadata, got %d", len(updates))
	}
}

func TestCombinedMetadataRule(t *testing.T) {
	rule := NewCombinedMetadataRule()

	// Create state with both /Info and /Metadata
	xmpData := []byte(`<?xml version="1.0"?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta>`)

	oldState := &RevisionState{
		Trailer: generic.NewDictionary(),
		Root:    generic.NewDictionary(),
		Objects: make(map[int]generic.PdfObject),
	}

	infoDict := generic.NewDictionary()
	infoDict.Set("Title", generic.NewTextString("Test"))
	metadataStream := &generic.StreamObject{Data: xmpData}

	newTrailer := generic.NewDictionary()
	newTrailer.Set("Info", generic.Reference{ObjectNumber: 1, GenerationNumber: 0})
	newRoot := generic.NewDictionary()
	newRoot.Set("Metadata", generic.Reference{ObjectNumber: 2, GenerationNumber: 0})

	newState := &RevisionState{
		Trailer: newTrailer,
		Root:    newRoot,
		Objects: map[int]generic.PdfObject{
			1: infoDict,
			2: metadataStream,
		},
	}

	updates, err := rule.Apply(oldState, newState)

	if err != nil {
		t.Errorf("CombinedMetadataRule.Apply returned error: %v", err)
	}

	if len(updates) != 2 {
		t.Errorf("Expected 2 updates (Info + Metadata), got %d", len(updates))
	}
}

func TestValidateXMPMetadata(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid XMP",
			data:    []byte(`<?xml version="1.0"?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta>`),
			wantErr: false,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "invalid XML",
			data:    []byte(`<invalid>>>`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateXMPMetadata(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateXMPMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsXMPContent(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "XMP with xmpmeta",
			data: []byte(`<x:xmpmeta xmlns:x="adobe:ns:meta/">`),
			want: true,
		},
		{
			name: "XMP with adobe ns",
			data: []byte(`<root xmlns="adobe:ns:meta/">`),
			want: true,
		},
		{
			name: "not XMP",
			data: []byte(`<html><body>Hello</body></html>`),
			want: false,
		},
		{
			name: "empty",
			data: []byte{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsXMPContent(tt.data); got != tt.want {
				t.Errorf("IsXMPContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetInfoReference(t *testing.T) {
	tests := []struct {
		name    string
		trailer *generic.DictionaryObject
		wantNil bool
	}{
		{
			name:    "nil trailer",
			trailer: nil,
			wantNil: true,
		},
		{
			name:    "no Info key",
			trailer: generic.NewDictionary(),
			wantNil: true,
		},
		{
			name: "with Info reference pointer",
			trailer: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				ref := &generic.Reference{ObjectNumber: 5}
				d.Set("Info", ref)
				return d
			}(),
			wantNil: false,
		},
		{
			name: "with Info reference value",
			trailer: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("Info", generic.Reference{ObjectNumber: 5})
				return d
			}(),
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getInfoReference(tt.trailer)
			if (got == nil) != tt.wantNil {
				t.Errorf("getInfoReference() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}

func TestGetMetadataReference(t *testing.T) {
	tests := []struct {
		name    string
		root    *generic.DictionaryObject
		wantNil bool
		wantErr bool
	}{
		{
			name:    "nil root",
			root:    nil,
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "no Metadata key",
			root:    generic.NewDictionary(),
			wantNil: true,
			wantErr: false,
		},
		{
			name: "with Metadata reference",
			root: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("Metadata", generic.Reference{ObjectNumber: 10})
				return d
			}(),
			wantNil: false,
			wantErr: false,
		},
		{
			name: "Metadata not a reference",
			root: func() *generic.DictionaryObject {
				d := generic.NewDictionary()
				d.Set("Metadata", generic.NameObject("invalid"))
				return d
			}(),
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getMetadataReference(tt.root)
			if (err != nil) != tt.wantErr {
				t.Errorf("getMetadataReference() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("getMetadataReference() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}
