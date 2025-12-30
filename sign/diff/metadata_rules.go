// Package diff provides difference analysis for PDF document validation.
// This file contains rules for metadata modifications.
package diff

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strings"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Metadata-related errors
var (
	ErrMetadataNotStream    = errors.New("/Metadata should be a reference to a stream object")
	ErrMetadataNotReference = errors.New("/Metadata should be an indirect reference")
	ErrMetadataXMLInvalid   = errors.New("/Metadata XML syntax could not be validated")
	ErrMetadataXMLEntities  = errors.New("XML entities found in XMP metadata")
	ErrMetadataNotXMP       = errors.New("metadata does not look like XMP")
)

// WhitelistRule defines the interface for whitelist rules.
type WhitelistRule interface {
	// Apply returns the reference updates that are whitelisted by this rule.
	Apply(old, new *RevisionState) ([]ReferenceUpdate, error)
}

// DocInfoRule allows the /Info dictionary in the trailer to be updated.
// Updates to /Info are always OK since they only affect document metadata
// and most readers will fall back to older revisions regardless.
type DocInfoRule struct{}

// NewDocInfoRule creates a new DocInfoRule.
func NewDocInfoRule() *DocInfoRule {
	return &DocInfoRule{}
}

// Apply implements WhitelistRule.
func (r *DocInfoRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	updates := []ReferenceUpdate{}

	// Get /Info from new trailer
	newInfo := getInfoReference(new.Trailer)
	if newInfo == nil {
		return updates, nil
	}

	// Get /Info from old trailer
	oldInfo := getInfoReference(old.Trailer)

	// If new info reference is different or new, whitelist it
	if oldInfo == nil || oldInfo.ObjectNumber != newInfo.ObjectNumber {
		update := ReferenceUpdate{
			Reference: newInfo,
			Level:     ModificationFormFilling,
		}
		updates = append(updates, update)
	} else if oldInfo.ObjectNumber == newInfo.ObjectNumber {
		// Same reference, but check if the object was modified
		oldObj := old.GetObject(oldInfo.ObjectNumber)
		newObj := new.GetObject(newInfo.ObjectNumber)
		if oldObj != nil && newObj != nil {
			update := ReferenceUpdate{
				Reference: newInfo,
				OldValue:  oldObj,
				NewValue:  newObj,
				Level:     ModificationFormFilling,
			}
			updates = append(updates, update)
		}
	}

	return updates, nil
}

// getInfoReference gets the /Info reference from a trailer dictionary.
func getInfoReference(trailer *generic.DictionaryObject) *generic.Reference {
	if trailer == nil {
		return nil
	}

	infoObj := trailer.Get("Info")
	if infoObj == nil {
		return nil
	}

	if ref, ok := infoObj.(*generic.Reference); ok {
		return ref
	}
	if ref, ok := infoObj.(generic.Reference); ok {
		return &ref
	}
	return nil
}

// MetadataUpdateRule adjudicates updates to the XMP metadata stream.
// The content of the metadata isn't validated in any significant way;
// this class only checks whether the XML is well-formed.
type MetadataUpdateRule struct {
	// CheckXMLSyntax does a well-formedness check on the XML syntax.
	CheckXMLSyntax bool

	// AlwaysRefuseStreamOverride always refuses to override the metadata stream
	// if its object ID existed in a prior revision, including if the new stream
	// overrides the old metadata stream and the syntax check passes.
	AlwaysRefuseStreamOverride bool
}

// NewMetadataUpdateRule creates a new MetadataUpdateRule with default settings.
func NewMetadataUpdateRule() *MetadataUpdateRule {
	return &MetadataUpdateRule{
		CheckXMLSyntax:             true,
		AlwaysRefuseStreamOverride: false,
	}
}

// Apply implements WhitelistRule.
func (r *MetadataUpdateRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	updates := []ReferenceUpdate{}

	// Get /Metadata from new root
	newMetadataRef, err := getMetadataReference(new.Root)
	if err != nil {
		return nil, &SuspiciousModification{Message: err.Error()}
	}
	if newMetadataRef == nil {
		return updates, nil // nothing to do
	}

	// Validate new metadata XML if required
	if r.CheckXMLSyntax {
		newMetadataObj := new.GetObject(newMetadataRef.ObjectNumber)
		if err := r.isWellFormedXML(newMetadataObj); err != nil {
			return nil, err
		}
	}

	// Get /Metadata from old root
	oldMetadataRef, err := getMetadataReference(old.Root)
	if err != nil {
		return nil, &SuspiciousModification{Message: err.Error()}
	}

	// Validate old metadata XML if it exists and we're checking syntax
	if r.CheckXMLSyntax && oldMetadataRef != nil {
		oldMetadataObj := old.GetObject(oldMetadataRef.ObjectNumber)
		if err := r.isWellFormedXML(oldMetadataObj); err != nil {
			return nil, err
		}
	}

	// Check if we should allow the update
	sameRefOK := oldMetadataRef != nil &&
		oldMetadataRef.ObjectNumber == newMetadataRef.ObjectNumber &&
		!r.AlwaysRefuseStreamOverride

	// Reference is available if it's new or the same and allowed
	refAvailable := !old.HasObject(newMetadataRef.ObjectNumber) || sameRefOK

	if refAvailable {
		update := ReferenceUpdate{
			Reference: newMetadataRef,
			Level:     ModificationFormFilling,
		}
		if oldMetadataRef != nil {
			update.OldValue = old.GetObject(oldMetadataRef.ObjectNumber)
		}
		update.NewValue = new.GetObject(newMetadataRef.ObjectNumber)
		updates = append(updates, update)
	} else {
		return nil, &SuspiciousModification{
			Message: "metadata stream override not allowed",
		}
	}

	return updates, nil
}

// getMetadataReference gets the /Metadata reference from a root dictionary.
func getMetadataReference(root *generic.DictionaryObject) (*generic.Reference, error) {
	if root == nil {
		return nil, nil
	}

	metadataObj := root.Get("Metadata")
	if metadataObj == nil {
		return nil, nil
	}

	switch v := metadataObj.(type) {
	case *generic.Reference:
		return v, nil
	case generic.Reference:
		return &v, nil
	default:
		return nil, ErrMetadataNotReference
	}
}

// isWellFormedXML checks whether the provided object is a stream with well-formed XML data.
func (r *MetadataUpdateRule) isWellFormedXML(obj generic.PdfObject) error {
	if obj == nil {
		return nil
	}

	stream, ok := obj.(*generic.StreamObject)
	if !ok {
		return &SuspiciousModification{Message: ErrMetadataNotStream.Error()}
	}

	data := stream.Data
	if len(data) == 0 {
		// Empty stream is technically valid
		return nil
	}

	// Try to parse as XML
	decoder := xml.NewDecoder(bytes.NewReader(data))

	var root *xml.StartElement
	for {
		token, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return &SuspiciousModification{Message: ErrMetadataXMLInvalid.Error()}
		}

		switch t := token.(type) {
		case xml.StartElement:
			if root == nil {
				root = &t
			}
		case xml.CharData:
			// Character data is OK
		case xml.Comment:
			// Comments are OK
		case xml.ProcInst:
			// Processing instructions are OK
		case xml.Directive:
			// Check for entity declarations in DOCTYPE
			directive := string(t)
			if strings.Contains(directive, "ENTITY") {
				return &SuspiciousModification{Message: ErrMetadataXMLEntities.Error()}
			}
		}
	}

	// Check that root element looks like XMP
	if root != nil {
		expectedNS := "adobe:ns:meta/"
		if root.Name.Space != expectedNS && !strings.Contains(root.Name.Local, "xmpmeta") {
			return &SuspiciousModification{Message: ErrMetadataNotXMP.Error()}
		}
	}

	return nil
}

// CombinedMetadataRule combines DocInfoRule and MetadataUpdateRule.
type CombinedMetadataRule struct {
	DocInfoRule        *DocInfoRule
	MetadataUpdateRule *MetadataUpdateRule
}

// NewCombinedMetadataRule creates a combined metadata rule with default settings.
func NewCombinedMetadataRule() *CombinedMetadataRule {
	return &CombinedMetadataRule{
		DocInfoRule:        NewDocInfoRule(),
		MetadataUpdateRule: NewMetadataUpdateRule(),
	}
}

// Apply implements WhitelistRule.
func (r *CombinedMetadataRule) Apply(old, new *RevisionState) ([]ReferenceUpdate, error) {
	allUpdates := []ReferenceUpdate{}

	// Apply DocInfoRule
	docInfoUpdates, err := r.DocInfoRule.Apply(old, new)
	if err != nil {
		return nil, err
	}
	allUpdates = append(allUpdates, docInfoUpdates...)

	// Apply MetadataUpdateRule
	metadataUpdates, err := r.MetadataUpdateRule.Apply(old, new)
	if err != nil {
		return nil, err
	}
	allUpdates = append(allUpdates, metadataUpdates...)

	return allUpdates, nil
}

// ValidateXMPMetadata validates XMP metadata content.
func ValidateXMPMetadata(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	rule := &MetadataUpdateRule{CheckXMLSyntax: true}
	stream := &generic.StreamObject{Data: data}
	return rule.isWellFormedXML(stream)
}

// IsXMPContent checks if the given data appears to be XMP metadata.
func IsXMPContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for common XMP markers
	content := string(data)
	return strings.Contains(content, "xmpmeta") ||
		strings.Contains(content, "adobe:ns:meta") ||
		strings.Contains(content, "x:xmpmeta")
}
