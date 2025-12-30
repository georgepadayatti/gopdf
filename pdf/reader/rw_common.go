// Package reader provides common utilities for PDF reading and writing.
package reader

import (
	"fmt"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// PdfHandler provides a general interface for querying objects
// in PDF readers and writers alike.
type PdfHandler interface {
	// GetObject retrieves the object associated with the provided reference.
	GetObject(ref generic.Reference) (generic.PdfObject, error)

	// TrailerView returns a view of the document trailer.
	TrailerView() *generic.DictionaryObject

	// RootRef returns a reference to the document catalog.
	RootRef() generic.Reference

	// Root returns the document catalog.
	Root() *generic.DictionaryObject

	// DocumentID returns the document ID (first and second part).
	DocumentID() ([]byte, []byte)
}

// BasePdfHandler provides common functionality for PdfHandler implementations.
type BasePdfHandler struct {
	trailer *generic.TrailerDictionary
}

// NewBasePdfHandler creates a new base PDF handler.
func NewBasePdfHandler(trailer *generic.TrailerDictionary) *BasePdfHandler {
	return &BasePdfHandler{
		trailer: trailer,
	}
}

// TrailerView returns a view of the document trailer.
func (h *BasePdfHandler) TrailerView() *generic.DictionaryObject {
	if h.trailer == nil {
		return nil
	}
	return h.trailer.DictionaryObject
}

// RootRef returns a reference to the document catalog.
func (h *BasePdfHandler) RootRef() generic.Reference {
	if h.trailer == nil {
		return generic.Reference{}
	}
	root := h.trailer.Get("Root")
	if ref, ok := root.(*generic.IndirectObject); ok {
		return generic.Reference{
			ObjectNumber:     ref.ObjectNumber,
			GenerationNumber: ref.GenerationNumber,
		}
	}
	return generic.Reference{}
}

// DocumentID returns the document ID.
func (h *BasePdfHandler) DocumentID() ([]byte, []byte) {
	if h.trailer == nil {
		return nil, nil
	}

	idArray := h.trailer.GetArray("ID")
	if idArray == nil || len(idArray) < 2 {
		return nil, nil
	}

	var id1, id2 []byte

	if str, ok := idArray[0].(*generic.StringObject); ok {
		id1 = str.Value
	}
	if str, ok := idArray[1].(*generic.StringObject); ok {
		id2 = str.Value
	}

	return id1, id2
}

// PageTreeWalker helps traverse the page tree.
type PageTreeWalker struct {
	handler    PdfHandler
	pageIndex  int
	currentRef generic.Reference
}

// NewPageTreeWalker creates a new page tree walker.
func NewPageTreeWalker(handler PdfHandler) *PageTreeWalker {
	return &PageTreeWalker{
		handler:   handler,
		pageIndex: -1,
	}
}

// GetPage retrieves a page by index.
func (w *PageTreeWalker) GetPage(index int) (*generic.DictionaryObject, error) {
	root := w.handler.Root()
	if root == nil {
		return nil, ErrObjectNotFound
	}

	pagesRef := root.Get("Pages")
	if pagesRef == nil {
		return nil, ErrObjectNotFound
	}

	// Get the pages dictionary
	var pagesDict *generic.DictionaryObject
	switch v := pagesRef.(type) {
	case *generic.IndirectObject:
		obj, err := w.handler.GetObject(generic.Reference{
			ObjectNumber:     v.ObjectNumber,
			GenerationNumber: v.GenerationNumber,
		})
		if err != nil {
			return nil, err
		}
		if dict, ok := obj.(*generic.DictionaryObject); ok {
			pagesDict = dict
		}
	case *generic.DictionaryObject:
		pagesDict = v
	}

	if pagesDict == nil {
		return nil, ErrObjectNotFound
	}

	// Handle negative indices
	if count, ok := pagesDict.GetInt("Count"); ok && index < 0 {
		index = int(count) + index
	}

	// Walk the page tree to find the page
	return w.walkPageTree(pagesDict, index, 0)
}

// walkPageTree recursively walks the page tree.
func (w *PageTreeWalker) walkPageTree(node *generic.DictionaryObject, targetIndex, currentIndex int) (*generic.DictionaryObject, error) {
	nodeType := node.GetName("Type")

	if nodeType == "Page" {
		if currentIndex == targetIndex {
			return node, nil
		}
		return nil, nil
	}

	// It's a Pages node
	kids := node.GetArray("Kids")
	if kids == nil {
		return nil, ErrObjectNotFound
	}

	for _, kid := range kids {
		var kidDict *generic.DictionaryObject

		switch v := kid.(type) {
		case *generic.IndirectObject:
			obj, err := w.handler.GetObject(generic.Reference{
				ObjectNumber:     v.ObjectNumber,
				GenerationNumber: v.GenerationNumber,
			})
			if err != nil {
				continue
			}
			if dict, ok := obj.(*generic.DictionaryObject); ok {
				kidDict = dict
			}
		case *generic.DictionaryObject:
			kidDict = v
		}

		if kidDict == nil {
			continue
		}

		kidType := kidDict.GetName("Type")

		if kidType == "Page" {
			if currentIndex == targetIndex {
				return kidDict, nil
			}
			currentIndex++
		} else {
			// Pages node
			count, _ := kidDict.GetInt("Count")
			if currentIndex+int(count) > targetIndex {
				// Target is within this subtree
				result, err := w.walkPageTree(kidDict, targetIndex, currentIndex)
				if err != nil {
					return nil, err
				}
				if result != nil {
					return result, nil
				}
			}
			currentIndex += int(count)
		}
	}

	return nil, nil
}

// PositionDict tracks object positions in a PDF file.
type PositionDict struct {
	positions map[int]int64
}

// NewPositionDict creates a new position dictionary.
func NewPositionDict() *PositionDict {
	return &PositionDict{
		positions: make(map[int]int64),
	}
}

// Set records the position of an object.
func (p *PositionDict) Set(objNum int, pos int64) {
	p.positions[objNum] = pos
}

// Get retrieves the position of an object.
func (p *PositionDict) Get(objNum int) (int64, bool) {
	pos, ok := p.positions[objNum]
	return pos, ok
}

// All returns all positions.
func (p *PositionDict) All() map[int]int64 {
	return p.positions
}

// ObjectHeaderReadError represents an error reading an object header.
type ObjectHeaderReadError struct {
	Message  string
	Position int64
}

// Error implements the error interface.
func (e *ObjectHeaderReadError) Error() string {
	return e.Message
}

// ReadObjectHeader reads and parses an object header.
func ReadObjectHeader(data []byte, pos int64) (int, int, int64, error) {
	// Expected format: "objNum genNum obj"
	start := pos
	end := pos

	// Find the end of the line
	for end < int64(len(data)) && data[end] != '\n' && data[end] != '\r' {
		end++
	}

	if end >= int64(len(data)) {
		return 0, 0, 0, &ObjectHeaderReadError{
			Message:  "unexpected end of file reading object header",
			Position: pos,
		}
	}

	line := string(data[start:end])

	var objNum, genNum int
	var keyword string
	n, err := parseObjectHeader(line, &objNum, &genNum, &keyword)
	if err != nil || n < 3 || keyword != "obj" {
		return 0, 0, 0, &ObjectHeaderReadError{
			Message:  "invalid object header: " + line,
			Position: pos,
		}
	}

	// Skip past the newline
	end++
	if end < int64(len(data)) && (data[end] == '\n' || data[end] == '\r') {
		end++
	}

	return objNum, genNum, end, nil
}

func parseObjectHeader(line string, objNum, genNum *int, keyword *string) (int, error) {
	_, err := fmt.Sscanf(line, "%d %d %s", objNum, genNum, keyword)
	if err != nil {
		return 0, err
	}
	return 3, nil
}

// GetResourceDict retrieves the resource dictionary for a page.
func GetResourceDict(page *generic.DictionaryObject, handler PdfHandler) *generic.DictionaryObject {
	// Check page directly
	if resources := page.GetDict("Resources"); resources != nil {
		return resources
	}

	// Walk up to parent pages node
	parent := page.Get("Parent")
	if parent == nil {
		return nil
	}

	var parentDict *generic.DictionaryObject
	switch v := parent.(type) {
	case *generic.IndirectObject:
		obj, err := handler.GetObject(generic.Reference{
			ObjectNumber:     v.ObjectNumber,
			GenerationNumber: v.GenerationNumber,
		})
		if err == nil {
			if dict, ok := obj.(*generic.DictionaryObject); ok {
				parentDict = dict
			}
		}
	case *generic.DictionaryObject:
		parentDict = v
	}

	if parentDict != nil {
		return GetResourceDict(parentDict, handler)
	}

	return nil
}
