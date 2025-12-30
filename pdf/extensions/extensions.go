// Package extensions provides PDF developer extension handling.
package extensions

import (
	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// DevExtensionMultivalued indicates how an extension should behave
// with respect to multivalued extensions in ISO 32000-2:2020.
type DevExtensionMultivalued int

const (
	// ExtensionAlways always serializes this extension as a multivalued extension.
	ExtensionAlways DevExtensionMultivalued = iota

	// ExtensionNever never serializes this extension as a multivalued extension.
	ExtensionNever

	// ExtensionMaybe makes this extension single-valued whenever possible,
	// but allows multiple values when a different but non-comparable extension
	// with the same prefix is already present in the file.
	ExtensionMaybe
)

// DeveloperExtension represents a PDF developer extension designation.
type DeveloperExtension struct {
	// PrefixName is the registered developer prefix.
	PrefixName string

	// BaseVersion is the base version onto which the extension applies.
	BaseVersion string

	// ExtensionLevel is the extension level number.
	ExtensionLevel int

	// URL is an optional URL linking to the extension's documentation.
	URL string

	// ExtensionRevision is optional extra revision information (not comparable).
	ExtensionRevision string

	// CompareByLevel indicates whether to compare extensions by level number.
	// If true and a copy of this extension already exists in the target file
	// with a higher level number, it will not be overridden.
	// If one exists with a lower level number, it will be overridden.
	// If false, the decision is based on SubsumedBy and Subsumes.
	// Default is false since it's generally not safe to assume extension levels
	// are used as a versioning system.
	CompareByLevel bool

	// SubsumedBy lists extension levels that would subsume this one.
	// If one of these is present in the extensions dictionary, attempting to
	// register this extension will not override it.
	// Ignored if CompareByLevel is true.
	SubsumedBy []int

	// Subsumes lists extensions explicitly subsumed by this one.
	// If one of these is present in the extensions dictionary, attempting to
	// register this extension will override it.
	// Ignored if CompareByLevel is true.
	Subsumes []int

	// Multivalued indicates whether this extension should behave well with
	// the new mechanism for multivalued extensions in ISO 32000-2:2020.
	Multivalued DevExtensionMultivalued
}

// NewDeveloperExtension creates a new developer extension with required fields.
func NewDeveloperExtension(prefixName, baseVersion string, extensionLevel int) *DeveloperExtension {
	return &DeveloperExtension{
		PrefixName:     prefixName,
		BaseVersion:    baseVersion,
		ExtensionLevel: extensionLevel,
		Multivalued:    ExtensionMaybe,
		SubsumedBy:     []int{},
		Subsumes:       []int{},
	}
}

// AsPdfObject formats the extension data into a PDF dictionary for registration
// into the /Extensions dictionary.
func (e *DeveloperExtension) AsPdfObject() *generic.DictionaryObject {
	result := generic.NewDictionary()
	result.Set("Type", generic.NameObject("DeveloperExtensions"))
	result.Set("BaseVersion", generic.NameObject(e.BaseVersion))
	result.Set("ExtensionLevel", generic.IntegerObject(e.ExtensionLevel))

	if e.URL != "" {
		result.Set("URL", generic.NewTextString(e.URL))
	}

	if e.ExtensionRevision != "" {
		result.Set("ExtensionRevision", generic.NewTextString(e.ExtensionRevision))
	}

	return result
}

// ShouldOverride determines if this extension should override an existing one.
func (e *DeveloperExtension) ShouldOverride(existingLevel int) bool {
	if e.CompareByLevel {
		return e.ExtensionLevel > existingLevel
	}

	// Check if existing level subsumes this one
	for _, level := range e.SubsumedBy {
		if level == existingLevel {
			return false
		}
	}

	// Check if this extension subsumes the existing one
	for _, level := range e.Subsumes {
		if level == existingLevel {
			return true
		}
	}

	// Default: don't override
	return false
}

// IsSubsumedBy checks if this extension is subsumed by the given level.
func (e *DeveloperExtension) IsSubsumedBy(level int) bool {
	if e.CompareByLevel {
		return level > e.ExtensionLevel
	}

	for _, l := range e.SubsumedBy {
		if l == level {
			return true
		}
	}
	return false
}

// ExtensionRegistry manages a collection of developer extensions.
type ExtensionRegistry struct {
	extensions map[string][]*DeveloperExtension
}

// NewExtensionRegistry creates a new extension registry.
func NewExtensionRegistry() *ExtensionRegistry {
	return &ExtensionRegistry{
		extensions: make(map[string][]*DeveloperExtension),
	}
}

// Register adds an extension to the registry.
func (r *ExtensionRegistry) Register(ext *DeveloperExtension) {
	prefix := ext.PrefixName
	existing := r.extensions[prefix]

	// Check if we should override an existing extension
	for i, e := range existing {
		if e.BaseVersion == ext.BaseVersion {
			if ext.ShouldOverride(e.ExtensionLevel) {
				existing[i] = ext
				return
			}
			// Don't override
			return
		}
	}

	// Add new extension
	r.extensions[prefix] = append(existing, ext)
}

// Get returns extensions for a given prefix.
func (r *ExtensionRegistry) Get(prefix string) []*DeveloperExtension {
	return r.extensions[prefix]
}

// GetAll returns all registered extensions.
func (r *ExtensionRegistry) GetAll() map[string][]*DeveloperExtension {
	return r.extensions
}

// AsPdfObject converts the registry to a PDF Extensions dictionary.
func (r *ExtensionRegistry) AsPdfObject() *generic.DictionaryObject {
	result := generic.NewDictionary()

	for prefix, exts := range r.extensions {
		if len(exts) == 1 && exts[0].Multivalued != ExtensionAlways {
			// Single-valued extension
			result.Set(prefix, exts[0].AsPdfObject())
		} else {
			// Multivalued extension
			arr := make(generic.ArrayObject, 0, len(exts))
			for _, ext := range exts {
				arr = append(arr, ext.AsPdfObject())
			}
			result.Set(prefix, arr)
		}
	}

	return result
}

// Common PDF extensions

// ADBEExtension returns the Adobe developer extension for a given level.
func ADBEExtension(level int) *DeveloperExtension {
	return &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: level,
		CompareByLevel: true,
		Multivalued:    ExtensionNever,
	}
}

// ISO32000Extension returns an ISO 32000 extension for a given base version and level.
func ISO32000Extension(baseVersion string, level int) *DeveloperExtension {
	return &DeveloperExtension{
		PrefixName:     "ISO_",
		BaseVersion:    baseVersion,
		ExtensionLevel: level,
		CompareByLevel: true,
		Multivalued:    ExtensionMaybe,
	}
}

// ParseExtensionsDict parses a PDF /Extensions dictionary into an ExtensionRegistry.
func ParseExtensionsDict(dict *generic.DictionaryObject) (*ExtensionRegistry, error) {
	registry := NewExtensionRegistry()

	if dict == nil {
		return registry, nil
	}

	for _, key := range dict.Keys() {
		value := dict.Get(key)

		switch v := value.(type) {
		case *generic.DictionaryObject:
			// Single extension
			ext, err := parseExtensionDict(key, v)
			if err != nil {
				return nil, err
			}
			registry.Register(ext)

		case generic.ArrayObject:
			// Multiple extensions
			for _, item := range v {
				if extDict, ok := item.(*generic.DictionaryObject); ok {
					ext, err := parseExtensionDict(key, extDict)
					if err != nil {
						return nil, err
					}
					ext.Multivalued = ExtensionAlways
					registry.Register(ext)
				}
			}
		}
	}

	return registry, nil
}

func parseExtensionDict(prefix string, dict *generic.DictionaryObject) (*DeveloperExtension, error) {
	ext := &DeveloperExtension{
		PrefixName:  prefix,
		Multivalued: ExtensionMaybe,
		SubsumedBy:  []int{},
		Subsumes:    []int{},
	}

	if bv := dict.GetName("BaseVersion"); bv != "" {
		ext.BaseVersion = bv
	}

	if level, ok := dict.GetInt("ExtensionLevel"); ok {
		ext.ExtensionLevel = int(level)
	}

	if url := getString(dict, "URL"); url != "" {
		ext.URL = url
	}

	if rev := getString(dict, "ExtensionRevision"); rev != "" {
		ext.ExtensionRevision = rev
	}

	return ext, nil
}

// getString extracts a string value from a dictionary.
func getString(dict *generic.DictionaryObject, key string) string {
	obj := dict.Get(key)
	if obj == nil {
		return ""
	}
	if str, ok := obj.(*generic.StringObject); ok {
		return string(str.Value)
	}
	return ""
}
