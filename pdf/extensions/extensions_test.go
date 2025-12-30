package extensions

import (
	"testing"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

func TestNewDeveloperExtension(t *testing.T) {
	ext := NewDeveloperExtension("ADBE", "1.7", 3)

	if ext.PrefixName != "ADBE" {
		t.Errorf("Expected PrefixName 'ADBE', got '%s'", ext.PrefixName)
	}

	if ext.BaseVersion != "1.7" {
		t.Errorf("Expected BaseVersion '1.7', got '%s'", ext.BaseVersion)
	}

	if ext.ExtensionLevel != 3 {
		t.Errorf("Expected ExtensionLevel 3, got %d", ext.ExtensionLevel)
	}

	if ext.Multivalued != ExtensionMaybe {
		t.Errorf("Expected Multivalued to be ExtensionMaybe")
	}

	if ext.CompareByLevel {
		t.Error("Expected CompareByLevel to be false by default")
	}
}

func TestDeveloperExtensionAsPdfObject(t *testing.T) {
	ext := &DeveloperExtension{
		PrefixName:        "ADBE",
		BaseVersion:       "1.7",
		ExtensionLevel:    3,
		URL:               "https://example.com/ext",
		ExtensionRevision: "2024-01",
	}

	obj := ext.AsPdfObject()

	if obj.GetName("Type") != "DeveloperExtensions" {
		t.Error("Expected Type to be DeveloperExtensions")
	}

	if obj.GetName("BaseVersion") != "1.7" {
		t.Error("Expected BaseVersion to be '1.7'")
	}

	if level, ok := obj.GetInt("ExtensionLevel"); !ok || level != 3 {
		t.Errorf("Expected ExtensionLevel 3, got %d", level)
	}

	if getString(obj, "URL") != "https://example.com/ext" {
		t.Error("Expected URL to be set")
	}

	if getString(obj, "ExtensionRevision") != "2024-01" {
		t.Error("Expected ExtensionRevision to be set")
	}
}

func TestDeveloperExtensionAsPdfObjectMinimal(t *testing.T) {
	ext := NewDeveloperExtension("TEST", "2.0", 1)

	obj := ext.AsPdfObject()

	// Should not have optional fields
	if obj.Has("URL") {
		t.Error("URL should not be set for minimal extension")
	}

	if obj.Has("ExtensionRevision") {
		t.Error("ExtensionRevision should not be set for minimal extension")
	}
}

func TestDeveloperExtensionShouldOverrideByLevel(t *testing.T) {
	ext := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 5,
		CompareByLevel: true,
	}

	// Should override lower levels
	if !ext.ShouldOverride(3) {
		t.Error("Extension level 5 should override level 3")
	}

	// Should not override higher levels
	if ext.ShouldOverride(7) {
		t.Error("Extension level 5 should not override level 7")
	}

	// Should not override equal levels
	if ext.ShouldOverride(5) {
		t.Error("Extension level 5 should not override level 5")
	}
}

func TestDeveloperExtensionShouldOverrideBySubsumes(t *testing.T) {
	ext := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 5,
		CompareByLevel: false,
		SubsumedBy:     []int{10, 15},
		Subsumes:       []int{1, 2, 3},
	}

	// Should override levels in Subsumes
	if !ext.ShouldOverride(2) {
		t.Error("Extension should override level 2 (in Subsumes)")
	}

	// Should not override levels in SubsumedBy
	if ext.ShouldOverride(10) {
		t.Error("Extension should not override level 10 (in SubsumedBy)")
	}

	// Should not override unknown levels
	if ext.ShouldOverride(7) {
		t.Error("Extension should not override unknown level 7")
	}
}

func TestDeveloperExtensionIsSubsumedBy(t *testing.T) {
	ext := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 5,
		CompareByLevel: false,
		SubsumedBy:     []int{10, 15},
	}

	if !ext.IsSubsumedBy(10) {
		t.Error("Extension should be subsumed by level 10")
	}

	if ext.IsSubsumedBy(3) {
		t.Error("Extension should not be subsumed by level 3")
	}
}

func TestDeveloperExtensionIsSubsumedByLevel(t *testing.T) {
	ext := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 5,
		CompareByLevel: true,
	}

	if !ext.IsSubsumedBy(10) {
		t.Error("Extension level 5 should be subsumed by level 10")
	}

	if ext.IsSubsumedBy(3) {
		t.Error("Extension level 5 should not be subsumed by level 3")
	}
}

func TestExtensionRegistry(t *testing.T) {
	registry := NewExtensionRegistry()

	ext1 := NewDeveloperExtension("ADBE", "1.7", 3)
	ext2 := NewDeveloperExtension("ADBE", "2.0", 1)
	ext3 := NewDeveloperExtension("ISO_", "2.0", 1)

	registry.Register(ext1)
	registry.Register(ext2)
	registry.Register(ext3)

	adbeExts := registry.Get("ADBE")
	if len(adbeExts) != 2 {
		t.Errorf("Expected 2 ADBE extensions, got %d", len(adbeExts))
	}

	isoExts := registry.Get("ISO_")
	if len(isoExts) != 1 {
		t.Errorf("Expected 1 ISO_ extension, got %d", len(isoExts))
	}

	all := registry.GetAll()
	if len(all) != 2 {
		t.Errorf("Expected 2 prefixes, got %d", len(all))
	}
}

func TestExtensionRegistryOverride(t *testing.T) {
	registry := NewExtensionRegistry()

	ext1 := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 3,
		CompareByLevel: true,
	}

	ext2 := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 5,
		CompareByLevel: true,
	}

	registry.Register(ext1)
	registry.Register(ext2)

	exts := registry.Get("ADBE")
	if len(exts) != 1 {
		t.Errorf("Expected 1 extension after override, got %d", len(exts))
	}

	if exts[0].ExtensionLevel != 5 {
		t.Errorf("Expected extension level 5 after override, got %d", exts[0].ExtensionLevel)
	}
}

func TestExtensionRegistryNoOverride(t *testing.T) {
	registry := NewExtensionRegistry()

	ext1 := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 5,
		CompareByLevel: true,
	}

	ext2 := &DeveloperExtension{
		PrefixName:     "ADBE",
		BaseVersion:    "1.7",
		ExtensionLevel: 3,
		CompareByLevel: true,
	}

	registry.Register(ext1)
	registry.Register(ext2)

	exts := registry.Get("ADBE")
	if len(exts) != 1 {
		t.Errorf("Expected 1 extension (no override), got %d", len(exts))
	}

	if exts[0].ExtensionLevel != 5 {
		t.Errorf("Expected extension level 5 (original), got %d", exts[0].ExtensionLevel)
	}
}

func TestExtensionRegistryAsPdfObject(t *testing.T) {
	registry := NewExtensionRegistry()

	ext1 := NewDeveloperExtension("ADBE", "1.7", 3)
	ext1.Multivalued = ExtensionNever
	registry.Register(ext1)

	obj := registry.AsPdfObject()

	if !obj.Has("ADBE") {
		t.Error("Expected ADBE key in extensions dictionary")
	}

	// Single extension should be a dictionary, not array
	adbeVal := obj.Get("ADBE")
	if _, ok := adbeVal.(*generic.DictionaryObject); !ok {
		t.Error("Expected single extension to be a dictionary")
	}
}

func TestExtensionRegistryAsPdfObjectMultivalued(t *testing.T) {
	registry := NewExtensionRegistry()

	ext1 := NewDeveloperExtension("ADBE", "1.7", 3)
	ext1.Multivalued = ExtensionAlways

	ext2 := NewDeveloperExtension("ADBE", "2.0", 1)
	ext2.Multivalued = ExtensionAlways

	registry.Register(ext1)
	registry.Register(ext2)

	obj := registry.AsPdfObject()

	adbeVal := obj.Get("ADBE")
	if arr, ok := adbeVal.(generic.ArrayObject); !ok {
		t.Error("Expected multivalued extensions to be an array")
	} else if len(arr) != 2 {
		t.Errorf("Expected 2 extensions in array, got %d", len(arr))
	}
}

func TestADBEExtension(t *testing.T) {
	ext := ADBEExtension(5)

	if ext.PrefixName != "ADBE" {
		t.Errorf("Expected PrefixName 'ADBE', got '%s'", ext.PrefixName)
	}

	if ext.BaseVersion != "1.7" {
		t.Errorf("Expected BaseVersion '1.7', got '%s'", ext.BaseVersion)
	}

	if ext.ExtensionLevel != 5 {
		t.Errorf("Expected ExtensionLevel 5, got %d", ext.ExtensionLevel)
	}

	if !ext.CompareByLevel {
		t.Error("ADBE extensions should compare by level")
	}

	if ext.Multivalued != ExtensionNever {
		t.Error("ADBE extensions should never be multivalued")
	}
}

func TestISO32000Extension(t *testing.T) {
	ext := ISO32000Extension("2.0", 1)

	if ext.PrefixName != "ISO_" {
		t.Errorf("Expected PrefixName 'ISO_', got '%s'", ext.PrefixName)
	}

	if ext.BaseVersion != "2.0" {
		t.Errorf("Expected BaseVersion '2.0', got '%s'", ext.BaseVersion)
	}

	if ext.ExtensionLevel != 1 {
		t.Errorf("Expected ExtensionLevel 1, got %d", ext.ExtensionLevel)
	}

	if !ext.CompareByLevel {
		t.Error("ISO extensions should compare by level")
	}
}

func TestParseExtensionsDict(t *testing.T) {
	dict := generic.NewDictionary()

	adbeExt := generic.NewDictionary()
	adbeExt.Set("BaseVersion", generic.NameObject("1.7"))
	adbeExt.Set("ExtensionLevel", generic.IntegerObject(3))
	adbeExt.Set("URL", generic.NewTextString("https://adobe.com"))
	dict.Set("ADBE", adbeExt)

	registry, err := ParseExtensionsDict(dict)
	if err != nil {
		t.Fatalf("ParseExtensionsDict failed: %v", err)
	}

	exts := registry.Get("ADBE")
	if len(exts) != 1 {
		t.Errorf("Expected 1 ADBE extension, got %d", len(exts))
	}

	if exts[0].BaseVersion != "1.7" {
		t.Errorf("Expected BaseVersion '1.7', got '%s'", exts[0].BaseVersion)
	}

	if exts[0].ExtensionLevel != 3 {
		t.Errorf("Expected ExtensionLevel 3, got %d", exts[0].ExtensionLevel)
	}

	if exts[0].URL != "https://adobe.com" {
		t.Errorf("Expected URL 'https://adobe.com', got '%s'", exts[0].URL)
	}
}

func TestParseExtensionsDictMultivalued(t *testing.T) {
	dict := generic.NewDictionary()

	ext1 := generic.NewDictionary()
	ext1.Set("BaseVersion", generic.NameObject("1.7"))
	ext1.Set("ExtensionLevel", generic.IntegerObject(3))

	ext2 := generic.NewDictionary()
	ext2.Set("BaseVersion", generic.NameObject("2.0"))
	ext2.Set("ExtensionLevel", generic.IntegerObject(1))

	arr := generic.ArrayObject{ext1, ext2}
	dict.Set("ADBE", arr)

	registry, err := ParseExtensionsDict(dict)
	if err != nil {
		t.Fatalf("ParseExtensionsDict failed: %v", err)
	}

	exts := registry.Get("ADBE")
	if len(exts) != 2 {
		t.Errorf("Expected 2 ADBE extensions, got %d", len(exts))
	}
}

func TestParseExtensionsDictNil(t *testing.T) {
	registry, err := ParseExtensionsDict(nil)
	if err != nil {
		t.Fatalf("ParseExtensionsDict(nil) failed: %v", err)
	}

	if len(registry.GetAll()) != 0 {
		t.Error("Expected empty registry for nil input")
	}
}

func TestDevExtensionMultivaluedConstants(t *testing.T) {
	// Verify the constants have distinct values
	if ExtensionAlways == ExtensionNever {
		t.Error("ExtensionAlways and ExtensionNever should be different")
	}

	if ExtensionNever == ExtensionMaybe {
		t.Error("ExtensionNever and ExtensionMaybe should be different")
	}

	if ExtensionAlways == ExtensionMaybe {
		t.Error("ExtensionAlways and ExtensionMaybe should be different")
	}
}
