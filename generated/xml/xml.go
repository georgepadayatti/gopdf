// Package xml provides W3C XML namespace types.
package xml

// Namespace is the W3C XML namespace.
const Namespace = "http://www.w3.org/XML/1998/namespace"

// LangValue represents xml:lang attribute value type.
type LangValue string

const (
	// LangValueEmpty represents an empty language value.
	LangValueEmpty LangValue = ""
)

// String returns the string representation of the LangValue.
func (l LangValue) String() string {
	return string(l)
}

// IsValid checks if the language value is valid (non-empty for real usage).
func (l LangValue) IsValid() bool {
	return l != LangValueEmpty
}
