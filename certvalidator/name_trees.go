// Package certvalidator provides X.509 certificate path validation.
// This file contains name constraint processing for RFC 5280 path validation.
package certvalidator

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// NameConstraintError indicates an error in name constraint processing.
var ErrNameConstraint = errors.New("name constraint error")

// GeneralNameType represents the type of a GeneralName in X.509.
type GeneralNameType int

const (
	// GeneralNameOtherName represents an otherName (OID-based)
	GeneralNameOtherName GeneralNameType = iota
	// GeneralNameRFC822Name represents an email address (RFC 822)
	GeneralNameRFC822Name
	// GeneralNameDNSName represents a DNS domain name
	GeneralNameDNSName
	// GeneralNameX400Address represents an X.400 address
	GeneralNameX400Address
	// GeneralNameDirectoryName represents an X.500 distinguished name
	GeneralNameDirectoryName
	// GeneralNameEDIPartyName represents an EDI party name
	GeneralNameEDIPartyName
	// GeneralNameURI represents a Uniform Resource Identifier
	GeneralNameURI
	// GeneralNameIPAddress represents an IP address
	GeneralNameIPAddress
	// GeneralNameRegisteredID represents a registered OID
	GeneralNameRegisteredID
)

// String returns the string representation of GeneralNameType.
func (t GeneralNameType) String() string {
	switch t {
	case GeneralNameOtherName:
		return "otherName"
	case GeneralNameRFC822Name:
		return "rfc822Name"
	case GeneralNameDNSName:
		return "dNSName"
	case GeneralNameX400Address:
		return "x400Address"
	case GeneralNameDirectoryName:
		return "directoryName"
	case GeneralNameEDIPartyName:
		return "ediPartyName"
	case GeneralNameURI:
		return "uniformResourceIdentifier"
	case GeneralNameIPAddress:
		return "iPAddress"
	case GeneralNameRegisteredID:
		return "registeredID"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// HostTreeContains checks if other_host is contained in the base_host tree.
// If base_host starts with '.', it specifies a domain that must be expanded
// with one or more labels. Otherwise, it refers to a single host (exact match).
func HostTreeContains(baseHost, otherHost string) bool {
	if len(baseHost) == 0 {
		return false
	}

	if baseHost[0] == '.' {
		// Domain constraint: other host must end with base and have additional prefix
		if !strings.HasSuffix(strings.ToLower(otherHost), strings.ToLower(baseHost)) {
			return false
		}
		// Must have at least one label before the base domain
		prefix := otherHost[:len(otherHost)-len(baseHost)]
		return len(prefix) > 0
	}

	// Exact match
	return strings.EqualFold(otherHost, baseHost)
}

// DNSTreeContains checks if 'other' is contained in the 'base' DNS domain tree.
// Returns true if 'other' consists of adding zero or more labels to 'base' from the left.
func DNSTreeContains(base, other string) bool {
	baseLabels := strings.Split(strings.ToLower(base), ".")
	otherLabels := strings.Split(strings.ToLower(other), ".")

	if len(otherLabels) < len(baseLabels) {
		return false
	}

	// Compare from the right (most significant labels)
	offset := len(otherLabels) - len(baseLabels)
	for i := 0; i < len(baseLabels); i++ {
		if otherLabels[offset+i] != baseLabels[i] {
			return false
		}
	}

	return true
}

// EmailTreeContains checks if 'other' email is contained in the 'base' email constraint.
// If base has a mailbox (local part), only exact match is allowed.
// Otherwise, it's a domain constraint.
func EmailTreeContains(base, other string) bool {
	baseMailbox, baseHost := splitEmail(base)
	otherMailbox, otherHost := splitEmail(other)

	if baseMailbox != "" {
		// Exact match only
		return strings.EqualFold(base, other)
	}

	// Domain/host constraint
	if otherMailbox == "" {
		return false // other must be a full email address
	}

	return HostTreeContains(baseHost, otherHost)
}

// splitEmail splits an email address into mailbox and host parts.
func splitEmail(email string) (mailbox, host string) {
	idx := strings.LastIndex(email, "@")
	if idx < 0 {
		return "", email
	}
	return email[:idx], email[idx+1:]
}

// URITreeContains checks if 'other' URI is contained in the 'base' URI constraint.
// The constraint applies to the host part of the URI.
func URITreeContains(base, other string) (bool, error) {
	otherHost, err := extractURIHost(other)
	if err != nil {
		return false, err
	}

	return HostTreeContains(base, otherHost), nil
}

// extractURIHost extracts the host from a URI.
func extractURIHost(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("%w: URI '%s' is not well-formed", ErrNameConstraint, uri)
	}

	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w: URI '%s' has no host", ErrNameConstraint, uri)
	}

	// Check if it's an IP address (not allowed for URI constraints per RFC 5280)
	if isIPAddress(host) {
		return "", fmt.Errorf("%w: URI constraints require FQDN, not IP address", ErrNameConstraint)
	}

	return host, nil
}

// isIPAddress checks if a string looks like an IP address.
func isIPAddress(s string) bool {
	// Simple check: contains only digits and dots (IPv4) or colons (IPv6)
	for _, c := range s {
		if (c >= '0' && c <= '9') || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	// Must have at least one dot or colon
	return strings.Contains(s, ".") || strings.Contains(s, ":")
}

// DirectoryNameTreeContains checks if 'other' directory name is contained in 'base'.
// Returns true if 'other' starts with all RDNs from 'base'.
func DirectoryNameTreeContains(base, other pkix.Name) bool {
	baseRDNs := flattenName(base)
	otherRDNs := flattenName(other)

	if len(otherRDNs) < len(baseRDNs) {
		return false
	}

	// Compare RDN sequences from the beginning
	for i, baseRDN := range baseRDNs {
		if !rdnEqual(baseRDN, otherRDNs[i]) {
			return false
		}
	}

	return true
}

// flattenName converts a pkix.Name to a slice of attribute type-value pairs.
func flattenName(name pkix.Name) []pkix.AttributeTypeAndValue {
	var result []pkix.AttributeTypeAndValue
	for _, rdn := range name.Names {
		result = append(result, rdn)
	}
	return result
}

// rdnEqual compares two AttributeTypeAndValue for equality.
func rdnEqual(a, b pkix.AttributeTypeAndValue) bool {
	if !a.Type.Equal(b.Type) {
		return false
	}

	// Compare values as strings
	aStr, aOk := a.Value.(string)
	bStr, bOk := b.Value.(string)
	if aOk && bOk {
		return strings.EqualFold(aStr, bStr)
	}

	// Fall back to direct comparison
	return a.Value == b.Value
}

// NameSubtree represents a name subtree for constraint checking.
type NameSubtree struct {
	NameType GeneralNameType
	TreeBase interface{} // string or pkix.Name, nil for universal tree
	Min      int
	Max      int // -1 for no maximum
}

// NewNameSubtree creates a new name subtree.
func NewNameSubtree(nameType GeneralNameType, base interface{}) *NameSubtree {
	return &NameSubtree{
		NameType: nameType,
		TreeBase: base,
		Min:      0,
		Max:      -1,
	}
}

// UniversalSubtree creates a subtree that accepts all names of a given type.
func UniversalSubtree(nameType GeneralNameType) *NameSubtree {
	return &NameSubtree{
		NameType: nameType,
		TreeBase: nil,
		Min:      0,
		Max:      -1,
	}
}

// Contains checks if the given name is contained in this subtree.
func (s *NameSubtree) Contains(name interface{}) (bool, error) {
	if s.TreeBase == nil {
		// Universal tree accepts all names
		return true, nil
	}

	// Check min/max constraints (not commonly used in PKIX)
	if s.Min != 0 || s.Max != -1 {
		return false, fmt.Errorf("minimum/maximum fields on name constraints are not supported in PKIX profile")
	}

	switch s.NameType {
	case GeneralNameDNSName:
		base, ok := s.TreeBase.(string)
		if !ok {
			return false, fmt.Errorf("DNS constraint base must be string")
		}
		other, ok := name.(string)
		if !ok {
			return false, fmt.Errorf("DNS name must be string")
		}
		return DNSTreeContains(base, other), nil

	case GeneralNameRFC822Name:
		base, ok := s.TreeBase.(string)
		if !ok {
			return false, fmt.Errorf("email constraint base must be string")
		}
		other, ok := name.(string)
		if !ok {
			return false, fmt.Errorf("email name must be string")
		}
		return EmailTreeContains(base, other), nil

	case GeneralNameURI:
		base, ok := s.TreeBase.(string)
		if !ok {
			return false, fmt.Errorf("URI constraint base must be string")
		}
		other, ok := name.(string)
		if !ok {
			return false, fmt.Errorf("URI must be string")
		}
		return URITreeContains(base, other)

	case GeneralNameDirectoryName:
		base, ok := s.TreeBase.(pkix.Name)
		if !ok {
			return false, fmt.Errorf("directory name constraint base must be pkix.Name")
		}
		other, ok := name.(pkix.Name)
		if !ok {
			return false, fmt.Errorf("directory name must be pkix.Name")
		}
		return DirectoryNameTreeContains(base, other), nil

	default:
		return false, fmt.Errorf("unsupported name type: %v", s.NameType)
	}
}

// NameConstraintValidationResult contains the result of name constraint validation.
type NameConstraintValidationResult struct {
	FailingNameType *GeneralNameType
	FailingName     interface{}
}

// IsValid returns true if no name constraint was violated.
func (r *NameConstraintValidationResult) IsValid() bool {
	return r.FailingNameType == nil
}

// ErrorMessage returns an error message if validation failed.
func (r *NameConstraintValidationResult) ErrorMessage() string {
	if r.FailingNameType == nil {
		return ""
	}

	nameStr := fmt.Sprintf("%v", r.FailingName)
	if name, ok := r.FailingName.(pkix.Name); ok {
		nameStr = name.String()
	}

	return fmt.Sprintf("the name '%s' of type %s is not allowed", nameStr, r.FailingNameType.String())
}

// PermittedSubtrees manages permitted name subtrees for certificate validation.
type PermittedSubtrees struct {
	// trees maps name type to generations of permitted subtrees
	// Each generation represents constraints from a certificate in the chain
	trees map[GeneralNameType][][]*NameSubtree
}

// NewPermittedSubtrees creates a new PermittedSubtrees with initial permitted subtrees.
func NewPermittedSubtrees(initial map[GeneralNameType][]*NameSubtree) *PermittedSubtrees {
	ps := &PermittedSubtrees{
		trees: make(map[GeneralNameType][][]*NameSubtree),
	}

	// Initialize with universal acceptors for all name types if not specified
	for nameType := GeneralNameOtherName; nameType <= GeneralNameRegisteredID; nameType++ {
		if subtrees, ok := initial[nameType]; ok && len(subtrees) > 0 {
			ps.trees[nameType] = [][]*NameSubtree{subtrees}
		} else {
			ps.trees[nameType] = [][]*NameSubtree{{UniversalSubtree(nameType)}}
		}
	}

	return ps
}

// IntersectWith adds a new generation of permitted subtrees.
func (ps *PermittedSubtrees) IntersectWith(subtrees map[GeneralNameType][]*NameSubtree) {
	for nameType, newSubtrees := range subtrees {
		if len(newSubtrees) > 0 {
			ps.trees[nameType] = append(ps.trees[nameType], newSubtrees)
		}
	}
}

// AcceptName checks if a name is permitted by all generations of constraints.
func (ps *PermittedSubtrees) AcceptName(nameType GeneralNameType, name interface{}) bool {
	generations := ps.trees[nameType]

	// Check all generations in reverse order (newest first for efficiency)
	for i := len(generations) - 1; i >= 0; i-- {
		generation := generations[i]
		accepted := false
		for _, subtree := range generation {
			contains, err := subtree.Contains(name)
			if err == nil && contains {
				accepted = true
				break
			}
		}
		if !accepted {
			return false
		}
	}

	return true
}

// AcceptCert checks if all names in a certificate are permitted.
func (ps *PermittedSubtrees) AcceptCert(cert *x509.Certificate) *NameConstraintValidationResult {
	// Check subject DN if non-empty
	if len(cert.Subject.Names) > 0 {
		if !ps.AcceptName(GeneralNameDirectoryName, cert.Subject) {
			t := GeneralNameDirectoryName
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     cert.Subject,
			}
		}
	}

	// Check DNS names
	for _, dns := range cert.DNSNames {
		if !ps.AcceptName(GeneralNameDNSName, dns) {
			t := GeneralNameDNSName
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     dns,
			}
		}
	}

	// Check email addresses
	for _, email := range cert.EmailAddresses {
		if !ps.AcceptName(GeneralNameRFC822Name, email) {
			t := GeneralNameRFC822Name
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     email,
			}
		}
	}

	// Check URIs
	for _, uri := range cert.URIs {
		if !ps.AcceptName(GeneralNameURI, uri.String()) {
			t := GeneralNameURI
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     uri.String(),
			}
		}
	}

	return &NameConstraintValidationResult{}
}

// ExcludedSubtrees manages excluded name subtrees for certificate validation.
type ExcludedSubtrees struct {
	trees map[GeneralNameType][]*NameSubtree
}

// NewExcludedSubtrees creates a new ExcludedSubtrees with initial excluded subtrees.
func NewExcludedSubtrees(initial map[GeneralNameType][]*NameSubtree) *ExcludedSubtrees {
	es := &ExcludedSubtrees{
		trees: make(map[GeneralNameType][]*NameSubtree),
	}

	// Copy initial subtrees
	for nameType, subtrees := range initial {
		es.trees[nameType] = make([]*NameSubtree, len(subtrees))
		copy(es.trees[nameType], subtrees)
	}

	return es
}

// UnionWith adds excluded subtrees to the existing set.
func (es *ExcludedSubtrees) UnionWith(subtrees map[GeneralNameType][]*NameSubtree) {
	for nameType, newSubtrees := range subtrees {
		es.trees[nameType] = append(es.trees[nameType], newSubtrees...)
	}
}

// RejectName checks if a name is excluded.
func (es *ExcludedSubtrees) RejectName(nameType GeneralNameType, name interface{}) bool {
	subtrees := es.trees[nameType]
	for _, subtree := range subtrees {
		contains, err := subtree.Contains(name)
		if err == nil && contains {
			return true
		}
	}
	return false
}

// AcceptCert checks if all names in a certificate are not excluded.
func (es *ExcludedSubtrees) AcceptCert(cert *x509.Certificate) *NameConstraintValidationResult {
	// Check subject DN if non-empty
	if len(cert.Subject.Names) > 0 {
		if es.RejectName(GeneralNameDirectoryName, cert.Subject) {
			t := GeneralNameDirectoryName
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     cert.Subject,
			}
		}
	}

	// Check DNS names
	for _, dns := range cert.DNSNames {
		if es.RejectName(GeneralNameDNSName, dns) {
			t := GeneralNameDNSName
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     dns,
			}
		}
	}

	// Check email addresses
	for _, email := range cert.EmailAddresses {
		if es.RejectName(GeneralNameRFC822Name, email) {
			t := GeneralNameRFC822Name
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     email,
			}
		}
	}

	// Check URIs
	for _, uri := range cert.URIs {
		if es.RejectName(GeneralNameURI, uri.String()) {
			t := GeneralNameURI
			return &NameConstraintValidationResult{
				FailingNameType: &t,
				FailingName:     uri.String(),
			}
		}
	}

	return &NameConstraintValidationResult{}
}

// DefaultPermittedSubtrees returns default permitted subtrees that accept all names.
func DefaultPermittedSubtrees() map[GeneralNameType][]*NameSubtree {
	result := make(map[GeneralNameType][]*NameSubtree)
	for nameType := GeneralNameOtherName; nameType <= GeneralNameRegisteredID; nameType++ {
		result[nameType] = []*NameSubtree{UniversalSubtree(nameType)}
	}
	return result
}

// DefaultExcludedSubtrees returns default excluded subtrees (empty).
func DefaultExcludedSubtrees() map[GeneralNameType][]*NameSubtree {
	result := make(map[GeneralNameType][]*NameSubtree)
	for nameType := GeneralNameOtherName; nameType <= GeneralNameRegisteredID; nameType++ {
		result[nameType] = []*NameSubtree{}
	}
	return result
}

// NameConstraintChecker performs name constraint validation on certificate chains.
type NameConstraintChecker struct {
	Permitted *PermittedSubtrees
	Excluded  *ExcludedSubtrees
}

// NewNameConstraintChecker creates a new name constraint checker with default settings.
func NewNameConstraintChecker() *NameConstraintChecker {
	return &NameConstraintChecker{
		Permitted: NewPermittedSubtrees(DefaultPermittedSubtrees()),
		Excluded:  NewExcludedSubtrees(DefaultExcludedSubtrees()),
	}
}

// ProcessCertificate processes name constraints from a CA certificate.
func (nc *NameConstraintChecker) ProcessCertificate(cert *x509.Certificate) {
	// Add permitted constraints
	if len(cert.PermittedDNSDomains) > 0 || len(cert.PermittedEmailAddresses) > 0 ||
		len(cert.PermittedURIDomains) > 0 {

		permitted := make(map[GeneralNameType][]*NameSubtree)

		for _, dns := range cert.PermittedDNSDomains {
			permitted[GeneralNameDNSName] = append(permitted[GeneralNameDNSName],
				NewNameSubtree(GeneralNameDNSName, dns))
		}

		for _, email := range cert.PermittedEmailAddresses {
			permitted[GeneralNameRFC822Name] = append(permitted[GeneralNameRFC822Name],
				NewNameSubtree(GeneralNameRFC822Name, email))
		}

		for _, uri := range cert.PermittedURIDomains {
			permitted[GeneralNameURI] = append(permitted[GeneralNameURI],
				NewNameSubtree(GeneralNameURI, uri))
		}

		nc.Permitted.IntersectWith(permitted)
	}

	// Add excluded constraints
	if len(cert.ExcludedDNSDomains) > 0 || len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.ExcludedURIDomains) > 0 {

		excluded := make(map[GeneralNameType][]*NameSubtree)

		for _, dns := range cert.ExcludedDNSDomains {
			excluded[GeneralNameDNSName] = append(excluded[GeneralNameDNSName],
				NewNameSubtree(GeneralNameDNSName, dns))
		}

		for _, email := range cert.ExcludedEmailAddresses {
			excluded[GeneralNameRFC822Name] = append(excluded[GeneralNameRFC822Name],
				NewNameSubtree(GeneralNameRFC822Name, email))
		}

		for _, uri := range cert.ExcludedURIDomains {
			excluded[GeneralNameURI] = append(excluded[GeneralNameURI],
				NewNameSubtree(GeneralNameURI, uri))
		}

		nc.Excluded.UnionWith(excluded)
	}
}

// ValidateCertificate checks if a certificate's names satisfy all constraints.
func (nc *NameConstraintChecker) ValidateCertificate(cert *x509.Certificate) *NameConstraintValidationResult {
	// Check permitted constraints
	result := nc.Permitted.AcceptCert(cert)
	if !result.IsValid() {
		return result
	}

	// Check excluded constraints
	return nc.Excluded.AcceptCert(cert)
}

// ValidateChain validates name constraints for an entire certificate chain.
// The chain should be ordered from end-entity to root.
func (nc *NameConstraintChecker) ValidateChain(chain []*x509.Certificate) *NameConstraintValidationResult {
	// Process CA certificates from root to end-entity
	for i := len(chain) - 1; i >= 1; i-- {
		nc.ProcessCertificate(chain[i])
	}

	// Validate the end-entity certificate
	if len(chain) > 0 {
		return nc.ValidateCertificate(chain[0])
	}

	return &NameConstraintValidationResult{}
}
