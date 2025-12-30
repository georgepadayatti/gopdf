package certvalidator

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
)

func TestGeneralNameTypeString(t *testing.T) {
	tests := []struct {
		nameType GeneralNameType
		expected string
	}{
		{GeneralNameOtherName, "otherName"},
		{GeneralNameRFC822Name, "rfc822Name"},
		{GeneralNameDNSName, "dNSName"},
		{GeneralNameX400Address, "x400Address"},
		{GeneralNameDirectoryName, "directoryName"},
		{GeneralNameEDIPartyName, "ediPartyName"},
		{GeneralNameURI, "uniformResourceIdentifier"},
		{GeneralNameIPAddress, "iPAddress"},
		{GeneralNameRegisteredID, "registeredID"},
		{GeneralNameType(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.nameType.String(); got != tt.expected {
				t.Errorf("GeneralNameType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHostTreeContains(t *testing.T) {
	tests := []struct {
		name      string
		baseHost  string
		otherHost string
		want      bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"exact match case insensitive", "Example.COM", "example.com", true},
		{"domain constraint", ".example.com", "sub.example.com", true},
		{"domain constraint multi-level", ".example.com", "a.b.example.com", true},
		{"domain constraint case insensitive", ".Example.COM", "sub.example.com", true},
		{"domain constraint exact base", ".example.com", "example.com", false},
		{"domain constraint wrong domain", ".example.com", "sub.other.com", false},
		{"exact match different", "example.com", "other.com", false},
		{"empty base", "", "example.com", false},
		{"domain constraint no prefix", ".example.com", ".example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostTreeContains(tt.baseHost, tt.otherHost); got != tt.want {
				t.Errorf("HostTreeContains(%q, %q) = %v, want %v", tt.baseHost, tt.otherHost, got, tt.want)
			}
		})
	}
}

func TestDNSTreeContains(t *testing.T) {
	tests := []struct {
		name  string
		base  string
		other string
		want  bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"subdomain", "example.com", "sub.example.com", true},
		{"multi-level subdomain", "example.com", "a.b.c.example.com", true},
		{"case insensitive", "EXAMPLE.COM", "sub.example.com", true},
		{"different domain", "example.com", "other.com", false},
		{"partial match", "example.com", "notexample.com", false},
		{"longer base", "sub.example.com", "example.com", false},
		{"empty strings", "", "", true},
		{"single label", "com", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DNSTreeContains(tt.base, tt.other); got != tt.want {
				t.Errorf("DNSTreeContains(%q, %q) = %v, want %v", tt.base, tt.other, got, tt.want)
			}
		})
	}
}

func TestEmailTreeContains(t *testing.T) {
	tests := []struct {
		name  string
		base  string
		other string
		want  bool
	}{
		{"exact match", "user@example.com", "user@example.com", true},
		{"exact match case insensitive", "USER@Example.COM", "user@example.com", true},
		{"domain constraint", "example.com", "anyone@example.com", true},
		{"domain with dot prefix", ".example.com", "user@sub.example.com", true},
		{"different mailbox same domain", "user@example.com", "other@example.com", false},
		{"domain constraint wrong domain", "example.com", "user@other.com", false},
		{"mailbox constraint no match", "user@example.com", "user@other.com", false},
		{"domain vs no mailbox", "example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EmailTreeContains(tt.base, tt.other); got != tt.want {
				t.Errorf("EmailTreeContains(%q, %q) = %v, want %v", tt.base, tt.other, got, tt.want)
			}
		})
	}
}

func TestSplitEmail(t *testing.T) {
	tests := []struct {
		email       string
		wantMailbox string
		wantHost    string
	}{
		{"user@example.com", "user", "example.com"},
		{"user.name@sub.example.com", "user.name", "sub.example.com"},
		{"example.com", "", "example.com"},
		{".example.com", "", ".example.com"},
		{"user@", "user", ""},
		{"@example.com", "", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			gotMailbox, gotHost := splitEmail(tt.email)
			if gotMailbox != tt.wantMailbox {
				t.Errorf("splitEmail(%q) mailbox = %v, want %v", tt.email, gotMailbox, tt.wantMailbox)
			}
			if gotHost != tt.wantHost {
				t.Errorf("splitEmail(%q) host = %v, want %v", tt.email, gotHost, tt.wantHost)
			}
		})
	}
}

func TestURITreeContains(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		other   string
		want    bool
		wantErr bool
	}{
		{"domain match", "example.com", "https://example.com/path", true, false},
		{"subdomain", ".example.com", "https://sub.example.com/path", true, false},
		{"different domain", "example.com", "https://other.com/path", false, false},
		{"invalid URI", "example.com", "://invalid", false, true},
		{"IP address", "192.168.1.1", "https://192.168.1.1/path", false, true},
		{"no host URI", "example.com", "file:///path/to/file", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := URITreeContains(tt.base, tt.other)
			if (err != nil) != tt.wantErr {
				t.Errorf("URITreeContains() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("URITreeContains(%q, %q) = %v, want %v", tt.base, tt.other, got, tt.want)
			}
		})
	}
}

func TestExtractURIHost(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    string
		wantErr bool
	}{
		{"simple URL", "https://example.com/path", "example.com", false},
		{"with port", "https://example.com:8080/path", "example.com", false},
		{"subdomain", "https://sub.example.com/", "sub.example.com", false},
		{"no path", "https://example.com", "example.com", false},
		{"IP address", "https://192.168.1.1/path", "", true},
		{"IPv6 address", "https://[::1]/path", "", true},
		{"no host", "file:///path/to/file", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractURIHost(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractURIHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractURIHost(%q) = %v, want %v", tt.uri, got, tt.want)
			}
		})
	}
}

func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"example.com", false},
		{"sub.example.com", false},
		{"192.168", true}, // Partial IP is still considered IP-like
		{"abc123", false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isIPAddress(tt.s); got != tt.want {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestDirectoryNameTreeContains(t *testing.T) {
	// Create test pkix.Name objects
	baseName := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Test Org"},
	}
	baseName.Names = []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
	}

	matchingName := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Test Org"},
		OrganizationalUnit: []string{"IT"},
	}
	matchingName.Names = []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "IT"},
	}

	nonMatchingName := pkix.Name{
		Country:      []string{"UK"},
		Organization: []string{"Other Org"},
	}
	nonMatchingName.Names = []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "UK"},
		{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Other Org"},
	}

	tests := []struct {
		name  string
		base  pkix.Name
		other pkix.Name
		want  bool
	}{
		{"matching prefix", baseName, matchingName, true},
		{"non-matching", baseName, nonMatchingName, false},
		{"exact match", baseName, baseName, true},
		{"shorter other", matchingName, baseName, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DirectoryNameTreeContains(tt.base, tt.other); got != tt.want {
				t.Errorf("DirectoryNameTreeContains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNameSubtreeContains(t *testing.T) {
	t.Run("DNS name constraint", func(t *testing.T) {
		subtree := NewNameSubtree(GeneralNameDNSName, "example.com")
		contains, err := subtree.Contains("sub.example.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !contains {
			t.Error("expected subtree to contain sub.example.com")
		}

		contains, err = subtree.Contains("other.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if contains {
			t.Error("expected subtree to not contain other.com")
		}
	})

	t.Run("universal subtree", func(t *testing.T) {
		subtree := UniversalSubtree(GeneralNameDNSName)
		contains, err := subtree.Contains("anything.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !contains {
			t.Error("universal subtree should contain any name")
		}
	})

	t.Run("email constraint", func(t *testing.T) {
		subtree := NewNameSubtree(GeneralNameRFC822Name, "example.com")
		contains, err := subtree.Contains("user@example.com")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !contains {
			t.Error("expected subtree to contain user@example.com")
		}
	})

	t.Run("URI constraint", func(t *testing.T) {
		subtree := NewNameSubtree(GeneralNameURI, "example.com")
		contains, err := subtree.Contains("https://example.com/path")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !contains {
			t.Error("expected subtree to contain URI with matching host")
		}
	})

	t.Run("unsupported name type", func(t *testing.T) {
		subtree := NewNameSubtree(GeneralNameIPAddress, "192.168.1.0/24")
		_, err := subtree.Contains("192.168.1.1")
		if err == nil {
			t.Error("expected error for unsupported name type")
		}
	})

	t.Run("min/max not supported", func(t *testing.T) {
		subtree := &NameSubtree{
			NameType: GeneralNameDNSName,
			TreeBase: "example.com",
			Min:      1,
			Max:      10,
		}
		_, err := subtree.Contains("sub.example.com")
		if err == nil {
			t.Error("expected error for non-zero min/max")
		}
	})
}

func TestPermittedSubtrees(t *testing.T) {
	t.Run("default accepts all", func(t *testing.T) {
		ps := NewPermittedSubtrees(DefaultPermittedSubtrees())
		if !ps.AcceptName(GeneralNameDNSName, "anything.com") {
			t.Error("default permitted subtrees should accept any DNS name")
		}
	})

	t.Run("DNS constraint", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "example.com")},
		}
		ps := NewPermittedSubtrees(initial)

		if !ps.AcceptName(GeneralNameDNSName, "sub.example.com") {
			t.Error("should accept subdomain")
		}
		if ps.AcceptName(GeneralNameDNSName, "other.com") {
			t.Error("should reject other domain")
		}
	})

	t.Run("intersect constraints", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "example.com")},
		}
		ps := NewPermittedSubtrees(initial)

		// Add more restrictive constraint
		ps.IntersectWith(map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "sub.example.com")},
		})

		if !ps.AcceptName(GeneralNameDNSName, "deep.sub.example.com") {
			t.Error("should accept deep subdomain of sub.example.com")
		}
		if ps.AcceptName(GeneralNameDNSName, "other.example.com") {
			t.Error("should reject other.example.com after intersection")
		}
	})
}

func TestExcludedSubtrees(t *testing.T) {
	t.Run("default excludes nothing", func(t *testing.T) {
		es := NewExcludedSubtrees(DefaultExcludedSubtrees())
		if es.RejectName(GeneralNameDNSName, "anything.com") {
			t.Error("default excluded subtrees should not reject any DNS name")
		}
	})

	t.Run("DNS exclusion", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "excluded.com")},
		}
		es := NewExcludedSubtrees(initial)

		if !es.RejectName(GeneralNameDNSName, "sub.excluded.com") {
			t.Error("should reject subdomain of excluded domain")
		}
		if es.RejectName(GeneralNameDNSName, "allowed.com") {
			t.Error("should not reject non-excluded domain")
		}
	})

	t.Run("union exclusions", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "excluded1.com")},
		}
		es := NewExcludedSubtrees(initial)

		es.UnionWith(map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "excluded2.com")},
		})

		if !es.RejectName(GeneralNameDNSName, "sub.excluded1.com") {
			t.Error("should still reject first exclusion")
		}
		if !es.RejectName(GeneralNameDNSName, "sub.excluded2.com") {
			t.Error("should reject second exclusion after union")
		}
	})
}

func TestNameConstraintValidationResult(t *testing.T) {
	t.Run("valid result", func(t *testing.T) {
		result := &NameConstraintValidationResult{}
		if !result.IsValid() {
			t.Error("empty result should be valid")
		}
		if result.ErrorMessage() != "" {
			t.Error("valid result should have empty error message")
		}
	})

	t.Run("invalid result", func(t *testing.T) {
		dnsType := GeneralNameDNSName
		result := &NameConstraintValidationResult{
			FailingNameType: &dnsType,
			FailingName:     "bad.example.com",
		}
		if result.IsValid() {
			t.Error("result with failing name should not be valid")
		}
		msg := result.ErrorMessage()
		if msg == "" {
			t.Error("invalid result should have error message")
		}
		if !contains(msg, "bad.example.com") {
			t.Errorf("error message should contain failing name, got: %s", msg)
		}
		if !contains(msg, "dNSName") {
			t.Errorf("error message should contain name type, got: %s", msg)
		}
	})
}

func TestPermittedSubtreesAcceptCert(t *testing.T) {
	t.Run("accept cert with matching DNS", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "example.com")},
		}
		ps := NewPermittedSubtrees(initial)

		cert := &x509.Certificate{
			DNSNames: []string{"sub.example.com"},
		}

		result := ps.AcceptCert(cert)
		if !result.IsValid() {
			t.Errorf("should accept cert: %s", result.ErrorMessage())
		}
	})

	t.Run("reject cert with non-matching DNS", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "example.com")},
		}
		ps := NewPermittedSubtrees(initial)

		cert := &x509.Certificate{
			DNSNames: []string{"other.com"},
		}

		result := ps.AcceptCert(cert)
		if result.IsValid() {
			t.Error("should reject cert with non-permitted DNS name")
		}
	})

	t.Run("accept cert with matching email", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameRFC822Name: {NewNameSubtree(GeneralNameRFC822Name, "example.com")},
		}
		ps := NewPermittedSubtrees(initial)

		cert := &x509.Certificate{
			EmailAddresses: []string{"user@example.com"},
		}

		result := ps.AcceptCert(cert)
		if !result.IsValid() {
			t.Errorf("should accept cert: %s", result.ErrorMessage())
		}
	})

	t.Run("accept cert with matching URI", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameURI: {NewNameSubtree(GeneralNameURI, "example.com")},
		}
		ps := NewPermittedSubtrees(initial)

		uri, _ := url.Parse("https://example.com/path")
		cert := &x509.Certificate{
			URIs: []*url.URL{uri},
		}

		result := ps.AcceptCert(cert)
		if !result.IsValid() {
			t.Errorf("should accept cert: %s", result.ErrorMessage())
		}
	})
}

func TestExcludedSubtreesAcceptCert(t *testing.T) {
	t.Run("accept cert not in exclusions", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "excluded.com")},
		}
		es := NewExcludedSubtrees(initial)

		cert := &x509.Certificate{
			DNSNames: []string{"allowed.com"},
		}

		result := es.AcceptCert(cert)
		if !result.IsValid() {
			t.Errorf("should accept cert: %s", result.ErrorMessage())
		}
	})

	t.Run("reject cert with excluded DNS", func(t *testing.T) {
		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDNSName: {NewNameSubtree(GeneralNameDNSName, "excluded.com")},
		}
		es := NewExcludedSubtrees(initial)

		cert := &x509.Certificate{
			DNSNames: []string{"sub.excluded.com"},
		}

		result := es.AcceptCert(cert)
		if result.IsValid() {
			t.Error("should reject cert with excluded DNS name")
		}
	})
}

func TestNameConstraintChecker(t *testing.T) {
	t.Run("new checker accepts all", func(t *testing.T) {
		nc := NewNameConstraintChecker()
		cert := &x509.Certificate{
			DNSNames:       []string{"anything.com"},
			EmailAddresses: []string{"user@anything.com"},
		}

		result := nc.ValidateCertificate(cert)
		if !result.IsValid() {
			t.Errorf("new checker should accept all: %s", result.ErrorMessage())
		}
	})

	t.Run("process certificate constraints", func(t *testing.T) {
		nc := NewNameConstraintChecker()

		// CA certificate with permitted DNS constraint
		caCert := &x509.Certificate{
			PermittedDNSDomains: []string{"example.com"},
		}
		nc.ProcessCertificate(caCert)

		// Should accept matching
		goodCert := &x509.Certificate{
			DNSNames: []string{"sub.example.com"},
		}
		result := nc.ValidateCertificate(goodCert)
		if !result.IsValid() {
			t.Errorf("should accept permitted DNS: %s", result.ErrorMessage())
		}

		// Should reject non-matching
		badCert := &x509.Certificate{
			DNSNames: []string{"other.com"},
		}
		result = nc.ValidateCertificate(badCert)
		if result.IsValid() {
			t.Error("should reject non-permitted DNS")
		}
	})

	t.Run("process excluded constraints", func(t *testing.T) {
		nc := NewNameConstraintChecker()

		// CA certificate with excluded DNS constraint
		caCert := &x509.Certificate{
			ExcludedDNSDomains: []string{"excluded.com"},
		}
		nc.ProcessCertificate(caCert)

		// Should accept non-excluded
		goodCert := &x509.Certificate{
			DNSNames: []string{"allowed.com"},
		}
		result := nc.ValidateCertificate(goodCert)
		if !result.IsValid() {
			t.Errorf("should accept non-excluded DNS: %s", result.ErrorMessage())
		}

		// Should reject excluded
		badCert := &x509.Certificate{
			DNSNames: []string{"sub.excluded.com"},
		}
		result = nc.ValidateCertificate(badCert)
		if result.IsValid() {
			t.Error("should reject excluded DNS")
		}
	})
}

func TestNameConstraintCheckerValidateChain(t *testing.T) {
	t.Run("valid chain", func(t *testing.T) {
		nc := NewNameConstraintChecker()

		// Create a simple chain: root -> intermediate -> end-entity
		root := &x509.Certificate{
			PermittedDNSDomains: []string{"example.com"},
		}
		intermediate := &x509.Certificate{
			PermittedDNSDomains: []string{"sub.example.com"},
		}
		endEntity := &x509.Certificate{
			DNSNames: []string{"host.sub.example.com"},
		}

		chain := []*x509.Certificate{endEntity, intermediate, root}
		result := nc.ValidateChain(chain)
		if !result.IsValid() {
			t.Errorf("should validate chain: %s", result.ErrorMessage())
		}
	})

	t.Run("invalid chain", func(t *testing.T) {
		nc := NewNameConstraintChecker()

		// Create a chain where end-entity violates constraints
		root := &x509.Certificate{
			PermittedDNSDomains: []string{"example.com"},
		}
		endEntity := &x509.Certificate{
			DNSNames: []string{"other.com"}, // Violates constraint
		}

		chain := []*x509.Certificate{endEntity, root}
		result := nc.ValidateChain(chain)
		if result.IsValid() {
			t.Error("should reject chain with constraint violation")
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		nc := NewNameConstraintChecker()
		chain := []*x509.Certificate{}
		result := nc.ValidateChain(chain)
		if !result.IsValid() {
			t.Error("empty chain should be valid")
		}
	})
}

func TestDefaultSubtrees(t *testing.T) {
	t.Run("default permitted", func(t *testing.T) {
		ps := DefaultPermittedSubtrees()
		if len(ps) == 0 {
			t.Error("should have entries for all name types")
		}
		for nameType := GeneralNameOtherName; nameType <= GeneralNameRegisteredID; nameType++ {
			if _, ok := ps[nameType]; !ok {
				t.Errorf("missing entry for %v", nameType)
			}
		}
	})

	t.Run("default excluded", func(t *testing.T) {
		es := DefaultExcludedSubtrees()
		if len(es) == 0 {
			t.Error("should have entries for all name types")
		}
		for nameType := GeneralNameOtherName; nameType <= GeneralNameRegisteredID; nameType++ {
			if subtrees, ok := es[nameType]; !ok {
				t.Errorf("missing entry for %v", nameType)
			} else if len(subtrees) != 0 {
				t.Errorf("excluded subtrees should be empty for %v", nameType)
			}
		}
	})
}

func TestRdnEqual(t *testing.T) {
	countryOID := asn1.ObjectIdentifier{2, 5, 4, 6}
	orgOID := asn1.ObjectIdentifier{2, 5, 4, 10}

	tests := []struct {
		name string
		a    pkix.AttributeTypeAndValue
		b    pkix.AttributeTypeAndValue
		want bool
	}{
		{
			name: "equal strings",
			a:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "US"},
			b:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "US"},
			want: true,
		},
		{
			name: "case insensitive",
			a:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "US"},
			b:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "us"},
			want: true,
		},
		{
			name: "different types",
			a:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "US"},
			b:    pkix.AttributeTypeAndValue{Type: orgOID, Value: "US"},
			want: false,
		},
		{
			name: "different values",
			a:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "US"},
			b:    pkix.AttributeTypeAndValue{Type: countryOID, Value: "UK"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rdnEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("rdnEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDirectoryNameConstraints(t *testing.T) {
	t.Run("directory name in permitted subtrees", func(t *testing.T) {
		baseName := pkix.Name{}
		baseName.Names = []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
		}

		initial := map[GeneralNameType][]*NameSubtree{
			GeneralNameDirectoryName: {NewNameSubtree(GeneralNameDirectoryName, baseName)},
		}
		ps := NewPermittedSubtrees(initial)

		matchingName := pkix.Name{}
		matchingName.Names = []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "IT"},
		}

		if !ps.AcceptName(GeneralNameDirectoryName, matchingName) {
			t.Error("should accept directory name with matching prefix")
		}

		nonMatchingName := pkix.Name{}
		nonMatchingName.Names = []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "UK"},
		}

		if ps.AcceptName(GeneralNameDirectoryName, nonMatchingName) {
			t.Error("should reject directory name with non-matching prefix")
		}
	})
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
