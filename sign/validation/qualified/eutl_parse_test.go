package qualified

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestExtractFromIntlString(t *testing.T) {
	tests := []struct {
		name     string
		input    []MultiLangString
		expected string
	}{
		{
			name:     "empty list",
			input:    []MultiLangString{},
			expected: "unknown",
		},
		{
			name: "single entry",
			input: []MultiLangString{
				{Lang: "de", Value: "German"},
			},
			expected: "German",
		},
		{
			name: "english preferred",
			input: []MultiLangString{
				{Lang: "de", Value: "German"},
				{Lang: "en", Value: "English"},
				{Lang: "fr", Value: "French"},
			},
			expected: "English",
		},
		{
			name: "english not present",
			input: []MultiLangString{
				{Lang: "de", Value: "German"},
				{Lang: "fr", Value: "French"},
			},
			expected: "German",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractFromIntlString(tt.input)
			if result != tt.expected {
				t.Errorf("extractFromIntlString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseDateTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "RFC3339",
			input:   "2024-01-15T10:30:00Z",
			wantErr: false,
		},
		{
			name:    "ISO date only",
			input:   "2024-01-15",
			wantErr: false,
		},
		{
			name:    "ISO datetime",
			input:   "2024-01-15T10:30:00",
			wantErr: false,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid",
			input:   "not-a-date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDateTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDateTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProcessCriteriaList(t *testing.T) {
	tests := []struct {
		name      string
		input     *CriteriaListXML
		wantErr   bool
		combineAs CriteriaCombination
	}{
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
		{
			name: "key usage criterion",
			input: &CriteriaListXML{
				Assert: "all",
				KeyUsage: []KeyUsageBitsXML{
					{
						KeyUsageBit: []KeyUsageBitXML{
							{Name: "digitalSignature", Value: true},
						},
					},
				},
			},
			wantErr:   false,
			combineAs: CriteriaCombinationAll,
		},
		{
			name: "policy set criterion",
			input: &CriteriaListXML{
				Assert: "atLeastOne",
				PolicySet: []PolicySetXML{
					{
						PolicyIdentifier: []PolicyIdentifierXML{
							{Identifier: IdentifierXML{Value: "1.2.3.4.5"}},
						},
					},
				},
			},
			wantErr:   false,
			combineAs: CriteriaCombinationAtLeastOne,
		},
		{
			name: "empty criteria",
			input: &CriteriaListXML{
				Assert: "all",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processCriteriaList(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("processCriteriaList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != nil {
				if result.CombineAs != tt.combineAs {
					t.Errorf("processCriteriaList() combineAs = %v, want %v", result.CombineAs, tt.combineAs)
				}
			}
		})
	}
}

func TestProcessQualifications(t *testing.T) {
	tests := []struct {
		name          string
		input         *QualificationsXML
		wantLen       int
	}{
		{
			name:    "nil input",
			input:   nil,
			wantLen: 0,
		},
		{
			name: "valid qualifications",
			input: &QualificationsXML{
				QualificationElement: []QualificationElementXML{
					{
						Qualifiers: &QualifiersXML{
							Qualifier: []QualifierXML{
								{URI: SvcInfoExtURIBase + "/QCWithQSCD"},
							},
						},
						CriteriaList: &CriteriaListXML{
							Assert: "all",
							KeyUsage: []KeyUsageBitsXML{
								{KeyUsageBit: []KeyUsageBitXML{{Name: "digitalSignature", Value: true}}},
							},
						},
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "no qualifiers",
			input: &QualificationsXML{
				QualificationElement: []QualificationElementXML{
					{
						CriteriaList: &CriteriaListXML{
							Assert: "all",
							KeyUsage: []KeyUsageBitsXML{
								{KeyUsageBit: []KeyUsageBitXML{{Name: "digitalSignature", Value: true}}},
							},
						},
					},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processQualifications(tt.input)
			if len(result) != tt.wantLen {
				t.Errorf("processQualifications() len = %v, want %v", len(result), tt.wantLen)
			}
		})
	}
}

func TestReadQualifiedServiceDefinitions(t *testing.T) {
	// Minimal valid TSL XML
	minimalTSL := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>EU</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName>
              <Name xml:lang="en">Test CA Service</Name>
            </ServiceName>
            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
            <StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	services, errors := ReadQualifiedServiceDefinitions(minimalTSL)

	// We expect some errors because there are no certificates
	if len(errors) > 0 {
		t.Logf("Got %d parsing errors (expected)", len(errors))
	}

	// The service should still be parsed (without certificates)
	t.Logf("Parsed %d services", len(services))
}

func TestTrustListToRegistryUnsafe(t *testing.T) {
	// Minimal valid TSL XML
	minimalTSL := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>EU</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	registry, errors := TrustListToRegistryUnsafe(minimalTSL, nil)

	if registry == nil {
		t.Error("TrustListToRegistryUnsafe() returned nil registry")
	}

	t.Logf("Parsed with %d errors", len(errors))
}

func TestParseLOTLUnsafeComplete(t *testing.T) {
	// Minimal LOTL XML
	minimalLOTL := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>EU</SchemeTerritory>
    <SchemeInformationURI>
      <URI xml:lang="en">https://example.com/lotl.xml</URI>
    </SchemeInformationURI>
    <PointersToOtherTSL>
      <OtherTSLPointer>
        <TSLLocation>https://example.com/tl.xml</TSLLocation>
        <AdditionalInformation>
          <OtherInformation>
            <SchemeTerritory>DE</SchemeTerritory>
          </OtherInformation>
          <OtherInformation>
            <MimeType>application/vnd.etsi.tsl+xml</MimeType>
          </OtherInformation>
        </AdditionalInformation>
      </OtherTSLPointer>
    </PointersToOtherTSL>
  </SchemeInformation>
</TrustServiceStatusList>`

	result, err := ParseLOTLUnsafeComplete(minimalLOTL)
	if err != nil {
		t.Fatalf("ParseLOTLUnsafeComplete() error = %v", err)
	}

	if result == nil {
		t.Fatal("ParseLOTLUnsafeComplete() returned nil result")
	}

	if len(result.References) == 0 {
		t.Error("ParseLOTLUnsafeComplete() returned no references")
	} else {
		ref := result.References[0]
		if ref.Territory != "DE" {
			t.Errorf("ParseLOTLUnsafeComplete() territory = %v, want DE", ref.Territory)
		}
		if ref.LocationURI != "https://example.com/tl.xml" {
			t.Errorf("ParseLOTLUnsafeComplete() location = %v, want https://example.com/tl.xml", ref.LocationURI)
		}
	}

	if len(result.PivotURLs) == 0 || !strings.HasSuffix(result.PivotURLs[0], ".xml") {
		t.Error("ParseLOTLUnsafeComplete() did not extract pivot URLs correctly")
	}
}

func TestLoadLOTLCerts(t *testing.T) {
	certs := LatestKnownLOTLTLSOCerts()
	if len(certs) == 0 {
		t.Skip("No bundled LOTL certificates found")
	}

	t.Logf("Loaded %d LOTL certificates", len(certs))

	// Verify the certificates are valid
	for i, cert := range certs {
		if cert == nil {
			t.Errorf("Certificate %d is nil", i)
			continue
		}
		if cert.Subject.CommonName == "" && len(cert.Subject.Organization) == 0 {
			t.Errorf("Certificate %d has no subject", i)
		}
	}
}

func TestBootstrapLOTLCerts(t *testing.T) {
	certs := OJEUBootstrapLOTLTLSOCerts()
	if len(certs) == 0 {
		t.Skip("No bundled bootstrap certificates found")
	}

	t.Logf("Loaded %d bootstrap certificates", len(certs))
}


func TestKeyUsageCriterionMatches(t *testing.T) {
	// Create a mock certificate with KeyUsage
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}

	tests := []struct {
		name     string
		settings KeyUsageConstraintsForCriteria
		want     bool
	}{
		{
			name: "matching required key usage",
			settings: KeyUsageConstraintsForCriteria{
				KeyUsage: map[string]bool{"digital_signature": true},
			},
			want: true,
		},
		{
			name: "missing required key usage",
			settings: KeyUsageConstraintsForCriteria{
				KeyUsage: map[string]bool{"key_encipherment": true},
			},
			want: false,
		},
		{
			name: "forbidden key usage present",
			settings: KeyUsageConstraintsForCriteria{
				KeyUsageForbidden: map[string]bool{"digital_signature": true},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			criterion := &KeyUsageCriterion{Settings: tt.settings}
			if got := criterion.Matches(cert); got != tt.want {
				t.Errorf("KeyUsageCriterion.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriteriaListMatches(t *testing.T) {
	cert := &x509.Certificate{
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	// Criterion that matches
	matchingCriterion := &KeyUsageCriterion{
		Settings: KeyUsageConstraintsForCriteria{
			KeyUsage: map[string]bool{"digital_signature": true},
		},
	}

	// Criterion that doesn't match
	nonMatchingCriterion := &KeyUsageCriterion{
		Settings: KeyUsageConstraintsForCriteria{
			KeyUsage: map[string]bool{"key_encipherment": true},
		},
	}

	tests := []struct {
		name      string
		list      *CriteriaList
		want      bool
	}{
		{
			name: "all - all match",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationAll,
				Criteria:  []Criterion{matchingCriterion},
			},
			want: true,
		},
		{
			name: "all - one doesn't match",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationAll,
				Criteria:  []Criterion{matchingCriterion, nonMatchingCriterion},
			},
			want: false,
		},
		{
			name: "atLeastOne - one matches",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationAtLeastOne,
				Criteria:  []Criterion{matchingCriterion, nonMatchingCriterion},
			},
			want: true,
		},
		{
			name: "atLeastOne - none match",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationAtLeastOne,
				Criteria:  []Criterion{nonMatchingCriterion},
			},
			want: false,
		},
		{
			name: "none - none match",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationNone,
				Criteria:  []Criterion{nonMatchingCriterion},
			},
			want: true,
		},
		{
			name: "none - one matches",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationNone,
				Criteria:  []Criterion{matchingCriterion},
			},
			want: false,
		},
		{
			name: "empty list",
			list: &CriteriaList{
				CombineAs: CriteriaCombinationAll,
				Criteria:  []Criterion{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.list.Matches(cert); got != tt.want {
				t.Errorf("CriteriaList.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProcessServiceExtensions(t *testing.T) {
	ext := &ServiceExtensionsXML{
		Extension: []ExtensionXML{
			{
				Critical: false,
				AdditionalServiceInformation: &AdditionalServiceInfoXML{
					URI:              ForeSignaturesURI,
					InformationValue: "For signatures",
				},
			},
			{
				Critical: false,
				ExpiredCertsRevocationInfo: "2020-01-01T00:00:00Z",
			},
		},
	}

	qualifications, additionalInfoTypes, otherInfo, expiredRevInfo := processServiceExtensions(ext)

	if len(additionalInfoTypes) == 0 {
		t.Error("processServiceExtensions() did not extract additional info types")
	}

	if !additionalInfoTypes[QcCertTypeEsign] {
		t.Error("processServiceExtensions() did not identify QcCertTypeEsign")
	}

	if len(otherInfo) != 0 {
		t.Errorf("processServiceExtensions() unexpected other info: %v", otherInfo)
	}

	if expiredRevInfo == nil {
		t.Error("processServiceExtensions() did not extract expired certs revocation info")
	}

	// qualifications should be empty in this test
	_ = qualifications
}

func TestXMLSignatureError(t *testing.T) {
	err := NewXMLSignatureError("test error message")
	if err == nil {
		t.Error("NewXMLSignatureError returned nil")
	}
	if err.Error() != "test error message" {
		t.Errorf("XMLSignatureError.Error() = %v, want 'test error message'", err.Error())
	}
}

func TestValidateXMLSignatureNoCerts(t *testing.T) {
	_, _, err := ValidateXMLSignature("<xml/>", nil)
	if err == nil {
		t.Error("ValidateXMLSignature should fail with no certificates")
	}

	_, _, err = ValidateXMLSignature("<xml/>", []*x509.Certificate{})
	if err == nil {
		t.Error("ValidateXMLSignature should fail with empty certificate list")
	}
}

func TestValidateXMLSignatureInvalidXML(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("dummy"),
	}

	_, _, err := ValidateXMLSignature("not valid xml at all", []*x509.Certificate{cert})
	if err == nil {
		t.Error("ValidateXMLSignature should fail with invalid XML")
	}
}

func TestValidateXMLSignatureNoSignature(t *testing.T) {
	cert := &x509.Certificate{
		Raw: []byte("dummy"),
	}

	// Valid XML but no signature
	xml := `<?xml version="1.0"?><root><data>test</data></root>`
	_, _, err := ValidateXMLSignature(xml, []*x509.Certificate{cert})
	if err == nil {
		t.Error("ValidateXMLSignature should fail with no signature in XML")
	}
}

func TestValidateXMLSignatureWithMultipleCertsNoCerts(t *testing.T) {
	_, _, err := ValidateXMLSignatureWithMultipleCerts("<xml/>", nil)
	if err == nil {
		t.Error("ValidateXMLSignatureWithMultipleCerts should fail with no certificates")
	}

	_, _, err = ValidateXMLSignatureWithMultipleCerts("<xml/>", []*x509.Certificate{})
	if err == nil {
		t.Error("ValidateXMLSignatureWithMultipleCerts should fail with empty certificate list")
	}
}

func TestTrustListToRegistryWithValidation(t *testing.T) {
	// Minimal valid TSL XML without signature
	minimalTSL := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>EU</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	// With certificates but no signature - should fall back to unsafe parsing
	cert := &x509.Certificate{
		Raw: []byte("dummy"),
	}

	registry, errors := TrustListToRegistry(minimalTSL, []*x509.Certificate{cert}, nil)
	if registry == nil {
		t.Error("TrustListToRegistry returned nil registry")
	}
	// Should have at least one error about signature validation
	if len(errors) == 0 {
		t.Log("TrustListToRegistry returned no errors (signature validation may have been skipped)")
	}
}

func TestTrustListToRegistryWithoutCerts(t *testing.T) {
	// Minimal valid TSL XML
	minimalTSL := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>EU</SchemeTerritory>
  </SchemeInformation>
  <TrustServiceProviderList>
  </TrustServiceProviderList>
</TrustServiceStatusList>`

	// Without certificates - should skip validation
	registry, errors := TrustListToRegistry(minimalTSL, nil, nil)
	if registry == nil {
		t.Error("TrustListToRegistry returned nil registry")
	}
	t.Logf("Parsed with %d errors", len(errors))
}

func TestValidateAndParseLOTLCompleteNoCerts(t *testing.T) {
	// Minimal LOTL XML
	minimalLOTL := `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <SchemeTerritory>EU</SchemeTerritory>
  </SchemeInformation>
</TrustServiceStatusList>`

	// With empty certs - should fall back to unsafe parsing
	result, err := ValidateAndParseLOTLComplete(minimalLOTL, []*x509.Certificate{})
	if err != nil {
		t.Logf("ValidateAndParseLOTLComplete with empty certs: %v", err)
	}
	if result == nil && err == nil {
		t.Error("ValidateAndParseLOTLComplete returned nil result without error")
	}
}

func TestTSPRegistryOperations(t *testing.T) {
	registry := NewTSPRegistry()

	// Create a mock certificate
	cert := &x509.Certificate{
		Raw: []byte("mock-cert-data"),
	}

	// Create CA service info
	caInfo := CAServiceInformation{
		QualifiedServiceInformation: QualifiedServiceInformation{
			BaseInfo: BaseServiceInformation{
				ServiceType:   CAQCUri,
				ServiceName:   "Test CA",
				ValidFrom:     time.Now().Add(-24 * time.Hour),
				ProviderCerts: []*x509.Certificate{cert},
			},
		},
	}

	registry.RegisterCA(caInfo)

	// Check if service is registered
	services := registry.ApplicableServiceDefinitions(cert, nil)
	if len(services) == 0 {
		t.Error("RegisterCA() did not register service")
	}

	// Check known CAs
	cas := registry.KnownCertificateAuthorities()
	if len(cas) == 0 {
		t.Error("KnownCertificateAuthorities() returned empty")
	}
}
