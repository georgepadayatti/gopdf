package etsi

import (
	"encoding/xml"
	"testing"
	"time"
)

func TestTS119612Namespace(t *testing.T) {
	expected := "http://uri.etsi.org/02231/v2#"
	if TS119612Namespace != expected {
		t.Errorf("TS119612Namespace = %q, want %q", TS119612Namespace, expected)
	}
}

func TestNewTrustServiceStatusList(t *testing.T) {
	tsl := NewTrustServiceStatusList()
	if tsl == nil {
		t.Fatal("NewTrustServiceStatusList() returned nil")
	}
}

func TestTrustServiceStatusListMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nextUpdate := now.Add(24 * time.Hour)

	tsl := &TrustServiceStatusList{
		TrustStatusListType: TrustStatusListType{
			TSLTag: "http://uri.etsi.org/19612/TSLTag",
			ID:     "tsl-1",
			SchemeInformation: &SchemeInformation{
				TSLSchemeInformationType: TSLSchemeInformationType{
					TSLVersionIdentifier: 5,
					TSLSequenceNumber:    1,
					TSLType: &TSLType{
						Value: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
					},
					SchemeOperatorName: &SchemeOperatorName{
						InternationalNamesType: InternationalNamesType{
							Name: []MultiLangNormStringType{
								{Value: "Test Operator", Lang: "en"},
							},
						},
					},
					SchemeName: &SchemeName{
						InternationalNamesType: InternationalNamesType{
							Name: []MultiLangNormStringType{
								{Value: "Test Scheme", Lang: "en"},
							},
						},
					},
					SchemeInformationURI: &SchemeInformationURI{
						NonEmptyMultiLangURIListType: NonEmptyMultiLangURIListType{
							URI: []NonEmptyMultiLangURIType{
								{Value: "https://example.com/tsl", Lang: "en"},
							},
						},
					},
					StatusDeterminationApproach:    "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/StatusDetn/EUappropriate",
					HistoricalInformationPeriod:    65535,
					ListIssueDateTime:              &now,
					NextUpdate: &NextUpdate{
						NextUpdateType: NextUpdateType{
							DateTime: &nextUpdate,
						},
					},
				},
			},
		},
	}

	data, err := xml.MarshalIndent(tsl, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	var parsed TrustServiceStatusList
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.TSLTag != "http://uri.etsi.org/19612/TSLTag" {
		t.Errorf("TSLTag = %q, want expected value", parsed.TSLTag)
	}
	if parsed.SchemeInformation == nil {
		t.Fatal("SchemeInformation should not be nil")
	}
	if parsed.SchemeInformation.TSLVersionIdentifier != 5 {
		t.Errorf("TSLVersionIdentifier = %d, want 5", parsed.SchemeInformation.TSLVersionIdentifier)
	}
}

func TestGetServicesByType(t *testing.T) {
	tsl := createTestTSL()

	services := tsl.GetServicesByType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
	if len(services) != 1 {
		t.Errorf("expected 1 service, got %d", len(services))
	}

	services = tsl.GetServicesByType("http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST")
	if len(services) != 1 {
		t.Errorf("expected 1 TSA service, got %d", len(services))
	}

	services = tsl.GetServicesByType("nonexistent")
	if len(services) != 0 {
		t.Errorf("expected 0 services for nonexistent type, got %d", len(services))
	}
}

func TestGetServicesByStatus(t *testing.T) {
	tsl := createTestTSL()

	services := tsl.GetServicesByStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
	if len(services) != 2 {
		t.Errorf("expected 2 granted services, got %d", len(services))
	}

	services = tsl.GetServicesByStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn")
	if len(services) != 0 {
		t.Errorf("expected 0 withdrawn services, got %d", len(services))
	}
}

func createTestTSL() *TrustServiceStatusList {
	now := time.Now().UTC()
	return &TrustServiceStatusList{
		TrustStatusListType: TrustStatusListType{
			TSLTag: "http://uri.etsi.org/19612/TSLTag",
			TrustServiceProviderList: &TrustServiceProviderList{
				TrustServiceProviderListType: TrustServiceProviderListType{
					TrustServiceProvider: []TrustServiceProvider{
						{
							TSPType: TSPType{
								TSPInformation: &TSPInformation{
									TSPInformationType: TSPInformationType{
										TSPName: &InternationalNamesType{
											Name: []MultiLangNormStringType{
												{Value: "Test TSP", Lang: "en"},
											},
										},
									},
								},
								TSPServices: &TSPServices{
									TSPServicesListType: TSPServicesListType{
										TSPService: []TSPService{
											{
												TSPServiceType: TSPServiceType{
													ServiceInformation: &ServiceInformation{
														TSPServiceInformationType: TSPServiceInformationType{
															ServiceTypeIdentifier: &ServiceTypeIdentifier{
																Value: "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
															},
															ServiceStatus: &ServiceStatus{
																Value: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
															},
															StatusStartingTime: &now,
														},
													},
												},
											},
											{
												TSPServiceType: TSPServiceType{
													ServiceInformation: &ServiceInformation{
														TSPServiceInformationType: TSPServiceInformationType{
															ServiceTypeIdentifier: &ServiceTypeIdentifier{
																Value: "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
															},
															ServiceStatus: &ServiceStatus{
																Value: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
															},
															StatusStartingTime: &now,
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestPostalAddressMarshal(t *testing.T) {
	pa := PostalAddress{
		PostalAddressType: PostalAddressType{
			StreetAddress: "123 Main St",
			Locality:      "Berlin",
			PostalCode:    "10115",
			CountryName:   "DE",
			Lang:          "en",
		},
	}

	data, err := xml.Marshal(pa)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed PostalAddress
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.StreetAddress != "123 Main St" {
		t.Error("StreetAddress mismatch")
	}
	if parsed.Locality != "Berlin" {
		t.Error("Locality mismatch")
	}
	if parsed.CountryName != "DE" {
		t.Error("CountryName mismatch")
	}
}

func TestDigitalIdentityTypeMarshal(t *testing.T) {
	cert := []byte("test-certificate-data")
	di := DigitalIdentityType{
		X509Certificate: cert,
		X509SubjectName: "CN=Test,O=Test Org",
	}

	data, err := xml.Marshal(di)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed DigitalIdentityType
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.X509SubjectName != "CN=Test,O=Test Org" {
		t.Error("X509SubjectName mismatch")
	}
}

func TestExtensionMarshal(t *testing.T) {
	ext := Extension{
		ExtensionType: ExtensionType{
			Critical: true,
			TSLAnyType: TSLAnyType{
				Content: []byte("<CustomExtension>value</CustomExtension>"),
			},
		},
	}

	data, err := xml.Marshal(ext)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Extension
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !parsed.Critical {
		t.Error("Critical should be true")
	}
}

func TestOtherTSLPointerMarshal(t *testing.T) {
	ptr := OtherTSLPointer{
		OtherTSLPointerType: OtherTSLPointerType{
			TSLLocation: "https://example.com/other-tsl.xml",
			AdditionalInformation: &AdditionalInformation{
				AdditionalInformationType: AdditionalInformationType{
					TextualInformation: []MultiLangStringType{
						{Value: "Additional info", Lang: "en"},
					},
				},
			},
		},
	}

	data, err := xml.Marshal(ptr)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed OtherTSLPointer
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.TSLLocation != "https://example.com/other-tsl.xml" {
		t.Error("TSLLocation mismatch")
	}
	if parsed.AdditionalInformation == nil {
		t.Fatal("AdditionalInformation should not be nil")
	}
}

func TestServiceHistoryMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sh := ServiceHistory{
		ServiceHistoryType: ServiceHistoryType{
			ServiceHistoryInstance: []ServiceHistoryInstance{
				{
					ServiceHistoryInstanceType: ServiceHistoryInstanceType{
						ServiceTypeIdentifier: &ServiceTypeIdentifier{
							Value: "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
						},
						ServiceStatus: &ServiceStatus{
							Value: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
						},
						StatusStartingTime: &now,
					},
				},
			},
		},
	}

	data, err := xml.Marshal(sh)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed ServiceHistory
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.ServiceHistoryInstance) != 1 {
		t.Errorf("expected 1 history instance, got %d", len(parsed.ServiceHistoryInstance))
	}
}

func TestSchemeOperatorNameMarshal(t *testing.T) {
	son := SchemeOperatorName{
		InternationalNamesType: InternationalNamesType{
			Name: []MultiLangNormStringType{
				{Value: "Operator EN", Lang: "en"},
				{Value: "Operator DE", Lang: "de"},
			},
		},
	}

	data, err := xml.Marshal(son)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed SchemeOperatorName
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(parsed.Name) != 2 {
		t.Errorf("expected 2 names, got %d", len(parsed.Name))
	}
}
