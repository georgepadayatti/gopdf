// Package dss provides Document Security Store (DSS) support for PAdES.
package dss

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/georgepadayatti/gopdf/pdf/generic"
)

// Common errors
var (
	ErrNoDSS                = errors.New("no DSS found in document")
	ErrInvalidDSS           = errors.New("invalid DSS structure")
	ErrCertNotFound         = errors.New("certificate not found in DSS")
	ErrOCSPResponseNotFound = errors.New("OCSP response not found in DSS")
	ErrCRLNotFound          = errors.New("CRL not found in DSS")
)

// DSS represents a Document Security Store.
type DSS struct {
	// Certs contains all certificates in the DSS.
	Certs []*x509.Certificate

	// OCSPs contains all OCSP responses.
	OCSPs [][]byte

	// CRLs contains all CRLs.
	CRLs [][]byte

	// VRI contains Validation Related Information.
	VRI map[string]*VRIEntry
}

// VRIEntry represents Validation Related Information for a signature.
type VRIEntry struct {
	// SignatureHash is the hash of the signature (used as key).
	SignatureHash string

	// Certs contains certificates for this signature.
	Certs []*x509.Certificate

	// OCSPs contains OCSP responses for this signature.
	OCSPs [][]byte

	// CRLs contains CRLs for this signature.
	CRLs [][]byte

	// Timestamp is when this VRI entry was created.
	Timestamp *time.Time
}

// NewDSS creates a new empty DSS.
func NewDSS() *DSS {
	return &DSS{
		Certs: []*x509.Certificate{},
		OCSPs: [][]byte{},
		CRLs:  [][]byte{},
		VRI:   make(map[string]*VRIEntry),
	}
}

// AddCertificate adds a certificate to the DSS.
func (d *DSS) AddCertificate(cert *x509.Certificate) {
	// Check if certificate already exists
	for _, existing := range d.Certs {
		if certsEqual(existing, cert) {
			return
		}
	}
	d.Certs = append(d.Certs, cert)
}

// AddCertificates adds multiple certificates.
func (d *DSS) AddCertificates(certs []*x509.Certificate) {
	for _, cert := range certs {
		d.AddCertificate(cert)
	}
}

// AddOCSPResponse adds an OCSP response to the DSS.
func (d *DSS) AddOCSPResponse(ocspResp []byte) {
	// Check if response already exists
	for _, existing := range d.OCSPs {
		if bytesEqual(existing, ocspResp) {
			return
		}
	}
	d.OCSPs = append(d.OCSPs, ocspResp)
}

// AddCRL adds a CRL to the DSS.
func (d *DSS) AddCRL(crl []byte) {
	// Check if CRL already exists
	for _, existing := range d.CRLs {
		if bytesEqual(existing, crl) {
			return
		}
	}
	d.CRLs = append(d.CRLs, crl)
}

// GetVRI gets or creates a VRI entry for a signature.
func (d *DSS) GetVRI(sigHash string) *VRIEntry {
	if vri, ok := d.VRI[sigHash]; ok {
		return vri
	}
	vri := &VRIEntry{
		SignatureHash: sigHash,
		Certs:         []*x509.Certificate{},
		OCSPs:         [][]byte{},
		CRLs:          [][]byte{},
	}
	d.VRI[sigHash] = vri
	return vri
}

// AddVRICert adds a certificate to a VRI entry.
func (d *DSS) AddVRICert(sigHash string, cert *x509.Certificate) {
	vri := d.GetVRI(sigHash)
	for _, existing := range vri.Certs {
		if certsEqual(existing, cert) {
			return
		}
	}
	vri.Certs = append(vri.Certs, cert)
	d.AddCertificate(cert) // Also add to main certs
}

// AddVRIOCSP adds an OCSP response to a VRI entry.
func (d *DSS) AddVRIOCSP(sigHash string, ocspResp []byte) {
	vri := d.GetVRI(sigHash)
	for _, existing := range vri.OCSPs {
		if bytesEqual(existing, ocspResp) {
			return
		}
	}
	vri.OCSPs = append(vri.OCSPs, ocspResp)
	d.AddOCSPResponse(ocspResp) // Also add to main OCSPs
}

// AddVRICRL adds a CRL to a VRI entry.
func (d *DSS) AddVRICRL(sigHash string, crl []byte) {
	vri := d.GetVRI(sigHash)
	for _, existing := range vri.CRLs {
		if bytesEqual(existing, crl) {
			return
		}
	}
	vri.CRLs = append(vri.CRLs, crl)
	d.AddCRL(crl) // Also add to main CRLs
}

// ComputeSignatureHash computes the hash used for VRI keys.
func ComputeSignatureHash(signature []byte) string {
	hash := sha256.Sum256(signature)
	return hex.EncodeToString(hash[:])
}

// ToPdfObject converts the DSS to a PDF dictionary.
func (d *DSS) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()
	dict.Set("Type", generic.NameObject("DSS"))

	// Add Certs array
	if len(d.Certs) > 0 {
		certs := make(generic.ArrayObject, len(d.Certs))
		for i, cert := range d.Certs {
			// Create stream for certificate
			certStream := &generic.StreamObject{
				Dictionary: generic.NewDictionary(),
				Data:       cert.Raw,
			}
			certs[i] = certStream
		}
		dict.Set("Certs", certs)
	}

	// Add OCSPs array
	if len(d.OCSPs) > 0 {
		ocsps := make(generic.ArrayObject, len(d.OCSPs))
		for i, ocsp := range d.OCSPs {
			ocspStream := &generic.StreamObject{
				Dictionary: generic.NewDictionary(),
				Data:       ocsp,
			}
			ocsps[i] = ocspStream
		}
		dict.Set("OCSPs", ocsps)
	}

	// Add CRLs array
	if len(d.CRLs) > 0 {
		crls := make(generic.ArrayObject, len(d.CRLs))
		for i, crl := range d.CRLs {
			crlStream := &generic.StreamObject{
				Dictionary: generic.NewDictionary(),
				Data:       crl,
			}
			crls[i] = crlStream
		}
		dict.Set("CRLs", crls)
	}

	// Add VRI dictionary
	if len(d.VRI) > 0 {
		vriDict := generic.NewDictionary()
		for hash, vri := range d.VRI {
			vriEntry := vri.ToPdfObject()
			vriDict.Set(hash, vriEntry)
		}
		dict.Set("VRI", vriDict)
	}

	return dict
}

// ToPdfObject converts a VRI entry to a PDF dictionary.
func (v *VRIEntry) ToPdfObject() *generic.DictionaryObject {
	dict := generic.NewDictionary()

	// Add Cert array
	if len(v.Certs) > 0 {
		certs := make(generic.ArrayObject, len(v.Certs))
		for i, cert := range v.Certs {
			certStream := &generic.StreamObject{
				Dictionary: generic.NewDictionary(),
				Data:       cert.Raw,
			}
			certs[i] = certStream
		}
		dict.Set("Cert", certs)
	}

	// Add OCSP array
	if len(v.OCSPs) > 0 {
		ocsps := make(generic.ArrayObject, len(v.OCSPs))
		for i, ocsp := range v.OCSPs {
			ocspStream := &generic.StreamObject{
				Dictionary: generic.NewDictionary(),
				Data:       ocsp,
			}
			ocsps[i] = ocspStream
		}
		dict.Set("OCSP", ocsps)
	}

	// Add CRL array
	if len(v.CRLs) > 0 {
		crls := make(generic.ArrayObject, len(v.CRLs))
		for i, crl := range v.CRLs {
			crlStream := &generic.StreamObject{
				Dictionary: generic.NewDictionary(),
				Data:       crl,
			}
			crls[i] = crlStream
		}
		dict.Set("CRL", crls)
	}

	// Add TU (timestamp of update) if present
	if v.Timestamp != nil {
		dict.Set("TU", generic.NewLiteralString(v.Timestamp.Format(time.RFC3339)))
	}

	return dict
}

// ParseDSS parses a DSS from a PDF dictionary.
func ParseDSS(dict *generic.DictionaryObject) (*DSS, error) {
	if dict == nil {
		return nil, ErrNoDSS
	}

	dss := NewDSS()

	// Parse Certs
	if certsObj := dict.Get("Certs"); certsObj != nil {
		if certsArr, ok := certsObj.(generic.ArrayObject); ok {
			for _, certObj := range certsArr {
				if certStream, ok := certObj.(*generic.StreamObject); ok {
					cert, err := x509.ParseCertificate(certStream.Data)
					if err == nil {
						dss.Certs = append(dss.Certs, cert)
					}
				}
			}
		}
	}

	// Parse OCSPs
	if ocspsObj := dict.Get("OCSPs"); ocspsObj != nil {
		if ocspsArr, ok := ocspsObj.(generic.ArrayObject); ok {
			for _, ocspObj := range ocspsArr {
				if ocspStream, ok := ocspObj.(*generic.StreamObject); ok {
					dss.OCSPs = append(dss.OCSPs, ocspStream.Data)
				}
			}
		}
	}

	// Parse CRLs
	if crlsObj := dict.Get("CRLs"); crlsObj != nil {
		if crlsArr, ok := crlsObj.(generic.ArrayObject); ok {
			for _, crlObj := range crlsArr {
				if crlStream, ok := crlObj.(*generic.StreamObject); ok {
					dss.CRLs = append(dss.CRLs, crlStream.Data)
				}
			}
		}
	}

	// Parse VRI
	if vriObj := dict.Get("VRI"); vriObj != nil {
		if vriDict, ok := vriObj.(*generic.DictionaryObject); ok {
			for _, hash := range vriDict.Keys() {
				if vriEntryObj := vriDict.Get(hash); vriEntryObj != nil {
					if vriEntryDict, ok := vriEntryObj.(*generic.DictionaryObject); ok {
						vri, err := ParseVRIEntry(hash, vriEntryDict)
						if err == nil {
							dss.VRI[hash] = vri
						}
					}
				}
			}
		}
	}

	return dss, nil
}

// ParseVRIEntry parses a VRI entry from a PDF dictionary.
func ParseVRIEntry(hash string, dict *generic.DictionaryObject) (*VRIEntry, error) {
	vri := &VRIEntry{
		SignatureHash: hash,
		Certs:         []*x509.Certificate{},
		OCSPs:         [][]byte{},
		CRLs:          [][]byte{},
	}

	// Parse Cert
	if certObj := dict.Get("Cert"); certObj != nil {
		if certArr, ok := certObj.(generic.ArrayObject); ok {
			for _, certStreamObj := range certArr {
				if certStream, ok := certStreamObj.(*generic.StreamObject); ok {
					cert, err := x509.ParseCertificate(certStream.Data)
					if err == nil {
						vri.Certs = append(vri.Certs, cert)
					}
				}
			}
		}
	}

	// Parse OCSP
	if ocspObj := dict.Get("OCSP"); ocspObj != nil {
		if ocspArr, ok := ocspObj.(generic.ArrayObject); ok {
			for _, ocspStreamObj := range ocspArr {
				if ocspStream, ok := ocspStreamObj.(*generic.StreamObject); ok {
					vri.OCSPs = append(vri.OCSPs, ocspStream.Data)
				}
			}
		}
	}

	// Parse CRL
	if crlObj := dict.Get("CRL"); crlObj != nil {
		if crlArr, ok := crlObj.(generic.ArrayObject); ok {
			for _, crlStreamObj := range crlArr {
				if crlStream, ok := crlStreamObj.(*generic.StreamObject); ok {
					vri.CRLs = append(vri.CRLs, crlStream.Data)
				}
			}
		}
	}

	// Parse TU
	if tuObj := dict.Get("TU"); tuObj != nil {
		if tuStr, ok := tuObj.(*generic.StringObject); ok {
			if t, err := time.Parse(time.RFC3339, string(tuStr.Value)); err == nil {
				vri.Timestamp = &t
			}
		}
	}

	return vri, nil
}

// FindCertBySubject finds a certificate by subject name.
func (d *DSS) FindCertBySubject(subject string) *x509.Certificate {
	for _, cert := range d.Certs {
		if cert.Subject.CommonName == subject || cert.Subject.String() == subject {
			return cert
		}
	}
	return nil
}

// FindCertByIssuerSerial finds a certificate by issuer and serial.
func (d *DSS) FindCertByIssuerSerial(issuer string, serial []byte) *x509.Certificate {
	for _, cert := range d.Certs {
		if (cert.Issuer.CommonName == issuer || cert.Issuer.String() == issuer) &&
			bytesEqual(cert.SerialNumber.Bytes(), serial) {
			return cert
		}
	}
	return nil
}

// Merge merges another DSS into this one.
func (d *DSS) Merge(other *DSS) {
	d.AddCertificates(other.Certs)
	for _, ocsp := range other.OCSPs {
		d.AddOCSPResponse(ocsp)
	}
	for _, crl := range other.CRLs {
		d.AddCRL(crl)
	}
	for hash, vri := range other.VRI {
		d.VRI[hash] = vri
	}
}

// IsEmpty returns true if the DSS contains no data.
func (d *DSS) IsEmpty() bool {
	return len(d.Certs) == 0 && len(d.OCSPs) == 0 && len(d.CRLs) == 0 && len(d.VRI) == 0
}

// Summary returns a summary of the DSS contents.
func (d *DSS) Summary() string {
	return fmt.Sprintf("DSS: %d certs, %d OCSPs, %d CRLs, %d VRI entries",
		len(d.Certs), len(d.OCSPs), len(d.CRLs), len(d.VRI))
}

// Helper functions

func certsEqual(a, b *x509.Certificate) bool {
	return bytesEqual(a.Raw, b.Raw)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
