// Package signers provides PKCS#11 signing support for PDF documents.
//
// PKCS#11 is a standard API for accessing cryptographic hardware tokens (HSMs,
// smart cards, etc.). This implementation uses the github.com/miekg/pkcs11 library.
package signers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sync"

	"github.com/georgepadayatti/gopdf/config"
	"github.com/georgepadayatti/gopdf/sign/cms"
	pkcs11 "github.com/miekg/pkcs11"
)

// PKCS#11 related errors
var (
	ErrPKCS11ModuleLoad     = errors.New("failed to load PKCS#11 module")
	ErrPKCS11NoToken        = errors.New("no matching token found")
	ErrPKCS11NoKey          = errors.New("private key not found")
	ErrPKCS11NoCert         = errors.New("certificate not found")
	ErrPKCS11MultipleKeys   = errors.New("multiple private keys found")
	ErrPKCS11MultipleCerts  = errors.New("multiple certificates found")
	ErrPKCS11SessionFailed  = errors.New("failed to open PKCS#11 session")
	ErrPKCS11LoginFailed    = errors.New("PKCS#11 login failed")
	ErrPKCS11SignFailed     = errors.New("PKCS#11 signing failed")
	ErrPKCS11UnsupportedAlg = errors.New("unsupported algorithm for PKCS#11")
)

// PKCS11SignatureOperationSpec describes how to invoke a signature operation.
type PKCS11SignatureOperationSpec struct {
	// Mechanism is the PKCS#11 mechanism to use.
	Mechanism *pkcs11.Mechanism

	// PreSignTransform is an optional transformation before signing.
	PreSignTransform func([]byte) ([]byte, error)

	// PostSignTransform is an optional transformation after signing.
	PostSignTransform func([]byte) ([]byte, error)
}

// Mechanism constants (from PKCS#11 spec)
const (
	CKM_RSA_PKCS            = 0x00000001
	CKM_SHA1_RSA_PKCS       = 0x00000006
	CKM_SHA256_RSA_PKCS     = 0x00000040
	CKM_SHA384_RSA_PKCS     = 0x00000041
	CKM_SHA512_RSA_PKCS     = 0x00000042
	CKM_SHA224_RSA_PKCS     = 0x00000046
	CKM_RSA_PKCS_PSS        = 0x0000000D
	CKM_SHA1_RSA_PKCS_PSS   = 0x0000000E
	CKM_SHA256_RSA_PKCS_PSS = 0x00000043
	CKM_SHA384_RSA_PKCS_PSS = 0x00000044
	CKM_SHA512_RSA_PKCS_PSS = 0x00000045
	CKM_SHA224_RSA_PKCS_PSS = 0x00000047
	CKM_DSA                 = 0x00000011
	CKM_DSA_SHA1            = 0x00000012
	CKM_DSA_SHA224          = 0x00000013
	CKM_DSA_SHA256          = 0x00000014
	CKM_DSA_SHA384          = 0x00000015
	CKM_DSA_SHA512          = 0x00000016
	CKM_ECDSA               = 0x00001041
	CKM_ECDSA_SHA1          = 0x00001042
	CKM_ECDSA_SHA224        = 0x00001043
	CKM_ECDSA_SHA256        = 0x00001044
	CKM_ECDSA_SHA384        = 0x00001045
	CKM_ECDSA_SHA512        = 0x00001046
	CKM_EDDSA               = 0x00001057
	CKM_SHA_1               = 0x00000220
	CKM_SHA224              = 0x00000255
	CKM_SHA256              = 0x00000250
	CKM_SHA384              = 0x00000260
	CKM_SHA512              = 0x00000270
)

// Object class constants
const (
	CKO_CERTIFICATE = 0x00000001
	CKO_PUBLIC_KEY  = 0x00000002
	CKO_PRIVATE_KEY = 0x00000003
)

// Attribute constants
const (
	CKA_CLASS            = 0x00000000
	CKA_TOKEN            = 0x00000001
	CKA_PRIVATE          = 0x00000002
	CKA_LABEL            = 0x00000003
	CKA_VALUE            = 0x00000011
	CKA_CERTIFICATE_TYPE = 0x00000080
	CKA_ID               = 0x00000102
	CKA_SIGN             = 0x00000108
)

// MGF constants for PSS
const (
	CKG_MGF1_SHA1   = 0x00000001
	CKG_MGF1_SHA224 = 0x00000005
	CKG_MGF1_SHA256 = 0x00000002
	CKG_MGF1_SHA384 = 0x00000003
	CKG_MGF1_SHA512 = 0x00000004
)

// RSA mechanism map for different digest algorithms
var rsaMechMap = map[string]uint{
	"sha1":   CKM_SHA1_RSA_PKCS,
	"sha224": CKM_SHA224_RSA_PKCS,
	"sha256": CKM_SHA256_RSA_PKCS,
	"sha384": CKM_SHA384_RSA_PKCS,
	"sha512": CKM_SHA512_RSA_PKCS,
}

// RSA-PSS mechanism map
var rsaPSSMechMap = map[string]uint{
	"sha1":   CKM_SHA1_RSA_PKCS_PSS,
	"sha224": CKM_SHA224_RSA_PKCS_PSS,
	"sha256": CKM_SHA256_RSA_PKCS_PSS,
	"sha384": CKM_SHA384_RSA_PKCS_PSS,
	"sha512": CKM_SHA512_RSA_PKCS_PSS,
}

// ECDSA mechanism map
var ecdsaMechMap = map[string]uint{
	"sha1":   CKM_ECDSA_SHA1,
	"sha224": CKM_ECDSA_SHA224,
	"sha256": CKM_ECDSA_SHA256,
	"sha384": CKM_ECDSA_SHA384,
	"sha512": CKM_ECDSA_SHA512,
}

// DSA mechanism map
var dsaMechMap = map[string]uint{
	"sha1":   CKM_DSA_SHA1,
	"sha224": CKM_DSA_SHA224,
	"sha256": CKM_DSA_SHA256,
	"sha384": CKM_DSA_SHA384,
	"sha512": CKM_DSA_SHA512,
}

// Digest mechanism map
var digestMechMap = map[string]uint{
	"sha1":   CKM_SHA_1,
	"sha224": CKM_SHA224,
	"sha256": CKM_SHA256,
	"sha384": CKM_SHA384,
	"sha512": CKM_SHA512,
}

// MGF mechanism map for PSS
var mgfMechMap = map[string]uint{
	"sha1":   CKG_MGF1_SHA1,
	"sha224": CKG_MGF1_SHA224,
	"sha256": CKG_MGF1_SHA256,
	"sha384": CKG_MGF1_SHA384,
	"sha512": CKG_MGF1_SHA512,
}

// digestAlgSizes maps digest algorithms to their output size
var digestAlgSizes = map[string]int{
	"sha1":   20,
	"sha224": 28,
	"sha256": 32,
	"sha384": 48,
	"sha512": 64,
}

// PKCS11Session wraps a PKCS#11 session.
type PKCS11Session struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	slotID  uint
}

// Close closes the PKCS#11 session.
func (s *PKCS11Session) Close() error {
	if s.ctx == nil {
		return nil
	}
	err := s.ctx.CloseSession(s.session)
	s.ctx.Finalize()
	s.ctx.Destroy()
	return err
}

// PKCS11Signer implements signing using a PKCS#11 token.
type PKCS11Signer struct {
	session     *PKCS11Session
	keyHandle   pkcs11.ObjectHandle
	signingCert *x509.Certificate
	certChain   []*x509.Certificate
	preferPSS   bool
	useRawMech  bool
	signKwargs  map[string]interface{}

	// Configuration
	certLabel string
	certID    []byte
	keyLabel  string
	keyID     []byte

	// Loaded state
	loaded bool
	mu     sync.Mutex
}

// NewPKCS11Signer creates a new PKCS#11 signer.
func NewPKCS11Signer(session *PKCS11Session) *PKCS11Signer {
	return &PKCS11Signer{
		session:    session,
		signKwargs: make(map[string]interface{}),
	}
}

// WithCertLabel sets the certificate label.
func (s *PKCS11Signer) WithCertLabel(label string) *PKCS11Signer {
	s.certLabel = label
	return s
}

// WithCertID sets the certificate ID.
func (s *PKCS11Signer) WithCertID(id []byte) *PKCS11Signer {
	s.certID = id
	return s
}

// WithKeyLabel sets the key label.
func (s *PKCS11Signer) WithKeyLabel(label string) *PKCS11Signer {
	s.keyLabel = label
	return s
}

// WithKeyID sets the key ID.
func (s *PKCS11Signer) WithKeyID(id []byte) *PKCS11Signer {
	s.keyID = id
	return s
}

// WithPreferPSS sets PSS preference.
func (s *PKCS11Signer) WithPreferPSS(prefer bool) *PKCS11Signer {
	s.preferPSS = prefer
	return s
}

// WithRawMechanism sets raw mechanism preference.
func (s *PKCS11Signer) WithRawMechanism(useRaw bool) *PKCS11Signer {
	s.useRawMech = useRaw
	return s
}

// WithSigningCertificate sets a pre-loaded signing certificate.
func (s *PKCS11Signer) WithSigningCertificate(cert *x509.Certificate) *PKCS11Signer {
	s.signingCert = cert
	return s
}

// WithCertificateChain sets the certificate chain.
func (s *PKCS11Signer) WithCertificateChain(chain []*x509.Certificate) *PKCS11Signer {
	s.certChain = chain
	return s
}

// Load loads the key and certificate from the PKCS#11 token.
func (s *PKCS11Signer) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loaded {
		return nil
	}

	// Determine effective labels/IDs
	effectiveKeyLabel := s.keyLabel
	effectiveKeyID := s.keyID
	effectiveCertLabel := s.certLabel
	effectiveCertID := s.certID

	// Default key identifiers from cert if not set
	if effectiveKeyLabel == "" && effectiveKeyID == nil {
		if effectiveCertID != nil {
			effectiveKeyID = effectiveCertID
		} else if effectiveCertLabel != "" {
			effectiveKeyLabel = effectiveCertLabel
		}
	}

	// Default cert identifiers from key if not set and no cert provided
	if s.signingCert == nil {
		if effectiveCertLabel == "" && effectiveCertID == nil {
			if effectiveKeyID != nil {
				effectiveCertID = effectiveKeyID
			} else if effectiveKeyLabel != "" {
				effectiveCertLabel = effectiveKeyLabel
			}
		}
	}

	// Load certificate if not provided
	if s.signingCert == nil {
		cert, err := s.pullCertificate(effectiveCertLabel, effectiveCertID)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		s.signingCert = cert
	}

	// Load key handle
	keyHandle, err := s.pullKeyHandle(effectiveKeyLabel, effectiveKeyID)
	if err != nil {
		return fmt.Errorf("failed to load key: %w", err)
	}
	s.keyHandle = keyHandle

	s.loaded = true
	return nil
}

// pullCertificate fetches a certificate from the token.
func (s *PKCS11Signer) pullCertificate(label string, id []byte) (*x509.Certificate, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_CLASS, CKO_CERTIFICATE),
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(CKA_LABEL, label))
	}
	if id != nil {
		template = append(template, pkcs11.NewAttribute(CKA_ID, id))
	}

	if err := s.session.ctx.FindObjectsInit(s.session.session, template); err != nil {
		return nil, fmt.Errorf("FindObjectsInit failed: %w", err)
	}
	defer s.session.ctx.FindObjectsFinal(s.session.session)

	objs, _, err := s.session.ctx.FindObjects(s.session.session, 10)
	if err != nil {
		return nil, fmt.Errorf("FindObjects failed: %w", err)
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("%w: label=%q, id=%s", ErrPKCS11NoCert, label, hex.EncodeToString(id))
	}
	if len(objs) > 1 {
		return nil, fmt.Errorf("%w: label=%q, id=%s", ErrPKCS11MultipleCerts, label, hex.EncodeToString(id))
	}

	// Get certificate value
	attrs, err := s.session.ctx.GetAttributeValue(s.session.session, objs[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("GetAttributeValue failed: %w", err)
	}

	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("certificate has no value")
	}

	cert, err := x509.ParseCertificate(attrs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// pullKeyHandle fetches a private key handle from the token.
func (s *PKCS11Signer) pullKeyHandle(label string, id []byte) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(CKA_SIGN, true),
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(CKA_LABEL, label))
	}
	if id != nil {
		template = append(template, pkcs11.NewAttribute(CKA_ID, id))
	}

	if err := s.session.ctx.FindObjectsInit(s.session.session, template); err != nil {
		return 0, fmt.Errorf("FindObjectsInit failed: %w", err)
	}
	defer s.session.ctx.FindObjectsFinal(s.session.session)

	objs, _, err := s.session.ctx.FindObjects(s.session.session, 10)
	if err != nil {
		return 0, fmt.Errorf("FindObjects failed: %w", err)
	}

	if len(objs) == 0 {
		return 0, fmt.Errorf("%w: label=%q, id=%s", ErrPKCS11NoKey, label, hex.EncodeToString(id))
	}
	if len(objs) > 1 {
		return 0, fmt.Errorf("%w: label=%q, id=%s", ErrPKCS11MultipleKeys, label, hex.EncodeToString(id))
	}

	return objs[0], nil
}

// PullAllCertificates fetches all certificates from the token.
func (s *PKCS11Signer) PullAllCertificates() ([]*x509.Certificate, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_CLASS, CKO_CERTIFICATE),
	}

	if err := s.session.ctx.FindObjectsInit(s.session.session, template); err != nil {
		return nil, fmt.Errorf("FindObjectsInit failed: %w", err)
	}
	defer s.session.ctx.FindObjectsFinal(s.session.session)

	var certs []*x509.Certificate
	for {
		objs, _, err := s.session.ctx.FindObjects(s.session.session, 10)
		if err != nil {
			return nil, fmt.Errorf("FindObjects failed: %w", err)
		}
		if len(objs) == 0 {
			break
		}

		for _, obj := range objs {
			attrs, err := s.session.ctx.GetAttributeValue(s.session.session, obj, []*pkcs11.Attribute{
				pkcs11.NewAttribute(CKA_VALUE, nil),
			})
			if err != nil {
				continue // Skip certificates we can't read
			}
			if len(attrs) == 0 || len(attrs[0].Value) == 0 {
				continue
			}

			cert, err := x509.ParseCertificate(attrs[0].Value)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

// Sign implements the Signer interface.
func (s *PKCS11Signer) Sign(data []byte) ([]byte, error) {
	if err := s.Load(); err != nil {
		return nil, err
	}

	// First, perform the raw signing through PKCS#11
	signature, err := s.signRaw(data, "sha256")
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 signing failed: %w", err)
	}

	// Build CMS structure with the precomputed signature
	builder := cms.NewCMSBuilder(s.signingCert, nil, s.getSignatureAlgorithm())
	builder.SetCertificateChain(s.certChain)
	builder.SetPrecomputedSignature(signature)

	// Build the CMS signed data
	return builder.Sign(data)
}

// signRaw performs the raw signing operation via PKCS#11.
func (s *PKCS11Signer) signRaw(data []byte, digestAlgorithm string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	spec, err := s.selectSigningParams(digestAlgorithm)
	if err != nil {
		return nil, err
	}

	// Apply pre-sign transform if needed
	if spec.PreSignTransform != nil {
		data, err = spec.PreSignTransform(data)
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform failed: %w", err)
		}
	}

	// Initialize signing
	if err := s.session.ctx.SignInit(s.session.session, []*pkcs11.Mechanism{spec.Mechanism}, s.keyHandle); err != nil {
		return nil, fmt.Errorf("%w: SignInit failed: %v", ErrPKCS11SignFailed, err)
	}

	// Sign
	signature, err := s.session.ctx.Sign(s.session.session, data)
	if err != nil {
		return nil, fmt.Errorf("%w: Sign failed: %v", ErrPKCS11SignFailed, err)
	}

	// Apply post-sign transform if needed
	if spec.PostSignTransform != nil {
		signature, err = spec.PostSignTransform(signature)
		if err != nil {
			return nil, fmt.Errorf("post-sign transform failed: %w", err)
		}
	}

	return signature, nil
}

// selectSigningParams determines the PKCS#11 signing parameters.
func (s *PKCS11Signer) selectSigningParams(digestAlgorithm string) (*PKCS11SignatureOperationSpec, error) {
	spec := &PKCS11SignatureOperationSpec{}

	// Determine key type from certificate
	keyType := s.getKeyType()

	switch keyType {
	case "RSA":
		if s.preferPSS {
			return s.selectRSAPSSParams(digestAlgorithm)
		}
		return s.selectRSAPKCS1Params(digestAlgorithm)
	case "ECDSA":
		return s.selectECDSAParams(digestAlgorithm)
	case "DSA":
		return s.selectDSAParams(digestAlgorithm)
	case "Ed25519", "Ed448":
		return s.selectEdDSAParams(keyType)
	default:
		return nil, fmt.Errorf("%w: %s", ErrPKCS11UnsupportedAlg, keyType)
	}

	return spec, nil
}

// selectRSAPKCS1Params selects RSA PKCS#1 v1.5 signing parameters.
func (s *PKCS11Signer) selectRSAPKCS1Params(digestAlgorithm string) (*PKCS11SignatureOperationSpec, error) {
	spec := &PKCS11SignatureOperationSpec{}

	if s.useRawMech {
		spec.Mechanism = pkcs11.NewMechanism(CKM_RSA_PKCS, nil)
		spec.PreSignTransform = hashFullyWithDigestInfo(digestAlgorithm)
	} else {
		mech, ok := rsaMechMap[digestAlgorithm]
		if !ok {
			return nil, fmt.Errorf("%w: RSA with %s", ErrPKCS11UnsupportedAlg, digestAlgorithm)
		}
		spec.Mechanism = pkcs11.NewMechanism(mech, nil)
	}

	return spec, nil
}

// selectRSAPSSParams selects RSA-PSS signing parameters.
func (s *PKCS11Signer) selectRSAPSSParams(digestAlgorithm string) (*PKCS11SignatureOperationSpec, error) {
	if s.useRawMech {
		return nil, fmt.Errorf("%w: RSA-PSS not available in raw mode", ErrPKCS11UnsupportedAlg)
	}

	mech, ok := rsaPSSMechMap[digestAlgorithm]
	if !ok {
		return nil, fmt.Errorf("%w: RSA-PSS with %s", ErrPKCS11UnsupportedAlg, digestAlgorithm)
	}

	digestMech, ok := digestMechMap[digestAlgorithm]
	if !ok {
		return nil, fmt.Errorf("%w: unknown digest %s", ErrPKCS11UnsupportedAlg, digestAlgorithm)
	}

	mgfMech, ok := mgfMechMap[digestAlgorithm]
	if !ok {
		return nil, fmt.Errorf("%w: unknown MGF for %s", ErrPKCS11UnsupportedAlg, digestAlgorithm)
	}

	saltLen := digestAlgSizes[digestAlgorithm]

	// PSS parameters (hash alg, MGF alg, salt len)
	pssParams := pkcs11.NewPSSParams(digestMech, mgfMech, uint(saltLen))

	spec := &PKCS11SignatureOperationSpec{
		Mechanism: pkcs11.NewMechanism(mech, pssParams),
	}

	return spec, nil
}

// selectECDSAParams selects ECDSA signing parameters.
func (s *PKCS11Signer) selectECDSAParams(digestAlgorithm string) (*PKCS11SignatureOperationSpec, error) {
	spec := &PKCS11SignatureOperationSpec{}

	if s.useRawMech {
		spec.Mechanism = pkcs11.NewMechanism(CKM_ECDSA, nil)
		spec.PreSignTransform = hashFully(digestAlgorithm)
	} else {
		mech, ok := ecdsaMechMap[digestAlgorithm]
		if !ok {
			return nil, fmt.Errorf("%w: ECDSA with %s", ErrPKCS11UnsupportedAlg, digestAlgorithm)
		}
		spec.Mechanism = pkcs11.NewMechanism(mech, nil)
	}

	// ECDSA signatures need to be encoded as DER
	spec.PostSignTransform = encodeECDSASignature

	return spec, nil
}

// selectDSAParams selects DSA signing parameters.
func (s *PKCS11Signer) selectDSAParams(digestAlgorithm string) (*PKCS11SignatureOperationSpec, error) {
	spec := &PKCS11SignatureOperationSpec{}

	if s.useRawMech {
		spec.Mechanism = pkcs11.NewMechanism(CKM_DSA, nil)
		spec.PreSignTransform = hashFully(digestAlgorithm)
	} else {
		mech, ok := dsaMechMap[digestAlgorithm]
		if !ok {
			return nil, fmt.Errorf("%w: DSA with %s", ErrPKCS11UnsupportedAlg, digestAlgorithm)
		}
		spec.Mechanism = pkcs11.NewMechanism(mech, nil)
	}

	// DSA signatures need to be encoded as DER
	spec.PostSignTransform = encodeDSASignature

	return spec, nil
}

// selectEdDSAParams selects EdDSA signing parameters.
func (s *PKCS11Signer) selectEdDSAParams(keyType string) (*PKCS11SignatureOperationSpec, error) {
	if s.useRawMech {
		return nil, fmt.Errorf("%w: %s not available in raw mode", ErrPKCS11UnsupportedAlg, keyType)
	}

	spec := &PKCS11SignatureOperationSpec{
		Mechanism: pkcs11.NewMechanism(CKM_EDDSA, nil),
	}

	return spec, nil
}

// getKeyType returns the key type based on the certificate.
func (s *PKCS11Signer) getKeyType() string {
	if s.signingCert == nil {
		return "unknown"
	}

	switch s.signingCert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.DSA:
		return "DSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "unknown"
	}
}

// getSignatureAlgorithm returns the CMS signature algorithm.
func (s *PKCS11Signer) getSignatureAlgorithm() cms.SignatureAlgorithm {
	keyType := s.getKeyType()

	switch keyType {
	case "RSA":
		// Note: RSA-PSS would need to be added to cms package if needed
		return cms.SHA256WithRSA
	case "ECDSA":
		return cms.SHA256WithECDSA
	default:
		return cms.SHA256WithRSA
	}
}

// GetCertificate implements the Signer interface.
func (s *PKCS11Signer) GetCertificate() *x509.Certificate {
	return s.signingCert
}

// GetCertificateChain implements the Signer interface.
func (s *PKCS11Signer) GetCertificateChain() []*x509.Certificate {
	return s.certChain
}

// GetSignatureSize implements the Signer interface.
func (s *PKCS11Signer) GetSignatureSize() int {
	// Estimate based on key size and CMS overhead
	size := 8192 // Base CMS structure

	if s.signingCert != nil {
		size += len(s.signingCert.Raw)

		// Add key-dependent signature size
		switch s.signingCert.PublicKeyAlgorithm {
		case x509.RSA:
			if rsaKey, ok := s.signingCert.PublicKey.(*rsa.PublicKey); ok {
				size += rsaKey.Size()
			}
		case x509.ECDSA:
			if ecKey, ok := s.signingCert.PublicKey.(*ecdsa.PublicKey); ok {
				size += (ecKey.Curve.Params().BitSize / 4) + 10 // r + s + DER overhead
			}
		}
	}

	for _, cert := range s.certChain {
		size += len(cert.Raw)
	}

	return size
}

// hashFully creates a transform that hashes data.
func hashFully(digestAlgorithm string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		h := getHasher(digestAlgorithm)
		if h == nil {
			return nil, fmt.Errorf("unknown digest algorithm: %s", digestAlgorithm)
		}
		h.Write(data)
		return h.Sum(nil), nil
	}
}

// hashFullyWithDigestInfo creates a transform that hashes and wraps in DigestInfo.
func hashFullyWithDigestInfo(digestAlgorithm string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		h := getHasher(digestAlgorithm)
		if h == nil {
			return nil, fmt.Errorf("unknown digest algorithm: %s", digestAlgorithm)
		}
		h.Write(data)
		digest := h.Sum(nil)

		// Wrap in DigestInfo structure
		return wrapDigestInfo(digestAlgorithm, digest)
	}
}

// getHasher returns a hash.Hash for the given algorithm.
func getHasher(digestAlgorithm string) hash.Hash {
	switch digestAlgorithm {
	case "sha1":
		return sha1.New()
	case "sha224":
		return sha256.New224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	default:
		return nil
	}
}

// wrapDigestInfo wraps a digest in a PKCS#1 DigestInfo structure.
func wrapDigestInfo(digestAlgorithm string, digest []byte) ([]byte, error) {
	var oid asn1.ObjectIdentifier

	switch digestAlgorithm {
	case "sha1":
		oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	case "sha224":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	case "sha256":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	case "sha384":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case "sha512":
		oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", digestAlgorithm)
	}

	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}

	type digestInfo struct {
		DigestAlgorithm algorithmIdentifier
		Digest          []byte
	}

	di := digestInfo{
		DigestAlgorithm: algorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.RawValue{Tag: 5}, // NULL
		},
		Digest: digest,
	}

	return asn1.Marshal(di)
}

// encodeECDSASignature encodes an ECDSA signature (r||s) to DER.
func encodeECDSASignature(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("invalid ECDSA signature length: %d", len(raw))
	}

	halfLen := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:halfLen])
	s := new(big.Int).SetBytes(raw[halfLen:])

	type ecdsaSig struct {
		R, S *big.Int
	}

	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

// encodeDSASignature encodes a DSA signature (r||s) to DER.
func encodeDSASignature(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("invalid DSA signature length: %d", len(raw))
	}

	halfLen := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:halfLen])
	s := new(big.Int).SetBytes(raw[halfLen:])

	type dsaSig struct {
		R, S *big.Int
	}

	return asn1.Marshal(dsaSig{R: r, S: s})
}

// OpenPKCS11Session opens a PKCS#11 session.
func OpenPKCS11Session(
	modulePath string,
	slotNo *int,
	tokenCriteria *config.TokenCriteria,
	userPIN string,
	protectedAuth bool,
) (*PKCS11Session, error) {
	// Load the PKCS#11 module
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("%w: %s", ErrPKCS11ModuleLoad, modulePath)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("PKCS#11 initialize failed: %w", err)
	}

	// Get slots
	slots, err := ctx.GetSlotList(true) // Only slots with tokens
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("failed to get slots: %w", err)
	}

	if len(slots) == 0 {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("%w: no slots with tokens available", ErrPKCS11NoToken)
	}

	// Find matching token
	var targetSlot uint
	found := false

	if slotNo != nil {
		if *slotNo >= len(slots) {
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("slot %d not found (only %d slots available)", *slotNo, len(slots))
		}
		targetSlot = slots[*slotNo]

		// Verify token criteria if specified
		if tokenCriteria != nil && !tokenCriteria.IsEmpty() {
			tokenInfo, err := ctx.GetTokenInfo(targetSlot)
			if err != nil {
				ctx.Finalize()
				ctx.Destroy()
				return nil, fmt.Errorf("failed to get token info: %w", err)
			}

			if !tokenMatchesCriteria(tokenInfo, tokenCriteria) {
				ctx.Finalize()
				ctx.Destroy()
				return nil, fmt.Errorf("%w: token in slot %d does not match criteria %s",
					ErrPKCS11NoToken, *slotNo, tokenCriteria)
			}
		}
		found = true
	} else if tokenCriteria != nil && !tokenCriteria.IsEmpty() {
		// Search for token matching criteria
		for _, slot := range slots {
			tokenInfo, err := ctx.GetTokenInfo(slot)
			if err != nil {
				continue
			}

			if tokenMatchesCriteria(tokenInfo, tokenCriteria) {
				targetSlot = slot
				found = true
				break
			}
		}
	} else {
		// Use first available slot
		if len(slots) > 1 {
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("multiple tokens available; specify slot number or token criteria")
		}
		targetSlot = slots[0]
		found = true
	}

	if !found {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("%w: no token matching criteria %s", ErrPKCS11NoToken, tokenCriteria)
	}

	// Open session
	session, err := ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("%w: %v", ErrPKCS11SessionFailed, err)
	}

	// Login if PIN provided
	if userPIN != "" {
		if err := ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil {
			ctx.CloseSession(session)
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("%w: %v", ErrPKCS11LoginFailed, err)
		}
	} else if protectedAuth {
		// Use protected authentication (PIN pad)
		if err := ctx.Login(session, pkcs11.CKU_USER, ""); err != nil {
			ctx.CloseSession(session)
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("%w: protected auth failed: %v", ErrPKCS11LoginFailed, err)
		}
	}

	return &PKCS11Session{
		ctx:     ctx,
		session: session,
		slotID:  targetSlot,
	}, nil
}

// tokenMatchesCriteria checks if a token matches the given criteria.
func tokenMatchesCriteria(tokenInfo pkcs11.TokenInfo, criteria *config.TokenCriteria) bool {
	if criteria == nil || criteria.IsEmpty() {
		return true
	}

	if criteria.Label != "" {
		// Trim trailing spaces from token label (PKCS#11 pads with spaces)
		tokenLabel := trimPKCS11String(tokenInfo.Label)
		if tokenLabel != criteria.Label {
			return false
		}
	}

	if criteria.Serial != nil {
		tokenSerial := trimPKCS11String(tokenInfo.SerialNumber)
		if tokenSerial != string(criteria.Serial) {
			return false
		}
	}

	return true
}

// trimPKCS11String trims trailing spaces from a PKCS#11 string.
func trimPKCS11String(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

// PKCS11SigningContext provides a context manager for PKCS#11 signing.
type PKCS11SigningContext struct {
	Config  *config.PKCS11SignatureConfig
	UserPIN string
	session *PKCS11Session
	signer  *PKCS11Signer
}

// NewPKCS11SigningContext creates a new PKCS#11 signing context.
func NewPKCS11SigningContext(cfg *config.PKCS11SignatureConfig) *PKCS11SigningContext {
	return &PKCS11SigningContext{
		Config: cfg,
	}
}

// WithUserPIN sets the user PIN.
func (c *PKCS11SigningContext) WithUserPIN(pin string) *PKCS11SigningContext {
	c.UserPIN = pin
	return c
}

// Open opens the PKCS#11 session and creates a signer.
func (c *PKCS11SigningContext) Open() (*PKCS11Signer, error) {
	// Determine PIN handling
	pin := c.UserPIN
	if pin == "" {
		pin = c.Config.UserPIN
	}

	protectedAuth := false
	if pin == "" && c.Config.PromptPIN == config.PKCS11PinDefer {
		protectedAuth = true
	}

	// Open session
	session, err := OpenPKCS11Session(
		c.Config.ModulePath,
		c.Config.SlotNo,
		c.Config.TokenCriteria,
		pin,
		protectedAuth,
	)
	if err != nil {
		return nil, err
	}
	c.session = session

	// Create signer
	signer := NewPKCS11Signer(session).
		WithCertLabel(c.Config.GetCertLabel()).
		WithCertID(c.Config.GetCertID()).
		WithKeyLabel(c.Config.GetKeyLabel()).
		WithKeyID(c.Config.GetKeyID()).
		WithPreferPSS(c.Config.PreferPSS).
		WithRawMechanism(c.Config.RawMechanism)

	// Set pre-loaded certificate if available
	if c.Config.SigningCertificate != nil {
		signer.WithSigningCertificate(c.Config.SigningCertificate)
	}

	// Set certificate chain if available
	if len(c.Config.OtherCerts) > 0 {
		signer.WithCertificateChain(c.Config.OtherCerts)
	}

	// Load key and certificate from token
	if err := signer.Load(); err != nil {
		session.Close()
		return nil, err
	}

	// Pull additional certificates from token if requested
	if c.Config.OtherCertsToPull == nil {
		// Pull all certificates
		certs, err := signer.PullAllCertificates()
		if err == nil && len(certs) > 0 {
			chain := signer.GetCertificateChain()
			chain = append(chain, certs...)
			signer.WithCertificateChain(chain)
		}
	} else if len(c.Config.OtherCertsToPull) > 0 {
		// Pull specific certificates by label
		for _, label := range c.Config.OtherCertsToPull {
			cert, err := signer.pullCertificate(label, nil)
			if err == nil {
				chain := signer.GetCertificateChain()
				chain = append(chain, cert)
				signer.WithCertificateChain(chain)
			}
		}
	}

	c.signer = signer
	return signer, nil
}

// Close closes the PKCS#11 session.
func (c *PKCS11SigningContext) Close() error {
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}

// FindToken finds a token in the given slots matching the criteria.
func FindToken(
	ctx *pkcs11.Ctx,
	slots []uint,
	slotNo *int,
	tokenCriteria *config.TokenCriteria,
) (uint, error) {
	if tokenCriteria == nil && slotNo == nil {
		if len(slots) == 1 {
			return slots[0], nil
		}
		return 0, fmt.Errorf("multiple slots available; specify slot number or token criteria")
	}

	if slotNo != nil {
		if *slotNo >= len(slots) {
			return 0, fmt.Errorf("slot %d not found (only %d slots available)", *slotNo, len(slots))
		}
		slot := slots[*slotNo]

		// Verify criteria if specified
		if tokenCriteria != nil && !tokenCriteria.IsEmpty() {
			tokenInfo, err := ctx.GetTokenInfo(slot)
			if err != nil {
				return 0, fmt.Errorf("failed to get token info: %w", err)
			}
			if !tokenMatchesCriteria(tokenInfo, tokenCriteria) {
				return 0, fmt.Errorf("token in slot %d does not match criteria", *slotNo)
			}
		}
		return slot, nil
	}

	// Search for matching token
	for _, slot := range slots {
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if tokenMatchesCriteria(tokenInfo, tokenCriteria) {
			return slot, nil
		}
	}

	return 0, fmt.Errorf("%w: no matching token found", ErrPKCS11NoToken)
}

// Ensure PKCS11Signer implements Signer interface
var _ Signer = (*PKCS11Signer)(nil)
