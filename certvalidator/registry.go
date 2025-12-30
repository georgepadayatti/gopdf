// Package certvalidator provides X.509 certificate path validation.
// This file contains certificate registry and path building functionality.
package certvalidator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"

	"github.com/georgepadayatti/gopdf/certvalidator/fetchers"
)

// Common errors for registry operations.
var (
	ErrCertNotFound      = errors.New("certificate not found")
	ErrPathBuildingError = errors.New("path building error")
	ErrNoPathsFound      = errors.New("no certification paths found")
)

// CertIssuerKey represents a certificate issuer and serial number pair for indexing.
// This is distinct from the ASN.1 IssuerSerial type in asn1_types.go.
type CertIssuerKey struct {
	IssuerHash [32]byte
	Serial     string
}

// NewCertIssuerKey creates a CertIssuerKey from a certificate.
func NewCertIssuerKey(cert *x509.Certificate) CertIssuerKey {
	return CertIssuerKey{
		IssuerHash: sha256.Sum256([]byte(canonicalNameString(cert.Issuer))),
		Serial:     cert.SerialNumber.String(),
	}
}

// CertificateCollection is a read-only interface for certificate lookups.
type CertificateCollection interface {
	// RetrieveByKeyIdentifier retrieves a certificate by its subject key identifier.
	RetrieveByKeyIdentifier(keyID []byte) *x509.Certificate

	// RetrieveManyByKeyIdentifier retrieves all certificates with the given key identifier.
	RetrieveManyByKeyIdentifier(keyID []byte) []*x509.Certificate

	// RetrieveByName retrieves certificates by subject name.
	RetrieveByName(name pkix.Name) []*x509.Certificate

	// RetrieveByIssuerKey retrieves a certificate by issuer and serial.
	RetrieveByIssuerKey(issuerKey CertIssuerKey) *x509.Certificate
}

// CertificateStore extends CertificateCollection with write operations.
type CertificateStore interface {
	CertificateCollection

	// Register adds a certificate to the store.
	// Returns true if the certificate was newly added.
	Register(cert *x509.Certificate) bool

	// RegisterMultiple adds multiple certificates to the store.
	RegisterMultiple(certs []*x509.Certificate)

	// All returns all certificates in the store.
	All() []*x509.Certificate

	// Count returns the number of certificates in the store.
	Count() int
}

// SimpleCertificateStore is a basic implementation of CertificateStore.
type SimpleCertificateStore struct {
	mu sync.RWMutex

	// Main storage keyed by issuer key
	certs map[CertIssuerKey]*x509.Certificate

	// Index by subject name hash for issuer lookups
	subjectMap map[string][]*x509.Certificate

	// Index by key identifier
	keyIDMap map[string][]*x509.Certificate
}

// NewSimpleCertificateStore creates a new SimpleCertificateStore.
func NewSimpleCertificateStore() *SimpleCertificateStore {
	return &SimpleCertificateStore{
		certs:      make(map[CertIssuerKey]*x509.Certificate),
		subjectMap: make(map[string][]*x509.Certificate),
		keyIDMap:   make(map[string][]*x509.Certificate),
	}
}

// Register adds a certificate to the store.
func (s *SimpleCertificateStore) Register(cert *x509.Certificate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	issuerKey := NewCertIssuerKey(cert)

	// Check if already registered
	if _, exists := s.certs[issuerKey]; exists {
		return false
	}

	// Add to main storage
	s.certs[issuerKey] = cert

	// Add to subject map
	subjectKey := subjectHashKey(cert.Subject)
	s.subjectMap[subjectKey] = append(s.subjectMap[subjectKey], cert)

	// Add to key ID map if subject key ID is present
	if len(cert.SubjectKeyId) > 0 {
		keyIDKey := string(cert.SubjectKeyId)
		s.keyIDMap[keyIDKey] = append(s.keyIDMap[keyIDKey], cert)
	}

	return true
}

// RegisterMultiple adds multiple certificates to the store.
func (s *SimpleCertificateStore) RegisterMultiple(certs []*x509.Certificate) {
	for _, cert := range certs {
		s.Register(cert)
	}
}

// RetrieveByKeyIdentifier retrieves a certificate by its subject key identifier.
func (s *SimpleCertificateStore) RetrieveByKeyIdentifier(keyID []byte) *x509.Certificate {
	certs := s.RetrieveManyByKeyIdentifier(keyID)
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// RetrieveManyByKeyIdentifier retrieves all certificates with the given key identifier.
func (s *SimpleCertificateStore) RetrieveManyByKeyIdentifier(keyID []byte) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.keyIDMap[string(keyID)]
}

// RetrieveByName retrieves certificates by subject name.
func (s *SimpleCertificateStore) RetrieveByName(name pkix.Name) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.subjectMap[subjectHashKey(name)]
}

// RetrieveByIssuerKey retrieves a certificate by issuer and serial.
func (s *SimpleCertificateStore) RetrieveByIssuerKey(issuerKey CertIssuerKey) *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.certs[issuerKey]
}

// All returns all certificates in the store.
func (s *SimpleCertificateStore) All() []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*x509.Certificate, 0, len(s.certs))
	for _, cert := range s.certs {
		result = append(result, cert)
	}
	return result
}

// Count returns the number of certificates in the store.
func (s *SimpleCertificateStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.certs)
}

// subjectHashKey creates a hash key from a subject name.
func subjectHashKey(name pkix.Name) string {
	h := sha256.Sum256([]byte(canonicalNameString(name)))
	return string(h[:])
}

// TrustManager manages trust anchors for certificate validation.
type TrustManager interface {
	// IsRoot checks if a certificate is a trust root.
	IsRoot(cert *x509.Certificate) bool

	// AsTrustAnchor returns the TrustAnchor if the authority matches a trust root.
	AsTrustAnchor(authority Authority) *CertTrustAnchor

	// FindPotentialIssuers finds trust anchors that could have issued the certificate.
	FindPotentialIssuers(cert *x509.Certificate, serviceType TrustedServiceType) []*CertTrustAnchor
}

// SimpleTrustManager is a basic implementation of TrustManager.
type SimpleTrustManager struct {
	mu sync.RWMutex

	// Set of trust anchors
	roots map[string]*CertTrustAnchor

	// Index by subject for issuer lookups
	rootSubjectMap map[string][]*CertTrustAnchor
}

// NewSimpleTrustManager creates a new SimpleTrustManager.
func NewSimpleTrustManager() *SimpleTrustManager {
	return &SimpleTrustManager{
		roots:          make(map[string]*CertTrustAnchor),
		rootSubjectMap: make(map[string][]*CertTrustAnchor),
	}
}

// BuildTrustManager creates a trust manager from certificates.
func BuildTrustManager(certs []*x509.Certificate, deriveQuals bool) *SimpleTrustManager {
	tm := NewSimpleTrustManager()
	for _, cert := range certs {
		tm.AddRoot(cert, deriveQuals)
	}
	return tm
}

// AddRoot adds a certificate as a trust root.
func (tm *SimpleTrustManager) AddRoot(cert *x509.Certificate, deriveQuals bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	anchor := NewCertTrustAnchor(cert, nil, deriveQuals)
	tm.registerRoot(anchor)
}

// AddRootWithQuals adds a certificate as a trust root with explicit qualifiers.
func (tm *SimpleTrustManager) AddRootWithQuals(cert *x509.Certificate, quals *TrustQualifiers) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	anchor := NewCertTrustAnchor(cert, quals, false)
	tm.registerRoot(anchor)
}

// registerRoot adds a trust anchor to the internal maps.
func (tm *SimpleTrustManager) registerRoot(anchor *CertTrustAnchor) {
	hashKey := anchor.Authority().Hashable()

	// Don't add duplicates
	if _, exists := tm.roots[hashKey]; exists {
		return
	}

	tm.roots[hashKey] = anchor

	// Add to subject map
	subjectKey := subjectHashKey(anchor.Authority().Name())
	tm.rootSubjectMap[subjectKey] = append(tm.rootSubjectMap[subjectKey], anchor)
}

// IsRoot checks if a certificate is a trust root.
func (tm *SimpleTrustManager) IsRoot(cert *x509.Certificate) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Create a temporary authority to check
	authority := NewAuthorityWithCert(cert)
	hashKey := authority.Hashable()

	_, exists := tm.roots[hashKey]
	return exists
}

// AsTrustAnchor returns the TrustAnchor if the authority matches a trust root.
func (tm *SimpleTrustManager) AsTrustAnchor(authority Authority) *CertTrustAnchor {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Look up by subject first
	subjectKey := subjectHashKey(authority.Name())
	anchors := tm.rootSubjectMap[subjectKey]

	for _, anchor := range anchors {
		if anchor.Authority().Hashable() == authority.Hashable() {
			return anchor
		}
	}

	return nil
}

// FindPotentialIssuers finds trust anchors that could have issued the certificate.
func (tm *SimpleTrustManager) FindPotentialIssuers(cert *x509.Certificate, serviceType TrustedServiceType) []*CertTrustAnchor {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var issuers []*CertTrustAnchor

	// Look up by issuer name
	issuerKey := subjectHashKey(cert.Issuer)
	anchors := tm.rootSubjectMap[issuerKey]

	for _, anchor := range anchors {
		// Check if this anchor could be the issuer
		if !anchor.Authority().IsPotentialIssuerOf(cert) {
			continue
		}

		// Check service type if specified
		quals := anchor.TrustQualifiers()
		if serviceType != TrustedServiceUnspecified {
			if quals.TrustedServiceType != TrustedServiceUnspecified &&
				quals.TrustedServiceType != serviceType {
				continue
			}
		}

		issuers = append(issuers, anchor)
	}

	return issuers
}

// AllRoots returns all trust anchors.
func (tm *SimpleTrustManager) AllRoots() []*CertTrustAnchor {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	result := make([]*CertTrustAnchor, 0, len(tm.roots))
	for _, anchor := range tm.roots {
		result = append(result, anchor)
	}
	return result
}

// Count returns the number of trust anchors.
func (tm *SimpleTrustManager) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	return len(tm.roots)
}

// CertificateRegistry extends SimpleCertificateStore with certificate fetching.
type CertificateRegistry struct {
	*SimpleCertificateStore

	// Fetcher for retrieving certificates from remote sources
	fetcher *fetchers.CertFetcher
}

// NewCertificateRegistry creates a new CertificateRegistry.
func NewCertificateRegistry(fetcher *fetchers.CertFetcher) *CertificateRegistry {
	return &CertificateRegistry{
		SimpleCertificateStore: NewSimpleCertificateStore(),
		fetcher:                fetcher,
	}
}

// BuildCertificateRegistry creates a registry with initial certificates.
func BuildCertificateRegistry(certs []*x509.Certificate, fetcher *fetchers.CertFetcher) *CertificateRegistry {
	registry := NewCertificateRegistry(fetcher)
	registry.RegisterMultiple(certs)
	return registry
}

// RetrieveFirstByName retrieves the first certificate matching the name.
func (r *CertificateRegistry) RetrieveFirstByName(name pkix.Name) *x509.Certificate {
	certs := r.RetrieveByName(name)
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// FindPotentialIssuers finds certificates that could be issuers.
// This checks both local store and filters by authority key identifier.
func (r *CertificateRegistry) FindPotentialIssuers(cert *x509.Certificate) []*x509.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Get candidates by issuer name
	issuerKey := subjectHashKey(cert.Issuer)
	candidates := r.subjectMap[issuerKey]

	var issuers []*x509.Certificate
	for _, candidate := range candidates {
		if isPotentialIssuer(candidate, cert) {
			issuers = append(issuers, candidate)
		}
	}

	if len(issuers) == 0 {
		for _, candidate := range r.certs {
			if isPotentialIssuer(candidate, cert) {
				issuers = append(issuers, candidate)
			}
		}
	}

	return issuers
}

// FetchMissingIssuers attempts to fetch missing issuers via AIA.
func (r *CertificateRegistry) FetchMissingIssuers(ctx context.Context, cert *x509.Certificate) ([]*x509.Certificate, error) {
	if r.fetcher == nil {
		return nil, nil
	}

	// Check if we already have potential issuers locally
	localIssuers := r.FindPotentialIssuers(cert)
	if len(localIssuers) > 0 {
		return localIssuers, nil
	}

	// Try to fetch via AIA
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, nil
	}

	var fetched []*x509.Certificate
	for _, url := range cert.IssuingCertificateURL {
		certs, err := r.fetcher.FetchCertificates(ctx, url)
		if err != nil {
			continue
		}

		for _, issuer := range certs {
			if isPotentialIssuer(issuer, cert) {
				r.Register(issuer)
				fetched = append(fetched, issuer)
			}
		}
	}

	return fetched, nil
}

// isPotentialIssuer checks if issuer could have issued cert.
func isPotentialIssuer(issuer, cert *x509.Certificate) bool {
	// Check authority key identifier if present
	if len(cert.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 {
		if bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) {
			return true
		}
		return false
	}

	// Fallback to issuer name match
	return namesEqual(cert.Issuer, issuer.Subject)
}

// PathBuilder builds certification paths from a target certificate to trust anchors.
type PathBuilder struct {
	trustManager TrustManager
	registry     *CertificateRegistry
}

// NewPathBuilder creates a new PathBuilder.
func NewPathBuilder(trustManager TrustManager, registry *CertificateRegistry) *PathBuilder {
	return &PathBuilder{
		trustManager: trustManager,
		registry:     registry,
	}
}

// CertificationPath represents a built certification path from target to trust anchor.
// This is distinct from ValidationPath in state.go which is used during validation.
type CertificationPath struct {
	// Certificates in the path from target to trust anchor (not including anchor)
	Certificates []*x509.Certificate

	// TrustAnchor at the end of the path
	TrustAnchor *CertTrustAnchor
}

// NewCertificationPath creates a new CertificationPath.
func NewCertificationPath(certs []*x509.Certificate, anchor *CertTrustAnchor) *CertificationPath {
	return &CertificationPath{
		Certificates: certs,
		TrustAnchor:  anchor,
	}
}

// Length returns the total length of the path including the trust anchor.
func (p *CertificationPath) Length() int {
	return len(p.Certificates) + 1
}

// Last returns the last certificate in the path (closest to trust anchor).
func (p *CertificationPath) Last() *x509.Certificate {
	if len(p.Certificates) == 0 {
		return nil
	}
	return p.Certificates[len(p.Certificates)-1]
}

// First returns the first certificate in the path (the target).
func (p *CertificationPath) First() *x509.Certificate {
	if len(p.Certificates) == 0 {
		return nil
	}
	return p.Certificates[0]
}

// BuildPaths builds all valid certification paths for a certificate.
func (pb *PathBuilder) BuildPaths(ctx context.Context, cert *x509.Certificate) ([]*CertificationPath, error) {
	var paths []*CertificationPath

	// Check if the certificate itself is a trust root
	if pb.trustManager.IsRoot(cert) {
		authority := NewAuthorityWithCert(cert)
		anchor := pb.trustManager.AsTrustAnchor(authority)
		if anchor != nil {
			paths = append(paths, NewCertificationPath(nil, anchor))
		}
	}

	// Build paths through walker
	walker := &pathWalker{
		ctx:         ctx,
		cert:        cert,
		pathBuilder: pb,
		certsSeen:   make(map[string]bool),
		currentPath: []*x509.Certificate{cert},
	}

	walkerPaths, err := walker.walk()
	if err != nil {
		// Only return error if we found no paths
		if len(paths) == 0 {
			return nil, err
		}
	}

	paths = append(paths, walkerPaths...)

	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: no paths found for certificate with subject %s",
			ErrNoPathsFound, cert.Subject.String())
	}

	return paths, nil
}

// BuildFirstPath builds the first valid certification path.
func (pb *PathBuilder) BuildFirstPath(ctx context.Context, cert *x509.Certificate) (*CertificationPath, error) {
	paths, err := pb.BuildPaths(ctx, cert)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, ErrNoPathsFound
	}
	return paths[0], nil
}

// pathWalker recursively walks the certificate graph to find paths.
type pathWalker struct {
	ctx         context.Context
	cert        *x509.Certificate
	pathBuilder *PathBuilder
	certsSeen   map[string]bool
	currentPath []*x509.Certificate
}

func (w *pathWalker) walk() ([]*CertificationPath, error) {
	var paths []*CertificationPath

	// Get all potential issuers
	issuers := w.fetchIssuers()

	for _, issuer := range issuers {
		// Check context cancellation
		select {
		case <-w.ctx.Done():
			return paths, w.ctx.Err()
		default:
		}

		// Check if issuer is a trust anchor
		authority := NewAuthorityWithCert(issuer.cert)
		if anchor := w.pathBuilder.trustManager.AsTrustAnchor(authority); anchor != nil {
			// Found a path to a trust anchor
			pathCerts := make([]*x509.Certificate, len(w.currentPath))
			copy(pathCerts, w.currentPath)
			paths = append(paths, NewCertificationPath(pathCerts, anchor))
			continue
		}

		// Check for cycles
		issuerKey := certKey(issuer.cert)
		if w.certsSeen[issuerKey] {
			continue
		}

		// Recurse with the issuer
		w.certsSeen[issuerKey] = true
		childWalker := &pathWalker{
			ctx:         w.ctx,
			cert:        issuer.cert,
			pathBuilder: w.pathBuilder,
			certsSeen:   w.certsSeen,
			currentPath: append(w.currentPath, issuer.cert),
		}

		childPaths, _ := childWalker.walk()
		paths = append(paths, childPaths...)

		delete(w.certsSeen, issuerKey)
	}

	return paths, nil
}

type issuerCandidate struct {
	cert     *x509.Certificate
	isRemote bool
}

func (w *pathWalker) fetchIssuers() []issuerCandidate {
	var candidates []issuerCandidate

	// First try local registry
	localIssuers := w.pathBuilder.registry.FindPotentialIssuers(w.cert)
	for _, issuer := range localIssuers {
		candidates = append(candidates, issuerCandidate{cert: issuer, isRemote: false})
	}

	// If no local issuers and we have a fetcher, try remote
	if len(candidates) == 0 && w.pathBuilder.registry.fetcher != nil {
		remoteIssuers, _ := w.pathBuilder.registry.FetchMissingIssuers(w.ctx, w.cert)
		for _, issuer := range remoteIssuers {
			candidates = append(candidates, issuerCandidate{cert: issuer, isRemote: true})
		}
	}

	return candidates
}

// certKey creates a unique key for a certificate.
func certKey(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return string(h[:])
}

// LayeredCertificateStore looks up certificates across multiple stores.
type LayeredCertificateStore struct {
	stores []CertificateCollection
}

// NewLayeredCertificateStore creates a new LayeredCertificateStore.
func NewLayeredCertificateStore(stores ...CertificateCollection) *LayeredCertificateStore {
	return &LayeredCertificateStore{stores: stores}
}

// RetrieveByKeyIdentifier retrieves from the first store that has a match.
func (s *LayeredCertificateStore) RetrieveByKeyIdentifier(keyID []byte) *x509.Certificate {
	for _, store := range s.stores {
		if cert := store.RetrieveByKeyIdentifier(keyID); cert != nil {
			return cert
		}
	}
	return nil
}

// RetrieveManyByKeyIdentifier retrieves from all stores.
func (s *LayeredCertificateStore) RetrieveManyByKeyIdentifier(keyID []byte) []*x509.Certificate {
	var result []*x509.Certificate
	seen := make(map[string]bool)

	for _, store := range s.stores {
		for _, cert := range store.RetrieveManyByKeyIdentifier(keyID) {
			key := certKey(cert)
			if !seen[key] {
				seen[key] = true
				result = append(result, cert)
			}
		}
	}
	return result
}

// RetrieveByName retrieves from all stores.
func (s *LayeredCertificateStore) RetrieveByName(name pkix.Name) []*x509.Certificate {
	var result []*x509.Certificate
	seen := make(map[string]bool)

	for _, store := range s.stores {
		for _, cert := range store.RetrieveByName(name) {
			key := certKey(cert)
			if !seen[key] {
				seen[key] = true
				result = append(result, cert)
			}
		}
	}
	return result
}

// RetrieveByIssuerKey retrieves from the first store that has a match.
func (s *LayeredCertificateStore) RetrieveByIssuerKey(issuerKey CertIssuerKey) *x509.Certificate {
	for _, store := range s.stores {
		if cert := store.RetrieveByIssuerKey(issuerKey); cert != nil {
			return cert
		}
	}
	return nil
}

// TrustAnchorStoreAdapter adapts TrustAnchorStore to CertificateCollection.
type TrustAnchorStoreAdapter struct {
	store *TrustAnchorStore
}

// NewTrustAnchorStoreAdapter creates an adapter for TrustAnchorStore.
func NewTrustAnchorStoreAdapter(store *TrustAnchorStore) *TrustAnchorStoreAdapter {
	return &TrustAnchorStoreAdapter{store: store}
}

// RetrieveByKeyIdentifier retrieves a trust anchor certificate by key ID.
func (a *TrustAnchorStoreAdapter) RetrieveByKeyIdentifier(keyID []byte) *x509.Certificate {
	for _, anchor := range a.store.All() {
		if bytes.Equal(anchor.Certificate().SubjectKeyId, keyID) {
			return anchor.Certificate()
		}
	}
	return nil
}

// RetrieveManyByKeyIdentifier retrieves all trust anchor certificates by key ID.
func (a *TrustAnchorStoreAdapter) RetrieveManyByKeyIdentifier(keyID []byte) []*x509.Certificate {
	var result []*x509.Certificate
	for _, anchor := range a.store.All() {
		if bytes.Equal(anchor.Certificate().SubjectKeyId, keyID) {
			result = append(result, anchor.Certificate())
		}
	}
	return result
}

// RetrieveByName retrieves trust anchor certificates by name.
func (a *TrustAnchorStoreAdapter) RetrieveByName(name pkix.Name) []*x509.Certificate {
	var result []*x509.Certificate
	for _, anchor := range a.store.All() {
		if anchor.Certificate().Subject.String() == name.String() {
			result = append(result, anchor.Certificate())
		}
	}
	return result
}

// RetrieveByIssuerKey retrieves a trust anchor certificate by issuer key.
func (a *TrustAnchorStoreAdapter) RetrieveByIssuerKey(issuerKey CertIssuerKey) *x509.Certificate {
	for _, anchor := range a.store.All() {
		if NewCertIssuerKey(anchor.Certificate()) == issuerKey {
			return anchor.Certificate()
		}
	}
	return nil
}
