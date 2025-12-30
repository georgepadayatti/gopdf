// Package certvalidator provides X.509 certificate path validation.
// This file contains policy tree processing for RFC 5280 path validation.
package certvalidator

import (
	"fmt"
)

// AnyPolicy is the special OID indicating acceptance of any policy.
const AnyPolicy = "2.5.29.32.0"

// PolicyQualifier represents a policy qualifier from an X.509 certificate.
type PolicyQualifier struct {
	PolicyQualifierID string
	Qualifier         interface{}
}

// CertificatePolicy represents a certificate policy from the CertificatePolicies extension.
type CertificatePolicy struct {
	PolicyIdentifier string
	PolicyQualifiers []PolicyQualifier
}

// PolicyMapping represents a mapping from issuer domain policy to subject domain policy.
type PolicyMapping struct {
	IssuerDomainPolicy  string
	SubjectDomainPolicy string
}

// PolicyTreeNode represents a node in the policy tree used for RFC 5280 validation.
type PolicyTreeNode struct {
	Parent            PolicyTreeNodeInterface
	Children          []*PolicyTreeNode
	ValidPolicy       string
	QualifierSet      []PolicyQualifier
	ExpectedPolicySet map[string]bool
}

// PolicyTreeNodeInterface defines the interface for policy tree nodes.
type PolicyTreeNodeInterface interface {
	AddChild(validPolicy string, qualifierSet []PolicyQualifier, expectedPolicySet map[string]bool) *PolicyTreeNode
	RemoveChild(child *PolicyTreeNode)
	AtDepth(depth int) []*PolicyTreeNode
	WalkUp(depth int) []*PolicyTreeNode
	NodesInCurrentDomain() []*PolicyTreeNode
	GetChildren() []*PolicyTreeNode
}

// PolicyTreeRoot represents the root of a policy tree.
type PolicyTreeRoot struct {
	Children []*PolicyTreeNode
}

// NewPolicyTreeRoot creates a new policy tree root.
func NewPolicyTreeRoot() *PolicyTreeRoot {
	return &PolicyTreeRoot{
		Children: make([]*PolicyTreeNode, 0),
	}
}

// InitPolicyTree creates a new policy tree with an initial node at depth 0.
func InitPolicyTree(validPolicy string, qualifierSet []PolicyQualifier, expectedPolicySet map[string]bool) *PolicyTreeRoot {
	root := NewPolicyTreeRoot()
	root.AddChild(validPolicy, qualifierSet, expectedPolicySet)
	return root
}

// GetChildren returns the children of this node.
func (r *PolicyTreeRoot) GetChildren() []*PolicyTreeNode {
	return r.Children
}

// AddChild creates a new PolicyTreeNode as a child of this node.
func (r *PolicyTreeRoot) AddChild(validPolicy string, qualifierSet []PolicyQualifier, expectedPolicySet map[string]bool) *PolicyTreeNode {
	child := &PolicyTreeNode{
		Parent:            r,
		Children:          make([]*PolicyTreeNode, 0),
		ValidPolicy:       validPolicy,
		QualifierSet:      qualifierSet,
		ExpectedPolicySet: expectedPolicySet,
	}
	r.Children = append(r.Children, child)
	return child
}

// RemoveChild removes a child from this node.
func (r *PolicyTreeRoot) RemoveChild(child *PolicyTreeNode) {
	for i, c := range r.Children {
		if c == child {
			r.Children = append(r.Children[:i], r.Children[i+1:]...)
			return
		}
	}
}

// AtDepth returns all nodes in the tree at a specific depth.
func (r *PolicyTreeRoot) AtDepth(depth int) []*PolicyTreeNode {
	var result []*PolicyTreeNode
	for _, child := range r.Children {
		if depth == 0 {
			result = append(result, child)
		} else {
			result = append(result, child.AtDepth(depth-1)...)
		}
	}
	return result
}

// WalkUp returns all nodes at the specified depth or above, starting from leaves.
func (r *PolicyTreeRoot) WalkUp(depth int) []*PolicyTreeNode {
	var result []*PolicyTreeNode
	for _, child := range r.Children {
		if depth != 0 {
			result = append(result, child.WalkUp(depth-1)...)
		}
		result = append(result, child)
	}
	return result
}

// NodesInCurrentDomain returns all nodes that are children of an any_policy node.
func (r *PolicyTreeRoot) NodesInCurrentDomain() []*PolicyTreeNode {
	var result []*PolicyTreeNode
	for _, child := range r.Children {
		result = append(result, child)
		if child.ValidPolicy == AnyPolicy {
			result = append(result, child.NodesInCurrentDomain()...)
		}
	}
	return result
}

// PolicyTreeNode methods

// GetChildren returns the children of this node.
func (n *PolicyTreeNode) GetChildren() []*PolicyTreeNode {
	return n.Children
}

// AddChild creates a new PolicyTreeNode as a child of this node.
func (n *PolicyTreeNode) AddChild(validPolicy string, qualifierSet []PolicyQualifier, expectedPolicySet map[string]bool) *PolicyTreeNode {
	child := &PolicyTreeNode{
		Parent:            n,
		Children:          make([]*PolicyTreeNode, 0),
		ValidPolicy:       validPolicy,
		QualifierSet:      qualifierSet,
		ExpectedPolicySet: expectedPolicySet,
	}
	n.Children = append(n.Children, child)
	return child
}

// RemoveChild removes a child from this node.
func (n *PolicyTreeNode) RemoveChild(child *PolicyTreeNode) {
	for i, c := range n.Children {
		if c == child {
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return
		}
	}
}

// AtDepth returns all nodes in the subtree at a specific depth.
func (n *PolicyTreeNode) AtDepth(depth int) []*PolicyTreeNode {
	var result []*PolicyTreeNode
	for _, child := range n.Children {
		if depth == 0 {
			result = append(result, child)
		} else {
			result = append(result, child.AtDepth(depth-1)...)
		}
	}
	return result
}

// WalkUp returns all nodes at the specified depth or above, starting from leaves.
func (n *PolicyTreeNode) WalkUp(depth int) []*PolicyTreeNode {
	var result []*PolicyTreeNode
	for _, child := range n.Children {
		if depth != 0 {
			result = append(result, child.WalkUp(depth-1)...)
		}
		result = append(result, child)
	}
	return result
}

// NodesInCurrentDomain returns all nodes that are children of an any_policy node.
func (n *PolicyTreeNode) NodesInCurrentDomain() []*PolicyTreeNode {
	var result []*PolicyTreeNode
	for _, child := range n.Children {
		result = append(result, child)
		if child.ValidPolicy == AnyPolicy {
			result = append(result, child.NodesInCurrentDomain()...)
		}
	}
	return result
}

// PathToRoot returns all nodes from this node to the root.
func (n *PolicyTreeNode) PathToRoot() []*PolicyTreeNode {
	var result []*PolicyTreeNode
	node := n
	for node != nil {
		result = append(result, node)
		if parent, ok := node.Parent.(*PolicyTreeNode); ok {
			node = parent
		} else {
			break
		}
	}
	return result
}

// UpdatePolicyTree updates the policy tree during RFC 5280 validation.
// Implements RFC 5280 Section 6.1.3 (d).
func UpdatePolicyTree(
	certificatePolicies []CertificatePolicy,
	validPolicyTree *PolicyTreeRoot,
	depth int,
	anyPolicyUninhibited bool,
) *PolicyTreeRoot {
	var certAnyPolicy *CertificatePolicy
	certPolicyIdentifiers := make(map[string]bool)

	// Step (d)(1): For each policy P not equal to anyPolicy in the certificate policies
	for i := range certificatePolicies {
		policy := &certificatePolicies[i]
		policyIdentifier := policy.PolicyIdentifier

		if policyIdentifier == AnyPolicy {
			certAnyPolicy = policy
			continue
		}

		certPolicyIdentifiers[policyIdentifier] = true

		policyQualifiers := policy.PolicyQualifiers
		policyIDMatch := false
		var parentAnyPolicy *PolicyTreeNode

		// Step (d)(1)(i): For each node of depth i-1 in the valid_policy_tree where P
		// is in the expected_policy_set, create a child node
		for _, node := range validPolicyTree.AtDepth(depth - 1) {
			if node.ValidPolicy == AnyPolicy {
				parentAnyPolicy = node
			}
			// Check if policyIdentifier is in the expected policy set
			// Note: anyPolicy in the expected set matches any policy
			if node.ExpectedPolicySet[policyIdentifier] || node.ExpectedPolicySet[AnyPolicy] {
				policyIDMatch = true
				node.AddChild(policyIdentifier, policyQualifiers, map[string]bool{policyIdentifier: true})
			}
		}

		// Step (d)(1)(ii): If there was no match in step (i) and the valid_policy_tree
		// includes a node of depth i-1 with the valid_policy anyPolicy, generate a
		// child node with the following values:
		if !policyIDMatch && parentAnyPolicy != nil {
			parentAnyPolicy.AddChild(policyIdentifier, policyQualifiers, map[string]bool{policyIdentifier: true})
		}
	}

	// Step (d)(2): If the certificate policies extension includes the policy anyPolicy
	// with the qualifier set AP-Q and either (a) inhibit_anyPolicy is greater than 0 or
	// (b) i<n and the certificate is self-issued, then:
	if certAnyPolicy != nil && anyPolicyUninhibited {
		for _, node := range validPolicyTree.AtDepth(depth - 1) {
			for expectedPolicyIdentifier := range node.ExpectedPolicySet {
				// Skip anyPolicy itself
				if expectedPolicyIdentifier == AnyPolicy {
					continue
				}
				if !certPolicyIdentifiers[expectedPolicyIdentifier] {
					node.AddChild(
						expectedPolicyIdentifier,
						certAnyPolicy.PolicyQualifiers,
						map[string]bool{expectedPolicyIdentifier: true},
					)
				}
			}
		}
	}

	// Step (d)(3): If there is a node in the valid_policy_tree of depth i-1 or less
	// without any child nodes, delete that node.
	return prunePolicyTree(validPolicyTree, depth-1)
}

// prunePolicyTree removes nodes without children from the policy tree.
func prunePolicyTree(validPolicyTree *PolicyTreeRoot, depth int) *PolicyTreeRoot {
	for _, node := range validPolicyTree.WalkUp(depth) {
		if len(node.Children) == 0 && node.Parent != nil {
			node.Parent.RemoveChild(node)
		}
	}
	if len(validPolicyTree.Children) == 0 {
		return nil
	}
	return validPolicyTree
}

// EnumeratePolicyMappings processes policy mapping extension values.
func EnumeratePolicyMappings(mappings []PolicyMapping) (map[string]map[string]bool, error) {
	policyMap := make(map[string]map[string]bool)

	for _, mapping := range mappings {
		issuerDomainPolicy := mapping.IssuerDomainPolicy
		subjectDomainPolicy := mapping.SubjectDomainPolicy

		if policyMap[issuerDomainPolicy] == nil {
			policyMap[issuerDomainPolicy] = make(map[string]bool)
		}
		policyMap[issuerDomainPolicy][subjectDomainPolicy] = true

		// Step 3 a
		if issuerDomainPolicy == AnyPolicy || subjectDomainPolicy == AnyPolicy {
			return nil, fmt.Errorf("policy mapping contains \"any policy\"")
		}
	}

	return policyMap, nil
}

// ApplyPolicyMapping applies policy mapping to the current policy tree.
func ApplyPolicyMapping(
	policyMap map[string]map[string]bool,
	validPolicyTree *PolicyTreeRoot,
	depth int,
	policyMappingUninhibited bool,
) *PolicyTreeRoot {
	for issuerDomainPolicy, subjectDomainPolicies := range policyMap {
		// Step 3 b 1
		if policyMappingUninhibited {
			issuerDomainPolicyMatch := false
			var certAnyPolicy *PolicyTreeNode

			for _, node := range validPolicyTree.AtDepth(depth) {
				if node.ValidPolicy == AnyPolicy {
					certAnyPolicy = node
				}
				if node.ValidPolicy == issuerDomainPolicy {
					issuerDomainPolicyMatch = true
					node.ExpectedPolicySet = subjectDomainPolicies
				}
			}

			if !issuerDomainPolicyMatch && certAnyPolicy != nil {
				if parent, ok := certAnyPolicy.Parent.(*PolicyTreeNode); ok {
					parent.AddChild(
						issuerDomainPolicy,
						certAnyPolicy.QualifierSet,
						subjectDomainPolicies,
					)
				} else if root, ok := certAnyPolicy.Parent.(*PolicyTreeRoot); ok {
					root.AddChild(
						issuerDomainPolicy,
						certAnyPolicy.QualifierSet,
						subjectDomainPolicies,
					)
				}
			}
		} else {
			// Step 3 b 2
			for _, node := range validPolicyTree.AtDepth(depth) {
				if node.ValidPolicy == issuerDomainPolicy {
					node.Parent.RemoveChild(node)
				}
			}
			validPolicyTree = prunePolicyTree(validPolicyTree, depth-1)
			if validPolicyTree == nil {
				return nil
			}
		}
	}
	return validPolicyTree
}

// PruneUnacceptablePolicies prunes the policy tree to only contain acceptable policies.
func PruneUnacceptablePolicies(
	pathLength int,
	validPolicyTree *PolicyTreeRoot,
	acceptablePolicies map[string]bool,
) *PolicyTreeRoot {
	// Step 4 g iii 1: compute nodes that branch off any_policy
	validPolicyNodeSet := make([]*PolicyTreeNode, 0)
	for _, node := range validPolicyTree.NodesInCurrentDomain() {
		validPolicyNodeSet = append(validPolicyNodeSet, node)
	}

	// Step 4 g iii 2: eliminate unacceptable policies
	validAndAcceptable := make(map[string]bool)
	for _, policyNode := range validPolicyNodeSet {
		policyID := policyNode.ValidPolicy
		if policyID == AnyPolicy || acceptablePolicies[policyID] {
			validAndAcceptable[policyID] = true
		} else {
			policyNode.Parent.RemoveChild(policyNode)
		}
	}

	// Step 4 g iii 3: expand any_policy node if present
	for _, policyNode := range validPolicyTree.AtDepth(pathLength) {
		if policyNode.ValidPolicy == AnyPolicy {
			wildcardParent := policyNode.Parent
			wildcardQuals := policyNode.QualifierSet

			for acceptablePolicy := range acceptablePolicies {
				if !validAndAcceptable[acceptablePolicy] {
					wildcardParent.AddChild(
						acceptablePolicy,
						wildcardQuals,
						map[string]bool{acceptablePolicy: true},
					)
				}
			}
			// Prune the anyPolicy node
			wildcardParent.RemoveChild(policyNode)
			break
		}
	}

	// Step 4 g iii 4: prune the policy tree
	return prunePolicyTree(validPolicyTree, pathLength-1)
}

// CollectValidPolicies collects all valid policies from the policy tree.
func CollectValidPolicies(validPolicyTree *PolicyTreeRoot, depth int) map[string]bool {
	result := make(map[string]bool)
	for _, node := range validPolicyTree.AtDepth(depth) {
		if node.ValidPolicy != AnyPolicy {
			result[node.ValidPolicy] = true
		}
	}
	return result
}

// PolicyTreeIsEmpty checks if the policy tree is empty or nil.
func PolicyTreeIsEmpty(tree *PolicyTreeRoot) bool {
	return tree == nil || len(tree.Children) == 0
}
