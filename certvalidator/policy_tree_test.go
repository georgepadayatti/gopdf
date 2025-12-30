package certvalidator

import (
	"testing"
)

func TestPolicyTreeRoot(t *testing.T) {
	t.Run("new root has no children", func(t *testing.T) {
		root := NewPolicyTreeRoot()
		if len(root.Children) != 0 {
			t.Errorf("expected 0 children, got %d", len(root.Children))
		}
	})

	t.Run("add child", func(t *testing.T) {
		root := NewPolicyTreeRoot()
		child := root.AddChild("policy1", nil, map[string]bool{"policy1": true})
		if len(root.Children) != 1 {
			t.Errorf("expected 1 child, got %d", len(root.Children))
		}
		if child.ValidPolicy != "policy1" {
			t.Errorf("expected policy1, got %s", child.ValidPolicy)
		}
		if child.Parent != root {
			t.Error("child parent should be root")
		}
	})

	t.Run("remove child", func(t *testing.T) {
		root := NewPolicyTreeRoot()
		child1 := root.AddChild("policy1", nil, map[string]bool{"policy1": true})
		root.AddChild("policy2", nil, map[string]bool{"policy2": true})
		if len(root.Children) != 2 {
			t.Errorf("expected 2 children, got %d", len(root.Children))
		}
		root.RemoveChild(child1)
		if len(root.Children) != 1 {
			t.Errorf("expected 1 child after removal, got %d", len(root.Children))
		}
		if root.Children[0].ValidPolicy != "policy2" {
			t.Error("remaining child should be policy2")
		}
	})
}

func TestInitPolicyTree(t *testing.T) {
	tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
	if tree == nil {
		t.Fatal("tree should not be nil")
	}
	if len(tree.Children) != 1 {
		t.Errorf("expected 1 child, got %d", len(tree.Children))
	}
	if tree.Children[0].ValidPolicy != AnyPolicy {
		t.Errorf("expected %s, got %s", AnyPolicy, tree.Children[0].ValidPolicy)
	}
}

func TestPolicyTreeAtDepth(t *testing.T) {
	root := NewPolicyTreeRoot()
	child1 := root.AddChild("level0-1", nil, nil)
	child2 := root.AddChild("level0-2", nil, nil)
	grandchild1 := child1.AddChild("level1-1", nil, nil)
	child2.AddChild("level1-2", nil, nil)
	grandchild1.AddChild("level2-1", nil, nil)

	t.Run("depth 0", func(t *testing.T) {
		nodes := root.AtDepth(0)
		if len(nodes) != 2 {
			t.Errorf("expected 2 nodes at depth 0, got %d", len(nodes))
		}
	})

	t.Run("depth 1", func(t *testing.T) {
		nodes := root.AtDepth(1)
		if len(nodes) != 2 {
			t.Errorf("expected 2 nodes at depth 1, got %d", len(nodes))
		}
	})

	t.Run("depth 2", func(t *testing.T) {
		nodes := root.AtDepth(2)
		if len(nodes) != 1 {
			t.Errorf("expected 1 node at depth 2, got %d", len(nodes))
		}
	})
}

func TestPolicyTreeWalkUp(t *testing.T) {
	root := NewPolicyTreeRoot()
	child := root.AddChild("level0", nil, nil)
	grandchild := child.AddChild("level1", nil, nil)
	grandchild.AddChild("level2", nil, nil)

	nodes := root.WalkUp(2)
	if len(nodes) < 3 {
		t.Errorf("expected at least 3 nodes, got %d", len(nodes))
	}
}

func TestPolicyTreeNodesInCurrentDomain(t *testing.T) {
	root := NewPolicyTreeRoot()
	anyPolicyNode := root.AddChild(AnyPolicy, nil, nil)
	root.AddChild("policy1", nil, nil)
	anyPolicyNode.AddChild("policy2", nil, nil)
	anyPolicyNode.AddChild("policy3", nil, nil)

	nodes := root.NodesInCurrentDomain()
	// Should include: anyPolicy, policy1, policy2, policy3
	if len(nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(nodes))
	}
}

func TestPolicyTreeNodePathToRoot(t *testing.T) {
	root := NewPolicyTreeRoot()
	child := root.AddChild("level0", nil, nil)
	grandchild := child.AddChild("level1", nil, nil)
	greatGrandchild := grandchild.AddChild("level2", nil, nil)

	path := greatGrandchild.PathToRoot()
	if len(path) != 3 {
		t.Errorf("expected 3 nodes in path, got %d", len(path))
	}
	if path[0].ValidPolicy != "level2" {
		t.Error("first node should be level2")
	}
	if path[2].ValidPolicy != "level0" {
		t.Error("last node should be level0")
	}
}

func TestUpdatePolicyTree(t *testing.T) {
	t.Run("add matching policy", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{"policy1": true, "policy2": true})

		policies := []CertificatePolicy{
			{PolicyIdentifier: "policy1", PolicyQualifiers: nil},
		}

		result := UpdatePolicyTree(policies, tree, 1, true)
		if result == nil {
			t.Fatal("tree should not be nil")
		}

		nodesAtDepth1 := result.AtDepth(1)
		found := false
		for _, node := range nodesAtDepth1 {
			if node.ValidPolicy == "policy1" {
				found = true
				break
			}
		}
		if !found {
			t.Error("policy1 should be in tree at depth 1")
		}
	})

	t.Run("any policy expansion", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{"policy1": true, "policy2": true})

		policies := []CertificatePolicy{
			{PolicyIdentifier: AnyPolicy, PolicyQualifiers: nil},
		}

		result := UpdatePolicyTree(policies, tree, 1, true)
		if result == nil {
			t.Fatal("tree should not be nil")
		}
	})
}

func TestEnumeratePolicyMappings(t *testing.T) {
	t.Run("valid mappings", func(t *testing.T) {
		mappings := []PolicyMapping{
			{IssuerDomainPolicy: "policy1", SubjectDomainPolicy: "policy2"},
			{IssuerDomainPolicy: "policy1", SubjectDomainPolicy: "policy3"},
			{IssuerDomainPolicy: "policy4", SubjectDomainPolicy: "policy5"},
		}

		result, err := EnumeratePolicyMappings(mappings)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result) != 2 {
			t.Errorf("expected 2 issuer policies, got %d", len(result))
		}

		if len(result["policy1"]) != 2 {
			t.Errorf("expected 2 subject policies for policy1, got %d", len(result["policy1"]))
		}
	})

	t.Run("any policy in mapping fails", func(t *testing.T) {
		mappings := []PolicyMapping{
			{IssuerDomainPolicy: AnyPolicy, SubjectDomainPolicy: "policy1"},
		}

		_, err := EnumeratePolicyMappings(mappings)
		if err == nil {
			t.Error("expected error for any policy mapping")
		}
	})

	t.Run("any policy as subject fails", func(t *testing.T) {
		mappings := []PolicyMapping{
			{IssuerDomainPolicy: "policy1", SubjectDomainPolicy: AnyPolicy},
		}

		_, err := EnumeratePolicyMappings(mappings)
		if err == nil {
			t.Error("expected error for any policy mapping")
		}
	})
}

func TestApplyPolicyMapping(t *testing.T) {
	t.Run("mapping uninhibited", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
		tree.Children[0].AddChild("policy1", nil, map[string]bool{"policy1": true})

		policyMap := map[string]map[string]bool{
			"policy1": {"policy2": true, "policy3": true},
		}

		result := ApplyPolicyMapping(policyMap, tree, 1, true)
		if result == nil {
			t.Fatal("tree should not be nil")
		}

		// Check that expected policy set was updated
		for _, node := range result.AtDepth(1) {
			if node.ValidPolicy == "policy1" {
				if !node.ExpectedPolicySet["policy2"] || !node.ExpectedPolicySet["policy3"] {
					t.Error("expected policy set should contain policy2 and policy3")
				}
			}
		}
	})

	t.Run("mapping inhibited removes nodes", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
		tree.Children[0].AddChild("policy1", nil, map[string]bool{"policy1": true})
		tree.Children[0].AddChild("policy2", nil, map[string]bool{"policy2": true})

		policyMap := map[string]map[string]bool{
			"policy1": {"policy3": true},
		}

		result := ApplyPolicyMapping(policyMap, tree, 1, false)
		if result == nil {
			t.Fatal("tree should not be nil after pruning")
		}

		// policy1 should be removed
		for _, node := range result.AtDepth(1) {
			if node.ValidPolicy == "policy1" {
				t.Error("policy1 should have been removed")
			}
		}
	})
}

func TestPruneUnacceptablePolicies(t *testing.T) {
	t.Run("keep acceptable policies", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
		tree.Children[0].AddChild("policy1", nil, map[string]bool{"policy1": true})
		tree.Children[0].AddChild("policy2", nil, map[string]bool{"policy2": true})
		tree.Children[0].AddChild("policy3", nil, map[string]bool{"policy3": true})

		acceptable := map[string]bool{"policy1": true, "policy2": true}

		result := PruneUnacceptablePolicies(1, tree, acceptable)
		if result == nil {
			t.Fatal("tree should not be nil")
		}

		nodes := result.AtDepth(1)
		for _, node := range nodes {
			if node.ValidPolicy == "policy3" {
				t.Error("policy3 should have been pruned")
			}
		}
	})

	t.Run("expand any policy", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
		anyPolicyChild := tree.Children[0].AddChild(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
		if anyPolicyChild == nil {
			t.Fatal("failed to add any policy child")
		}

		acceptable := map[string]bool{"policy1": true, "policy2": true}

		result := PruneUnacceptablePolicies(1, tree, acceptable)
		if result == nil {
			t.Fatal("tree should not be nil")
		}

		// any_policy should be expanded to policy1 and policy2
		nodes := result.AtDepth(1)
		foundPolicy1 := false
		foundPolicy2 := false
		foundAnyPolicy := false

		for _, node := range nodes {
			switch node.ValidPolicy {
			case "policy1":
				foundPolicy1 = true
			case "policy2":
				foundPolicy2 = true
			case AnyPolicy:
				foundAnyPolicy = true
			}
		}

		if foundAnyPolicy {
			t.Error("any_policy should have been removed")
		}
		if !foundPolicy1 || !foundPolicy2 {
			t.Error("acceptable policies should be present")
		}
	})
}

func TestCollectValidPolicies(t *testing.T) {
	tree := InitPolicyTree(AnyPolicy, nil, map[string]bool{AnyPolicy: true})
	tree.Children[0].AddChild("policy1", nil, map[string]bool{"policy1": true})
	tree.Children[0].AddChild("policy2", nil, map[string]bool{"policy2": true})
	tree.Children[0].AddChild(AnyPolicy, nil, map[string]bool{AnyPolicy: true})

	policies := CollectValidPolicies(tree, 1)

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	if !policies["policy1"] || !policies["policy2"] {
		t.Error("expected policy1 and policy2")
	}

	if policies[AnyPolicy] {
		t.Error("any_policy should not be in collected policies")
	}
}

func TestPolicyTreeIsEmpty(t *testing.T) {
	t.Run("nil tree", func(t *testing.T) {
		if !PolicyTreeIsEmpty(nil) {
			t.Error("nil tree should be empty")
		}
	})

	t.Run("empty tree", func(t *testing.T) {
		tree := NewPolicyTreeRoot()
		if !PolicyTreeIsEmpty(tree) {
			t.Error("tree with no children should be empty")
		}
	})

	t.Run("non-empty tree", func(t *testing.T) {
		tree := InitPolicyTree(AnyPolicy, nil, nil)
		if PolicyTreeIsEmpty(tree) {
			t.Error("tree with children should not be empty")
		}
	})
}

func TestPolicyQualifier(t *testing.T) {
	pq := PolicyQualifier{
		PolicyQualifierID: "1.2.3.4",
		Qualifier:         "test qualifier",
	}

	if pq.PolicyQualifierID != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", pq.PolicyQualifierID)
	}
}

func TestCertificatePolicy(t *testing.T) {
	cp := CertificatePolicy{
		PolicyIdentifier: "2.5.29.32.0",
		PolicyQualifiers: []PolicyQualifier{
			{PolicyQualifierID: "1.2.3.4", Qualifier: "test"},
		},
	}

	if cp.PolicyIdentifier != AnyPolicy {
		t.Errorf("expected %s, got %s", AnyPolicy, cp.PolicyIdentifier)
	}

	if len(cp.PolicyQualifiers) != 1 {
		t.Errorf("expected 1 qualifier, got %d", len(cp.PolicyQualifiers))
	}
}

func TestPolicyMapping(t *testing.T) {
	pm := PolicyMapping{
		IssuerDomainPolicy:  "policy1",
		SubjectDomainPolicy: "policy2",
	}

	if pm.IssuerDomainPolicy != "policy1" {
		t.Errorf("expected policy1, got %s", pm.IssuerDomainPolicy)
	}
	if pm.SubjectDomainPolicy != "policy2" {
		t.Errorf("expected policy2, got %s", pm.SubjectDomainPolicy)
	}
}

func TestPolicyTreeNodeExpectedPolicySet(t *testing.T) {
	root := NewPolicyTreeRoot()
	expected := map[string]bool{"policy1": true, "policy2": true}
	child := root.AddChild("test", nil, expected)

	if !child.ExpectedPolicySet["policy1"] {
		t.Error("expected policy1 in set")
	}
	if !child.ExpectedPolicySet["policy2"] {
		t.Error("expected policy2 in set")
	}
	if child.ExpectedPolicySet["policy3"] {
		t.Error("policy3 should not be in set")
	}
}
