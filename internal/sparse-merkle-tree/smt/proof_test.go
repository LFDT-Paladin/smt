// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smt

import (
	"math/big"
	"testing"

	"github.com/LFDT-Paladin/smt/internal/crypto/hash"
	"github.com/LFDT-Paladin/smt/internal/sparse-merkle-tree/node"
	"github.com/LFDT-Paladin/smt/internal/sparse-merkle-tree/utils"
	"github.com/LFDT-Paladin/smt/pkg/sparse-merkle-tree/core"
	"github.com/stretchr/testify/assert"
)

func TestMarkNonEmptySibling(t *testing.T) {
	p := &proof{}
	for i := 0; i < 256; i++ {
		p.MarkNonEmptySibling(uint(i))
	}
	expected := make([]byte, 32)
	for i := 0; i < 32; i++ {
		expected[i] = 0xff
	}
	assert.Equal(t, p.nonEmptySiblings, expected)
}

func TestIsBitOnBigEndian(t *testing.T) {
	p := &proof{}
	expected := make([]byte, 32)
	for i := 0; i < 32; i++ {
		expected[i] = 0xff
	}
	p.nonEmptySiblings = expected
	for i := 0; i < 256; i++ {
		assert.True(t, isBitOnBigEndian(p.nonEmptySiblings, uint(i)))
	}
}

func TestMarkAndCheck(t *testing.T) {
	p := &proof{}
	p.MarkNonEmptySibling(0)
	p.MarkNonEmptySibling(10)
	p.MarkNonEmptySibling(136)
	assert.True(t, p.IsNonEmptySibling(0))
	assert.False(t, p.IsNonEmptySibling(1))
	assert.False(t, p.IsNonEmptySibling(2))
	assert.False(t, p.IsNonEmptySibling(3))
	assert.False(t, p.IsNonEmptySibling(4))
	assert.False(t, p.IsNonEmptySibling(5))
	assert.False(t, p.IsNonEmptySibling(6))
	assert.False(t, p.IsNonEmptySibling(7))
	assert.False(t, p.IsNonEmptySibling(8))
	assert.False(t, p.IsNonEmptySibling(9))
	assert.True(t, p.IsNonEmptySibling(10))
	assert.False(t, p.IsNonEmptySibling(55))
	assert.True(t, p.IsNonEmptySibling(136))
	assert.False(t, p.IsNonEmptySibling(137))
}

func TestProof_Getters(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	leaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), big.NewInt(123))

	p := &proof{
		existence:    true,
		siblings:     []core.NodeRef{idx},
		depth:        5,
		existingNode: leaf,
		hasher:       hasher,
	}

	assert.True(t, p.IsExistenceProof())
	assert.Equal(t, []core.NodeRef{idx}, p.Siblings())
	assert.Equal(t, uint(5), p.Depth())
	assert.Equal(t, leaf, p.ExistingNode())

	// Test non-existence proof
	p2 := &proof{
		existence:    false,
		siblings:     []core.NodeRef{idx},
		depth:        3,
		existingNode: nil,
		hasher:       hasher,
	}

	assert.False(t, p2.IsExistenceProof())
	assert.Nil(t, p2.ExistingNode())
}

func TestAllSiblings(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), hasher)
	idx3, _ := node.NewNodeIndexFromBigInt(big.NewInt(3), hasher)

	p := &proof{
		depth:    5,
		siblings: []core.NodeRef{idx1, idx2, idx3},
		hasher:   hasher,
	}

	// Mark siblings at levels 0, 2, and 4 as non-empty
	p.MarkNonEmptySibling(0)
	p.MarkNonEmptySibling(2)
	p.MarkNonEmptySibling(4)

	allSiblings := p.AllSiblings()
	assert.Len(t, allSiblings, 5)
	assert.Equal(t, idx1, allSiblings[0])            // level 0
	assert.Equal(t, node.ZERO_INDEX, allSiblings[1]) // level 1 (empty)
	assert.Equal(t, idx2, allSiblings[2])            // level 2
	assert.Equal(t, node.ZERO_INDEX, allSiblings[3]) // level 3 (empty)
	assert.Equal(t, idx3, allSiblings[4])            // level 4
}

func TestAllSiblings_AllEmpty(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	p := &proof{
		depth:            3,
		siblings:         []core.NodeRef{},
		nonEmptySiblings: make([]byte, 1), // Initialize bitmap to avoid panic
		hasher:           hasher,
	}

	allSiblings := p.AllSiblings()
	assert.Len(t, allSiblings, 3)
	for i := 0; i < 3; i++ {
		assert.Equal(t, node.ZERO_INDEX, allSiblings[i])
	}
}

func TestAllSiblings_AllNonEmpty(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), hasher)
	idx3, _ := node.NewNodeIndexFromBigInt(big.NewInt(3), hasher)

	p := &proof{
		depth:    3,
		siblings: []core.NodeRef{idx1, idx2, idx3},
		hasher:   hasher,
	}

	// Mark all siblings as non-empty
	p.MarkNonEmptySibling(0)
	p.MarkNonEmptySibling(1)
	p.MarkNonEmptySibling(2)

	allSiblings := p.AllSiblings()
	assert.Len(t, allSiblings, 3)
	assert.Equal(t, idx1, allSiblings[0])
	assert.Equal(t, idx2, allSiblings[1])
	assert.Equal(t, idx3, allSiblings[2])
}

func TestToCircomVerifierProof_ExistenceProof(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence:    true,
		siblings:     []core.NodeRef{idx},
		depth:        3,
		existingNode: nil,
		hasher:       hasher,
	}

	// Mark sibling at level 0 as non-empty
	p.MarkNonEmptySibling(0)

	cp, err := p.ToCircomVerifierProof(big.NewInt(10), big.NewInt(123), root, 64)
	assert.NoError(t, err)
	assert.NotNil(t, cp)
	assert.Equal(t, root, cp.Root)
	assert.Equal(t, 0, cp.Fnc) // inclusion
	assert.NotNil(t, cp.Key)
	assert.NotNil(t, cp.Value)
	assert.Equal(t, node.ZERO_INDEX, cp.OldKey)
	assert.Equal(t, big.NewInt(0), cp.OldValue)
}

func TestToCircomVerifierProof_NonExistenceProof(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	existingLeaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), big.NewInt(456))
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence:    false,
		siblings:     []core.NodeRef{idx},
		depth:        3,
		existingNode: existingLeaf,
		hasher:       hasher,
	}

	// Mark sibling at level 0 as non-empty
	p.MarkNonEmptySibling(0)

	cp, err := p.ToCircomVerifierProof(big.NewInt(20), big.NewInt(789), root, 64)
	assert.NoError(t, err)
	assert.NotNil(t, cp)
	assert.Equal(t, root, cp.Root)
	assert.Equal(t, 1, cp.Fnc) // non-inclusion
	assert.Equal(t, existingLeaf.Index(), cp.OldKey)
	assert.Equal(t, big.NewInt(456), cp.OldValue)
}

func TestToCircomVerifierProof_ExistingNodeWithNilValue(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	existingLeaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), nil) // nil value
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence:    false,
		siblings:     []core.NodeRef{idx},
		depth:        3,
		existingNode: existingLeaf,
		hasher:       hasher,
	}

	// Mark sibling at level 0 as non-empty
	p.MarkNonEmptySibling(0)

	cp, err := p.ToCircomVerifierProof(big.NewInt(20), big.NewInt(789), root, 64)
	assert.NoError(t, err)
	assert.NotNil(t, cp)
	// OldValue should be the index when value is nil
	assert.Equal(t, idx.BigInt(), cp.OldValue)
}

func TestToCircomVerifierProof_ErrorInvalidKey(t *testing.T) {
	hasher := &hash.Keccak256Hasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	p := &proof{
		existence: true,
		siblings:  []core.NodeRef{idx},
		depth:     3,
		hasher:    hasher,
	}

	// Mark sibling at level 0 as non-empty so AllSiblings() works
	p.MarkNonEmptySibling(0)

	// Use a key that's out of range for Keccak256
	outOfRangeKey := new(big.Int).Lsh(big.NewInt(1), 256)
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	cp, err := p.ToCircomVerifierProof(outOfRangeKey, big.NewInt(123), root, 64)
	assert.Error(t, err)
	assert.Nil(t, cp)
}

func TestToCircomVerifierProof_ErrorInvalidValue(t *testing.T) {
	hasher := &hash.Keccak256Hasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	p := &proof{
		existence: true,
		siblings:  []core.NodeRef{idx},
		depth:     3,
		hasher:    hasher,
	}

	// Mark sibling at level 0 as non-empty so AllSiblings() works
	p.MarkNonEmptySibling(0)

	// Use a value that's out of range for Keccak256
	outOfRangeValue := new(big.Int).Lsh(big.NewInt(1), 256)
	key := big.NewInt(10)
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	cp, err := p.ToCircomVerifierProof(key, outOfRangeValue, root, 64)
	assert.Error(t, err)
	assert.Nil(t, cp)
}

func TestToCircomVerifierProof_PadsSiblings(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence: true,
		siblings:  []core.NodeRef{idx},
		depth:     3,
		hasher:    hasher,
	}

	// Mark sibling at level 0 as non-empty
	p.MarkNonEmptySibling(0)

	cp, err := p.ToCircomVerifierProof(big.NewInt(10), big.NewInt(123), root, 64)
	assert.NoError(t, err)
	assert.NotNil(t, cp)
	// Should pad siblings to levels+1 (65 in this case)
	assert.Len(t, cp.Siblings, 65)
	// First sibling should be from the proof, rest should be ZERO_INDEX
	assert.Equal(t, idx, cp.Siblings[0])
	for i := 1; i < 65; i++ {
		assert.Equal(t, node.ZERO_INDEX, cp.Siblings[i])
	}
}

func TestVerifyProof_InvalidProof(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	leaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), big.NewInt(123))
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	// Create a proof that doesn't match
	p := &proof{
		existence: true,
		siblings:  []core.NodeRef{},
		depth:     0,
		hasher:    hasher,
	}

	valid := VerifyProof(root, p, leaf)
	assert.False(t, valid)
}

func TestVerifyProof_NonExistenceWithMatchingIndex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	existingLeaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), big.NewInt(456))
	// Create a leaf with the same index
	leaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), big.NewInt(123))
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence:    false,
		siblings:     []core.NodeRef{},
		depth:        0,
		existingNode: existingLeaf,
		hasher:       hasher,
	}

	// This should fail because the leaf index matches the existing node index
	valid := VerifyProof(root, p, leaf)
	assert.False(t, valid)
}

func TestVerifyProof_NonExistenceWithNilExistingNode(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	leaf, _ := node.NewLeafNode(utils.NewIndexOnly(idx), big.NewInt(123))
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence:    false,
		siblings:     []core.NodeRef{},
		depth:        0,
		existingNode: nil,
		hasher:       hasher,
	}

	// This should work - non-existence proof with no existing node
	// May be false if root doesn't match, but shouldn't panic
	assert.NotPanics(t, func() {
		_ = VerifyProof(root, p, leaf)
	})
}

func TestMarkNonEmptySibling_Resize(t *testing.T) {
	p := &proof{
		nonEmptySiblings: make([]byte, 1),
	}

	// Mark a bit that requires resizing
	p.MarkNonEmptySibling(10)
	assert.True(t, p.IsNonEmptySibling(10))
	assert.GreaterOrEqual(t, len(p.nonEmptySiblings), 2)
}

func TestMarkNonEmptySibling_EmptyBitmap(t *testing.T) {
	p := &proof{
		nonEmptySiblings: nil,
	}

	// Mark a bit when bitmap is empty
	p.MarkNonEmptySibling(5)
	assert.True(t, p.IsNonEmptySibling(5))
	assert.GreaterOrEqual(t, len(p.nonEmptySiblings), 1)
}

func TestIsBitOnBigEndian_EdgeCases(t *testing.T) {
	bitmap := make([]byte, 4)

	// Test bit 0
	setBitBigEndian(bitmap, 0)
	assert.True(t, isBitOnBigEndian(bitmap, 0))

	// Test bit 7 (last bit of first byte)
	setBitBigEndian(bitmap, 7)
	assert.True(t, isBitOnBigEndian(bitmap, 7))

	// Test bit 8 (first bit of second byte)
	setBitBigEndian(bitmap, 8)
	assert.True(t, isBitOnBigEndian(bitmap, 8))

	// Test unset bit
	assert.False(t, isBitOnBigEndian(bitmap, 1))
}

func TestSetBitBigEndian(t *testing.T) {
	bitmap := make([]byte, 2)

	// Set various bits
	setBitBigEndian(bitmap, 0)
	setBitBigEndian(bitmap, 3)
	setBitBigEndian(bitmap, 7)
	setBitBigEndian(bitmap, 10)
	setBitBigEndian(bitmap, 15)

	// Verify all are set
	assert.True(t, isBitOnBigEndian(bitmap, 0))
	assert.True(t, isBitOnBigEndian(bitmap, 3))
	assert.True(t, isBitOnBigEndian(bitmap, 7))
	assert.True(t, isBitOnBigEndian(bitmap, 10))
	assert.True(t, isBitOnBigEndian(bitmap, 15))

	// Verify unset bits are false
	assert.False(t, isBitOnBigEndian(bitmap, 1))
	assert.False(t, isBitOnBigEndian(bitmap, 2))
	assert.False(t, isBitOnBigEndian(bitmap, 4))
}

// TestCalculateRootFromProof_ErrorPath - Error paths in calculateRootFromProof
// are tested indirectly through VerifyProof tests. The error case where
// NewBranchNode fails is difficult to test without a custom hasher that
// can be made to fail, which is complex to implement.

func TestAllSiblings_WithDepthZero(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	p := &proof{
		depth:            0,
		siblings:         []core.NodeRef{},
		nonEmptySiblings: make([]byte, 1), // Initialize bitmap to avoid panic
		hasher:           hasher,
	}

	allSiblings := p.AllSiblings()
	assert.Len(t, allSiblings, 0)
}

func TestToCircomVerifierProof_WithMoreSiblingsThanDepth(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), hasher)
	root, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)

	p := &proof{
		existence: true,
		siblings:  []core.NodeRef{idx1, idx2},
		depth:     1, // depth is 1 but we have 2 siblings
		hasher:    hasher,
	}

	p.MarkNonEmptySibling(0)
	p.MarkNonEmptySibling(1) // This is beyond depth, but let's test

	cp, err := p.ToCircomVerifierProof(big.NewInt(10), big.NewInt(123), root, 64)
	// This should work, AllSiblings will only use depth number of levels
	assert.NoError(t, err)
	assert.NotNil(t, cp)
}
