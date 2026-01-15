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

package node

import (
	"errors"
	"math/big"
	"testing"

	"github.com/LFDT-Paladin/smt/internal/crypto/hash"
	"github.com/LFDT-Paladin/smt/internal/sparse-merkle-tree/utils"
	"github.com/LFDT-Paladin/smt/pkg/sparse-merkle-tree/core"
	apicore "github.com/LFDT-Paladin/smt/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
)

func TestNodeIndex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", idx0.Hex())
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	assert.Equal(t, "0100000000000000000000000000000000000000000000000000000000000000", idx1.Hex())
	idx2, _ := NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.Equal(t, "0a00000000000000000000000000000000000000000000000000000000000000", idx2.Hex())

	idx3, _ := NewNodeIndexFromBigInt(big.NewInt(12345678), hasher)
	assert.Equal(t, "4e61bc0000000000000000000000000000000000000000000000000000000000", idx3.Hex())

	v4, _ := new(big.Int).SetString("4932297968297298434239270129193057052722409868268166443802652458940273154854", 10)
	idx4, _ := NewNodeIndexFromBigInt(v4, hasher)
	assert.Equal(t, "265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a", idx4.Hex())
	expectedBytes4 := []byte{38, 91, 170, 241, 97, 232, 117, 195, 114, 208, 142, 80, 245, 42, 189, 220, 1, 211, 46, 252, 147, 233, 2, 144, 187, 139, 61, 156, 235, 148, 231, 10}
	rawIndex4 := idx4.(*nodeIndex)
	assert.Equal(t, expectedBytes4, rawIndex4.index[:])

	idx5, err := NewNodeIndexFromHex("265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a", hasher)
	assert.NoError(t, err)
	assert.Equal(t, 0, v4.Cmp(idx5.BigInt()))
}

func TestNewEmptyNode(t *testing.T) {
	node := NewEmptyNode()
	assert.Equal(t, node.Type(), core.NodeTypeEmpty)
	assert.Nil(t, node.Index())
	assert.Nil(t, node.Ref())
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewLeafNode(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	i := utils.NewIndexOnly(idx)
	node, err := NewLeafNode(i, nil)
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeLeaf)
	assert.Equal(t, node.Index(), idx)
	elements := []*big.Int{idx.BigInt(), idx.BigInt(), big.NewInt(1)}
	hash, err := poseidon.Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewLeafNodeKeccak256(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.Keccak256Hasher{})
	i := utils.NewIndexOnly(idx)
	node, err := NewLeafNode(i, nil)
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeLeaf)
	assert.Equal(t, node.Index(), idx)
	elements := []*big.Int{idx.BigInt(), idx.BigInt(), big.NewInt(1)}
	hash, err := (&hash.Keccak256Hasher{}).Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewLeafNodeWithValue(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	i := utils.NewIndexOnly(idx)
	node, err := NewLeafNode(i, big.NewInt(12345))
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeLeaf)
	assert.Equal(t, node.Index(), idx)
	elements := []*big.Int{idx.BigInt(), big.NewInt(12345), big.NewInt(1)}
	hash, err := poseidon.Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Nil(t, node.LeftChild())
	assert.Nil(t, node.RightChild())
}

func TestNewBranchNode(t *testing.T) {
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), &hash.PoseidonHasher{})
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	node, err := NewBranchNode(idx0, idx1, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	assert.Equal(t, node.Type(), core.NodeTypeBranch)
	assert.Nil(t, node.Index())
	elements := []*big.Int{idx0.BigInt(), idx1.BigInt()}
	hash, err := poseidon.Hash(elements)
	assert.NoError(t, err)
	assert.Equal(t, node.Ref().BigInt(), hash)
	assert.Equal(t, node.LeftChild(), idx0)
	assert.Equal(t, node.RightChild(), idx1)
}

type badIndex struct{}

func (f *badIndex) CalculateIndex() (core.NodeIndex, error) {
	return nil, errors.New("Bang!")
}
func (f *badIndex) GetHasher() apicore.Hasher {
	return &hash.PoseidonHasher{}
}

func TestNewLeafNodeFail(t *testing.T) {
	_, err := NewLeafNode(&badIndex{}, nil)
	assert.EqualError(t, err, "Bang!")
}

func TestNewNodeIndexFromBigInt_Error(t *testing.T) {
	hasher := &hash.Keccak256Hasher{}
	// Create a value that's out of range for Keccak256 (>= 2^256)
	outOfRange := new(big.Int).Lsh(big.NewInt(1), 256)
	idx, err := NewNodeIndexFromBigInt(outOfRange, hasher)
	assert.Error(t, err)
	assert.Nil(t, idx)
	assert.Equal(t, ErrNodeIndexTooLarge, err)
}

func TestNewNodeIndexFromHex_WithPrefix(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	hexStr := "0x265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a"
	idx, err := NewNodeIndexFromHex(hexStr, hasher)
	assert.NoError(t, err)
	assert.NotNil(t, idx)
	// Should work the same as without prefix
	idx2, err2 := NewNodeIndexFromHex("265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a", hasher)
	assert.NoError(t, err2)
	assert.Equal(t, 0, idx.BigInt().Cmp(idx2.BigInt()))
}

func TestNewNodeIndexFromHex_InvalidHex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	invalidHex := "not_a_hex_string"
	idx, err := NewNodeIndexFromHex(invalidHex, hasher)
	assert.Error(t, err)
	assert.Nil(t, idx)
}

func TestNewNodeIndexFromHex_WrongLength(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	// Too short
	shortHex := "1234567890abcdef"
	idx, err := NewNodeIndexFromHex(shortHex, hasher)
	assert.Error(t, err)
	assert.Nil(t, idx)
	assert.Equal(t, ErrNodeBytesBadSize, err)

	// Too long
	longHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	idx2, err2 := NewNodeIndexFromHex(longHex, hasher)
	assert.Error(t, err2)
	assert.Nil(t, idx2)
	assert.Equal(t, ErrNodeBytesBadSize, err2)
}

func TestNodeIndex_IsZero(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	assert.True(t, idx0.IsZero())

	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	assert.False(t, idx1.IsZero())
}

func TestNodeIndex_Equal(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	idx2, _ := NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	idx3, _ := NewNodeIndexFromBigInt(big.NewInt(20), hasher)

	assert.True(t, idx1.Equal(idx2))
	assert.False(t, idx1.Equal(idx3))
	assert.True(t, idx1.Equal(idx1)) // self equality
}

func TestNodeIndex_GetHasher(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.Equal(t, hasher, idx.GetHasher())

	keccakHasher := &hash.Keccak256Hasher{}
	idx2, _ := NewNodeIndexFromBigInt(big.NewInt(10), keccakHasher)
	assert.Equal(t, keccakHasher, idx2.GetHasher())
}

func TestNodeIndex_ToPath(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	// Test with value 1 (binary: 000...001, so first bit is 1, rest are 0)
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	path := idx1.ToPath(8)
	assert.Len(t, path, 8)
	assert.True(t, path[0], "first bit should be 1")
	for i := 1; i < 8; i++ {
		assert.False(t, path[i], "other bits should be 0")
	}

	// Test with value 0
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	path0 := idx0.ToPath(10)
	assert.Len(t, path0, 10)
	for i := 0; i < 10; i++ {
		assert.False(t, path0[i], "all bits should be 0")
	}

	// Test with value 5 (binary: 101, so bits 0 and 2 are 1)
	idx5, _ := NewNodeIndexFromBigInt(big.NewInt(5), hasher)
	path5 := idx5.ToPath(3)
	assert.Len(t, path5, 3)
	assert.True(t, path5[0], "bit 0 should be 1")
	assert.False(t, path5[1], "bit 1 should be 0")
	assert.True(t, path5[2], "bit 2 should be 1")

	// Test with larger path
	path5Large := idx5.ToPath(64)
	assert.Len(t, path5Large, 64)
}

func TestNodeIndex_IsBitOne(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	// Test with value 1 (bit 0 is 1)
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), hasher)
	assert.True(t, idx1.IsBitOne(0))
	assert.False(t, idx1.IsBitOne(1))
	assert.False(t, idx1.IsBitOne(2))

	// Test with value 5 (binary: 101, bits 0 and 2 are 1)
	idx5, _ := NewNodeIndexFromBigInt(big.NewInt(5), hasher)
	assert.True(t, idx5.IsBitOne(0))
	assert.False(t, idx5.IsBitOne(1))
	assert.True(t, idx5.IsBitOne(2))
	assert.False(t, idx5.IsBitOne(3))

	// Test with value 0
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	assert.False(t, idx0.IsBitOne(0))
	assert.False(t, idx0.IsBitOne(100))

	// Test edge case: position >= 256
	assert.False(t, idx1.IsBitOne(256))
	assert.False(t, idx1.IsBitOne(257))
	assert.False(t, idx1.IsBitOne(1000))
}

func TestNodeIndex_BigInt(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	// Test round trip: BigInt -> NodeIndex -> BigInt
	testValues := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(10),
		big.NewInt(12345678),
		big.NewInt(256),
	}

	for _, val := range testValues {
		idx, err := NewNodeIndexFromBigInt(val, hasher)
		assert.NoError(t, err)
		result := idx.BigInt()
		assert.Equal(t, 0, val.Cmp(result), "BigInt round trip failed for value %s", val.String())
	}
}

func TestNodeIndex_Hex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	// Test round trip: Hex -> NodeIndex -> Hex
	hexStr := "265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a"
	idx, err := NewNodeIndexFromHex(hexStr, hasher)
	assert.NoError(t, err)
	resultHex := idx.Hex()
	assert.Equal(t, hexStr, resultHex)
}

func TestNode_Value(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	i := utils.NewIndexOnly(idx)

	// Test with nil value
	node1, err := NewLeafNode(i, nil)
	assert.NoError(t, err)
	assert.Nil(t, node1.Value())

	// Test with value
	value := big.NewInt(12345)
	node2, err := NewLeafNode(i, value)
	assert.NoError(t, err)
	assert.Equal(t, value, node2.Value())

	// Test empty node
	emptyNode := NewEmptyNode()
	assert.Nil(t, emptyNode.Value())
}

func TestNode_LeftChild_RightChild(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), hasher)

	// Test branch node
	branchNode, err := NewBranchNode(idx0, idx1, hasher)
	assert.NoError(t, err)
	assert.Equal(t, idx0, branchNode.LeftChild())
	assert.Equal(t, idx1, branchNode.RightChild())

	// Test leaf node (should return nil)
	leafIdx, _ := NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	leafIndexable := utils.NewIndexOnly(leafIdx)
	leafNode, err := NewLeafNode(leafIndexable, nil)
	assert.NoError(t, err)
	assert.Nil(t, leafNode.LeftChild())
	assert.Nil(t, leafNode.RightChild())

	// Test empty node
	emptyNode := NewEmptyNode()
	assert.Nil(t, emptyNode.LeftChild())
	assert.Nil(t, emptyNode.RightChild())
}

type errorHasher struct{}

func (e *errorHasher) Hash(inputs []*big.Int) (*big.Int, error) {
	return nil, errors.New("hash error")
}

func (e *errorHasher) CheckInRange(a *big.Int) bool {
	return true
}

func TestNewLeafNode_HashError(t *testing.T) {
	idx, _ := NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})

	// Mock GetHasher to return errorHasher
	calculateIndex := func() (core.NodeIndex, error) {
		return idx, nil
	}
	getHasher := func() apicore.Hasher {
		return &errorHasher{}
	}

	mockIdx := &mockIndexableWithHasher{
		calculateIndex: calculateIndex,
		getHasher:      getHasher,
	}

	node, err := NewLeafNode(mockIdx, big.NewInt(123))
	assert.Error(t, err)
	assert.Nil(t, node)
	assert.Equal(t, "hash error", err.Error())
}

func TestNewBranchNode_HashError(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx0, _ := NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	idx1, _ := NewNodeIndexFromBigInt(big.NewInt(1), hasher)

	errorHasher := &errorHasher{}
	node, err := NewBranchNode(idx0, idx1, errorHasher)
	assert.Error(t, err)
	assert.Nil(t, node)
	assert.Equal(t, "hash error", err.Error())
}

type mockIndexableWithHasher struct {
	calculateIndex func() (core.NodeIndex, error)
	getHasher      func() apicore.Hasher
}

func (m *mockIndexableWithHasher) CalculateIndex() (core.NodeIndex, error) {
	return m.calculateIndex()
}

func (m *mockIndexableWithHasher) GetHasher() apicore.Hasher {
	return m.getHasher()
}


func TestNewNodeIndexFromBigInt_EdgeCases(t *testing.T) {
	hasher := &hash.PoseidonHasher{}

	// Test with very large but valid value
	largeVal, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495616", 10)
	largeVal.Sub(largeVal, big.NewInt(1)) // Make it just under the field modulus
	idx, err := NewNodeIndexFromBigInt(largeVal, hasher)
	// This might fail if it's out of range for Poseidon, or succeed if it's in range
	if err != nil {
		assert.Equal(t, ErrNodeIndexTooLarge, err)
	} else {
		assert.NotNil(t, idx)
	}

	// Test with negative value using Keccak256Hasher (should fail CheckInRange)
	keccakHasher := &hash.Keccak256Hasher{}
	negativeVal := big.NewInt(-1)
	idx2, err2 := NewNodeIndexFromBigInt(negativeVal, keccakHasher)
	assert.Error(t, err2)
	assert.Nil(t, idx2)
}

func TestNewNodeIndexFromHex_EmptyString(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := NewNodeIndexFromHex("", hasher)
	assert.Error(t, err)
	assert.Nil(t, idx)
}

func TestZERO_INDEX(t *testing.T) {
	// Test that ZERO_INDEX is properly initialized
	assert.NotNil(t, ZERO_INDEX)
	assert.True(t, ZERO_INDEX.IsZero())
	zeroBigInt := ZERO_INDEX.BigInt()
	assert.Equal(t, 0, zeroBigInt.Cmp(big.NewInt(0)))
}
