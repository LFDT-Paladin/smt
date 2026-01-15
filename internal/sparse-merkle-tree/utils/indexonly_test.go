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

package utils

import (
	"math/big"
	"testing"

	"github.com/LFDT-Paladin/smt/internal/crypto/hash"
	"github.com/LFDT-Paladin/smt/internal/sparse-merkle-tree/node"
	"github.com/LFDT-Paladin/smt/pkg/sparse-merkle-tree/core"
	"github.com/stretchr/testify/assert"
)

func TestNewIndexOnly(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	assert.NotNil(t, indexOnly)
	assert.Equal(t, idx, indexOnly.Index)
}

func TestIndexOnly_CalculateIndex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(123), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	result, err := indexOnly.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, idx, result)
	assert.Equal(t, idx.BigInt().Cmp(result.BigInt()), 0)
}

func TestIndexOnly_CalculateIndex_MultipleCalls(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(456), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	
	// Call multiple times - should return same result
	result1, err1 := indexOnly.CalculateIndex()
	assert.NoError(t, err1)
	
	result2, err2 := indexOnly.CalculateIndex()
	assert.NoError(t, err2)
	
	assert.Equal(t, result1, result2)
	assert.Equal(t, idx, result1)
	assert.Equal(t, idx, result2)
}

func TestIndexOnly_CalculateIndex_DifferentIndexes(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx1, err := node.NewNodeIndexFromBigInt(big.NewInt(100), hasher)
	assert.NoError(t, err)
	
	idx2, err := node.NewNodeIndexFromBigInt(big.NewInt(200), hasher)
	assert.NoError(t, err)

	indexOnly1 := NewIndexOnly(idx1)
	indexOnly2 := NewIndexOnly(idx2)
	
	result1, err1 := indexOnly1.CalculateIndex()
	assert.NoError(t, err1)
	
	result2, err2 := indexOnly2.CalculateIndex()
	assert.NoError(t, err2)
	
	assert.NotEqual(t, result1.BigInt().Cmp(result2.BigInt()), 0)
	assert.Equal(t, idx1, result1)
	assert.Equal(t, idx2, result2)
}

func TestIndexOnly_GetHasher(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	resultHasher := indexOnly.GetHasher()
	assert.Equal(t, hasher, resultHasher)
}

func TestIndexOnly_GetHasher_Keccak256(t *testing.T) {
	hasher := &hash.Keccak256Hasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	resultHasher := indexOnly.GetHasher()
	assert.Equal(t, hasher, resultHasher)
}

func TestIndexOnly_GetHasher_DifferentHashers(t *testing.T) {
	poseidonHasher := &hash.PoseidonHasher{}
	keccakHasher := &hash.Keccak256Hasher{}
	
	idx1, err := node.NewNodeIndexFromBigInt(big.NewInt(10), poseidonHasher)
	assert.NoError(t, err)
	
	idx2, err := node.NewNodeIndexFromBigInt(big.NewInt(10), keccakHasher)
	assert.NoError(t, err)

	indexOnly1 := NewIndexOnly(idx1)
	indexOnly2 := NewIndexOnly(idx2)
	
	hasher1 := indexOnly1.GetHasher()
	hasher2 := indexOnly2.GetHasher()
	
	assert.NotEqual(t, hasher1, hasher2)
	assert.Equal(t, poseidonHasher, hasher1)
	assert.Equal(t, keccakHasher, hasher2)
}

func TestIndexOnly_CalculateIndex_ZeroIndex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(0), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	result, err := indexOnly.CalculateIndex()
	assert.NoError(t, err)
	assert.True(t, result.IsZero())
	assert.Equal(t, idx, result)
}

func TestIndexOnly_CalculateIndex_LargeIndex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	largeVal, _ := new(big.Int).SetString("4932297968297298434239270129193057052722409868268166443802652458940273154854", 10)
	idx, err := node.NewNodeIndexFromBigInt(largeVal, hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	result, err := indexOnly.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, 0, largeVal.Cmp(result.BigInt()))
	assert.Equal(t, idx, result)
}

func TestIndexOnly_ImplementsIndexable(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	
	// Verify it implements the Indexable interface
	var _ core.Indexable = indexOnly
	
	// Test interface methods
	result, err := indexOnly.CalculateIndex()
	assert.NoError(t, err)
	assert.NotNil(t, result)
	
	hasherResult := indexOnly.GetHasher()
	assert.NotNil(t, hasherResult)
}

func TestIndexOnly_CalculateIndex_Consistency(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(789), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	
	// Calculate index multiple times and verify consistency
	for i := 0; i < 10; i++ {
		result, err := indexOnly.CalculateIndex()
		assert.NoError(t, err)
		assert.Equal(t, idx, result)
		assert.Equal(t, 0, idx.BigInt().Cmp(result.BigInt()))
	}
}

func TestIndexOnly_WithHexIndex(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	hexStr := "265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a"
	idx, err := node.NewNodeIndexFromHex(hexStr, hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	result, err := indexOnly.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), result.Hex())
	assert.Equal(t, idx, result)
}

func TestIndexOnly_GetHasher_ReturnsSameInstance(t *testing.T) {
	hasher := &hash.PoseidonHasher{}
	idx, err := node.NewNodeIndexFromBigInt(big.NewInt(10), hasher)
	assert.NoError(t, err)

	indexOnly := NewIndexOnly(idx)
	
	// Get hasher multiple times - should return same instance
	hasher1 := indexOnly.GetHasher()
	hasher2 := indexOnly.GetHasher()
	
	assert.Equal(t, hasher1, hasher2)
	assert.Equal(t, hasher, hasher1)
}
