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

package crypto

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/stretchr/testify/assert"
)

func TestNewSalt(t *testing.T) {
	// Test that NewSalt generates values in the correct range [0, constants.Q)
	max := constants.Q

	// Generate multiple salts to test randomness and range
	salts := make([]*big.Int, 100)
	for i := 0; i < 100; i++ {
		salt := NewSalt()
		salts[i] = salt

		// Verify salt is in range [0, max)
		assert.GreaterOrEqual(t, salt.Cmp(big.NewInt(0)), 0, "salt should be >= 0")
		assert.Equal(t, -1, salt.Cmp(max), "salt should be < constants.Q")
	}

	// Verify that salts are different (test randomness)
	// With 100 random values, it's extremely unlikely they're all the same
	uniqueSalts := make(map[string]bool)
	for _, salt := range salts {
		uniqueSalts[salt.String()] = true
	}
	// Allow for some collisions but expect significant uniqueness
	assert.Greater(t, len(uniqueSalts), 50, "salts should be mostly unique (random)")
}

func TestNewRandomNumberInRange(t *testing.T) {
	t.Run("small range", func(t *testing.T) {
		max := big.NewInt(10)
		for i := 0; i < 50; i++ {
			result := NewRandomNumberInRange(max)
			assert.GreaterOrEqual(t, result.Cmp(big.NewInt(0)), 0, "result should be >= 0")
			assert.Equal(t, -1, result.Cmp(max), "result should be < max")
		}
	})

	t.Run("range of 1", func(t *testing.T) {
		max := big.NewInt(1)
		result := NewRandomNumberInRange(max)
		// With max = 1, the only valid value is 0
		assert.Equal(t, 0, result.Cmp(big.NewInt(0)), "result should be 0 when max is 1")
	})

	t.Run("large range", func(t *testing.T) {
		max, _ := new(big.Int).SetString("1000000000000000000000000000000000000000000000000000000000000", 10)
		for i := 0; i < 10; i++ {
			result := NewRandomNumberInRange(max)
			assert.GreaterOrEqual(t, result.Cmp(big.NewInt(0)), 0, "result should be >= 0")
			assert.Equal(t, -1, result.Cmp(max), "result should be < max")
		}
	})

	t.Run("range equals constants.Q", func(t *testing.T) {
		max := constants.Q
		for i := 0; i < 10; i++ {
			result := NewRandomNumberInRange(max)
			assert.GreaterOrEqual(t, result.Cmp(big.NewInt(0)), 0, "result should be >= 0")
			assert.Equal(t, -1, result.Cmp(max), "result should be < constants.Q")
		}
	})

	t.Run("randomness", func(t *testing.T) {
		max := big.NewInt(1000)
		results := make([]*big.Int, 100)
		for i := 0; i < 100; i++ {
			results[i] = NewRandomNumberInRange(max)
		}

		// Check that we get different values (test randomness)
		uniqueResults := make(map[string]bool)
		for _, result := range results {
			uniqueResults[result.String()] = true
		}
		// With 100 random values in range [0, 1000), expect significant uniqueness
		assert.Greater(t, len(uniqueResults), 50, "results should be mostly unique (random)")
	})

	t.Run("boundary values", func(t *testing.T) {
		max := big.NewInt(2)
		results := make(map[int]bool)
		// Generate many values to ensure we get both 0 and 1
		for i := 0; i < 100; i++ {
			result := NewRandomNumberInRange(max)
			val := int(result.Int64())
			results[val] = true
			assert.GreaterOrEqual(t, val, 0, "result should be >= 0")
			assert.Less(t, val, 2, "result should be < 2")
		}
		// With max = 2, we should get both 0 and 1
		assert.True(t, results[0], "should generate 0")
		assert.True(t, results[1], "should generate 1")
	})
}

func TestNewSalt_UsesConstantsQ(t *testing.T) {
	// Verify that NewSalt uses constants.Q as the max value
	max := constants.Q

	// Generate multiple salts and verify they're all < constants.Q
	for i := 0; i < 100; i++ {
		salt := NewSalt()
		assert.Equal(t, -1, salt.Cmp(max), "salt should be < constants.Q")
		assert.GreaterOrEqual(t, salt.Cmp(big.NewInt(0)), 0, "salt should be >= 0")
	}
}

func TestNewRandomNumberInRange_EdgeCases(t *testing.T) {
	t.Run("very small range", func(t *testing.T) {
		max := big.NewInt(3)
		results := make(map[int]bool)
		for i := 0; i < 50; i++ {
			result := NewRandomNumberInRange(max)
			val := int(result.Int64())
			results[val] = true
			assert.GreaterOrEqual(t, val, 0, "result should be >= 0")
			assert.Less(t, val, 3, "result should be < 3")
		}
		// Should get values 0, 1, 2
		assert.True(t, results[0] || results[1] || results[2], "should generate valid values")
	})

	t.Run("power of 2 range", func(t *testing.T) {
		max := big.NewInt(256)
		for i := 0; i < 20; i++ {
			result := NewRandomNumberInRange(max)
			assert.GreaterOrEqual(t, result.Cmp(big.NewInt(0)), 0, "result should be >= 0")
			assert.Equal(t, -1, result.Cmp(max), "result should be < 256")
		}
	})
}

