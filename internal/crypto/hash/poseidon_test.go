// Copyright © 2025 Kaleido, Inc.
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

package hash

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
)

func TestPoseidonHasher_Hash_MultipleInputs1(t *testing.T) {
	hasher := &PoseidonHasher{}
	v1, _ := new(big.Int).SetString("20349940423862035287868699599764962454537984981628200184279725786303353984557", 10)
	v2, _ := new(big.Int).SetString("10955310555638083816119775899206389561202556659568675876759181443512300421331", 10)
	inputs := []*big.Int{
		v1,
		v2,
	}

	result, err := hasher.Hash(inputs)
	if err != nil {
		t.Fatalf("Hash() failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil hash result")
	}

	// Verify the result matches direct poseidon.Hash call
	expected, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatalf("poseidon.Hash() failed: %v", err)
	}
	assert.Equal(t, expected, result)
}

func TestPoseidonHasher_Hash_MultipleInputs2(t *testing.T) {
	hasher := &PoseidonHasher{}
	v1 := big.NewInt(10)
	v2, _ := new(big.Int).SetString("43c49e8ba68a9b8a6bb5c230a734d8271a83d2f63722e7651272ebeef5446e", 16)
	v3, _ := new(big.Int).SetString("9198063289874244593808956064764348354864043212453245695133881114917754098693", 10)
	v4, _ := new(big.Int).SetString("3600411115173311692823743444460566395943576560299970643507632418781961416843", 10)

	inputs := []*big.Int{
		v1,
		v2,
		v3,
		v4,
	}

	result, err := hasher.Hash(inputs)
	if err != nil {
		t.Fatalf("Hash() failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil hash result")
	}

	// Verify the result matches direct poseidon.Hash call
	expected, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatalf("poseidon.Hash() failed: %v", err)
	}
	assert.Equal(t, expected, result)
}

func TestPoseidonHasher_Hash_SingleInput(t *testing.T) {
	hasher := &PoseidonHasher{}
	inputs := []*big.Int{big.NewInt(12345)}

	result, err := hasher.Hash(inputs)
	if err != nil {
		t.Fatalf("Hash() with single input failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil hash result for single input")
	}

	// Verify the result matches direct poseidon.Hash call
	expected, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatalf("poseidon.Hash() failed: %v", err)
	}
	assert.Equal(t, expected, result)
}

func TestPoseidonHasher_Hash_ZeroValue(t *testing.T) {
	hasher := &PoseidonHasher{}
	inputs := []*big.Int{big.NewInt(0)}

	result, err := hasher.Hash(inputs)
	if err != nil {
		t.Fatalf("Hash() with zero value failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil hash result for zero input")
	}

	// Verify the result matches direct poseidon.Hash call
	expected, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatalf("poseidon.Hash() failed: %v", err)
	}
	assert.Equal(t, expected, result)
}

func TestPoseidonHasher_Hash_EmptySlice(t *testing.T) {
	hasher := &PoseidonHasher{}
	inputs := []*big.Int{}

	result, err := hasher.Hash(inputs)
	// Poseidon hash requires at least 1 input, so empty slice should return an error
	if err == nil {
		t.Fatal("Hash() with empty slice should have returned an error")
	}

	if result != nil {
		t.Fatal("expected nil hash result for empty slice when error occurs")
	}

	// Verify the error matches direct poseidon.Hash call
	_, expectedErr := poseidon.Hash(inputs)
	assert.Error(t, expectedErr)
	assert.Error(t, err)
}

func TestPoseidonHasher_Hash_LargeNumbers(t *testing.T) {
	hasher := &PoseidonHasher{}

	// Use a large number that's still within the Poseidon field
	largeNum, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495616", 10)
	// Subtract 1 to ensure it's within the field
	largeNum.Sub(largeNum, big.NewInt(1))

	inputs := []*big.Int{largeNum}

	result, err := hasher.Hash(inputs)
	if err != nil {
		t.Fatalf("Hash() with large number failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil hash result for large number")
	}

	// Verify the result matches direct poseidon.Hash call
	expected, err := poseidon.Hash(inputs)
	if err != nil {
		t.Fatalf("poseidon.Hash() failed: %v", err)
	}
	assert.Equal(t, expected, result)
}

func TestPoseidonHasher_CheckInRange(t *testing.T) {
	hasher := &PoseidonHasher{}

	// Test with a value in range (small value)
	inRange := new(big.Int).SetUint64(1234567890)
	if !hasher.CheckInRange(inRange) {
		t.Errorf("CheckInRange() failed for in-range value: %s", inRange.String())
	}

	// Test with zero (should be in range)
	zero := big.NewInt(0)
	if !hasher.CheckInRange(zero) {
		t.Errorf("CheckInRange() failed for zero: %s", zero.String())
	}

	// Test with a value at the field boundary (field modulus - 1)
	// The Poseidon field modulus is approximately 2^254
	fieldModulus, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	atBoundary := new(big.Int).Sub(fieldModulus, big.NewInt(1))
	if !hasher.CheckInRange(atBoundary) {
		t.Errorf("CheckInRange() failed for value at boundary: %s", atBoundary.String())
	}

	// Test with a value out of range (greater than field modulus)
	outOfRange := new(big.Int).Add(fieldModulus, big.NewInt(1))
	if hasher.CheckInRange(outOfRange) {
		t.Errorf("CheckInRange() should have failed for out-of-range value: %s", outOfRange.String())
	}

	// Test with a very large value (2^256)
	veryLarge := new(big.Int).Lsh(big.NewInt(1), 256)
	if hasher.CheckInRange(veryLarge) {
		t.Errorf("CheckInRange() should have failed for very large value: %s", veryLarge.String())
	}
}

func TestPoseidonHasher_Hash_Consistency(t *testing.T) {
	hasher := &PoseidonHasher{}
	inputs := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}

	// Hash the same inputs multiple times
	result1, err1 := hasher.Hash(inputs)
	if err1 != nil {
		t.Fatalf("First Hash() call failed: %v", err1)
	}

	result2, err2 := hasher.Hash(inputs)
	if err2 != nil {
		t.Fatalf("Second Hash() call failed: %v", err2)
	}

	// Results should be identical (deterministic)
	assert.Equal(t, result1, result2, "Hash() should be deterministic")
}

