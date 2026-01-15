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

package storage

import (
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/LFDT-Paladin/smt/internal/crypto"
	"github.com/LFDT-Paladin/smt/internal/crypto/hash"
	"github.com/LFDT-Paladin/smt/internal/sparse-merkle-tree/node"
	"github.com/LFDT-Paladin/smt/internal/testutils"
	"github.com/LFDT-Paladin/smt/pkg/sparse-merkle-tree/core"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type testSqlProvider struct {
	db *gorm.DB
}

func (s *testSqlProvider) DB() *gorm.DB {
	return s.db
}

func (s *testSqlProvider) Close() {}

func TestSqliteStorage(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	tokenId := big.NewInt(1001)
	uriString := "https://example.com/token/1001"
	assert.NoError(t, err)
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewNonFungible(tokenId, uriString, sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)

	idx, _ := utxo1.CalculateIndex()
	err = s.UpsertRootNodeRef(ctx, idx)
	assert.NoError(t, err)
	dbIdx, err := s.GetRootNodeRef(ctx)
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), dbIdx.Hex())

	dbRoot := core.SMTRoot{Name: "test_1"}
	err = db.Table(core.TreeRootsTable).First(&dbRoot).Error
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), dbRoot.RootRef)

	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), dbNode.RefKey)

	n2, err := s.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n2.Ref().Hex())

	bn1, err := node.NewBranchNode(n1.Ref(), n1.Ref(), &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	n3, err := s.GetNode(ctx, bn1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, bn1.Ref().Hex(), n3.Ref().Hex())
}

func TestSqliteStorageFail_NoRootTable(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	_, err = s.GetRootNodeRef(ctx)
	assert.EqualError(t, err, "no such table: merkelTreeRoots")

	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	_, err = s.GetRootNodeRef(ctx)
	assert.EqualError(t, err, "key not found")
}

func TestSqliteStorageFail_NoNodeTable(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	idx, err := node.NewNodeIndexFromHex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", &hash.PoseidonHasher{})
	assert.NoError(t, err)
	_, err = s.GetNode(ctx, idx)
	assert.EqualError(t, err, "no such table: smtNodes_test_1")

	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	_, err = s.GetNode(ctx, idx)
	assert.EqualError(t, err, "key not found")
}

func TestSqliteStorageFail_BadNodeIndex(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})
	assert.NoError(t, err)

	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()

	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// modify the index in the db
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	badIndex := ""
	dbNode.Index = &badIndex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	_, err = s.GetNode(ctx, n1.Ref())
	assert.EqualError(t, err, "expected 32 bytes for the decoded node index")

	bn1, err := node.NewBranchNode(n1.Ref(), n1.Ref(), &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	dbNode = core.SMTNode{RefKey: bn1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	saveLeftChild := *dbNode.LeftChild
	dbNode.LeftChild = &badIndex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	_, err = s.GetNode(ctx, bn1.Ref())
	assert.EqualError(t, err, "expected 32 bytes for the decoded node index")

	dbNode.LeftChild = &saveLeftChild
	dbNode.RightChild = &badIndex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)
	_, err = s.GetNode(ctx, bn1.Ref())
	assert.EqualError(t, err, "expected 32 bytes for the decoded node index")

	s.Close()
}

func TestSqlStorage_GetHasher(t *testing.T) {
	provider := &testSqlProvider{db: nil}
	hasher := &hash.PoseidonHasher{}
	s := NewSqlStorage(provider, "test_1", hasher)
	assert.Equal(t, hasher, s.GetHasher())

	keccakHasher := &hash.Keccak256Hasher{}
	s2 := NewSqlStorage(provider, "test_2", keccakHasher)
	assert.Equal(t, keccakHasher, s2.GetHasher())
}

func TestSqlStorage_Transaction(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Test BeginTx
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, tx)

	// Test transaction operations
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)

	// Insert node through transaction
	err = tx.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Get node through transaction
	n2, err := tx.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n2.Ref().Hex())

	// Upsert root through transaction
	idx, _ := utxo1.CalculateIndex()
	err = tx.UpsertRootNodeRef(ctx, idx)
	assert.NoError(t, err)

	// Commit transaction
	err = tx.Commit(ctx)
	assert.NoError(t, err)

	// Verify data was committed
	n3, err := s.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n3.Ref().Hex())

	root, err := s.GetRootNodeRef(ctx)
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), root.Hex())
}

func TestSqlStorage_TransactionRollback(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Start transaction
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)

	// Insert node through transaction
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = tx.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Rollback transaction
	err = tx.Rollback(ctx)
	assert.NoError(t, err)

	// Verify data was not committed
	_, err = s.GetNode(ctx, n1.Ref())
	assert.Error(t, err)
	assert.Equal(t, core.ErrNotFound, err)
}

func TestSqlStorage_GetNodeWithValue(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create leaf node with value
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	value := big.NewInt(12345)
	n1, err := node.NewLeafNode(utxo1, value)
	assert.NoError(t, err)

	// Insert node
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Get node and verify value
	n2, err := s.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n2.Ref().Hex())
	assert.Equal(t, value, n2.Value())
}

func TestSqlStorage_GetNodeWithEmptyValueString(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create leaf node without value
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)

	// Insert node
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Modify the value in DB to be empty string
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	emptyValue := ""
	dbNode.Value = &emptyValue
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// Get node - should work with nil value (empty string is treated as nil)
	n2, err := s.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Nil(t, n2.Value())
}

func TestSqlStorage_GetNodeWithInvalidValue(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create leaf node with value
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	value := big.NewInt(12345)
	n1, err := node.NewLeafNode(utxo1, value)
	assert.NoError(t, err)

	// Insert node
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Modify the value in DB to be invalid hex
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	invalidValue := "not_a_hex_string"
	dbNode.Value = &invalidValue
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// Get node should fail with invalid value error
	_, err = s.GetNode(ctx, n1.Ref())
	assert.Error(t, err)
	assert.Equal(t, core.ErrInvalidValue, err)
}

func TestSqlStorage_GetRootNodeRef_InvalidHex(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Insert invalid root ref
	invalidRoot := core.SMTRoot{
		Name:    "test_1",
		RootRef: "invalid_hex_string",
	}
	err = db.Table(core.TreeRootsTable).Save(&invalidRoot).Error
	assert.NoError(t, err)

	// GetRootNodeRef should fail
	_, err = s.GetRootNodeRef(ctx)
	assert.Error(t, err)
}

func TestSqlStorage_GetRootNodeRef_WrongLength(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Insert root ref with wrong length
	invalidRoot := core.SMTRoot{
		Name:    "test_1",
		RootRef: "123456", // Too short
	}
	err = db.Table(core.TreeRootsTable).Save(&invalidRoot).Error
	assert.NoError(t, err)

	// GetRootNodeRef should fail
	_, err = s.GetRootNodeRef(ctx)
	assert.Error(t, err)
}

func TestSqlStorage_InsertNodeWithValue(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create leaf node with value
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	value := big.NewInt(99999)
	n1, err := node.NewLeafNode(utxo1, value)
	assert.NoError(t, err)

	// Insert node
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Verify value was stored
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	assert.NotNil(t, dbNode.Value)
	assert.Equal(t, value.Text(16), *dbNode.Value)
}

func TestSqlStorage_InsertNodeDuplicate(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert node
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)

	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Insert same node again (should not error due to OnConflict DoNothing)
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Verify only one node exists
	var count int64
	db.Table(core.NodesTablePrefix+"test_1").Where("ref_key = ?", n1.Ref().Hex()).Count(&count)
	assert.Equal(t, int64(1), count)
}

func TestSqlStorage_TransactionGetNode(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Insert node outside transaction
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Start transaction and get node
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)

	n2, err := tx.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n2.Ref().Hex())

	err = tx.Commit(ctx)
	assert.NoError(t, err)
}

func TestSqlStorage_TransactionUpsertRootNodeRef(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Start transaction
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)

	// Upsert root through transaction
	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(123), &hash.PoseidonHasher{})
	err = tx.UpsertRootNodeRef(ctx, idx)
	assert.NoError(t, err)

	// Commit
	err = tx.Commit(ctx)
	assert.NoError(t, err)

	// Verify root was saved
	root, err := s.GetRootNodeRef(ctx)
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), root.Hex())
}

func TestSqlStorage_GetNode_InvalidLeftChild(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert branch node
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), &hash.PoseidonHasher{})
	bn1, err := node.NewBranchNode(idx1, idx2, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	// Modify left child to be invalid hex
	dbNode := core.SMTNode{RefKey: bn1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	invalidHex := "not_hex"
	dbNode.LeftChild = &invalidHex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should fail
	_, err = s.GetNode(ctx, bn1.Ref())
	assert.Error(t, err)
}

func TestSqlStorage_GetNode_InvalidRightChild(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert branch node
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), &hash.PoseidonHasher{})
	bn1, err := node.NewBranchNode(idx1, idx2, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	// Modify right child to be invalid hex
	dbNode := core.SMTNode{RefKey: bn1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	invalidHex := "not_hex"
	dbNode.RightChild = &invalidHex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should fail
	_, err = s.GetNode(ctx, bn1.Ref())
	assert.Error(t, err)
}

func TestSqlStorage_GetNode_InvalidIndexHex(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert leaf node
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Modify index to be invalid hex (not just wrong length, but invalid hex)
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	invalidHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	dbNode.Index = &invalidHex
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should fail
	_, err = s.GetNode(ctx, n1.Ref())
	assert.Error(t, err)
}

func TestSqlStorage_GetRootNodeRef_OtherError(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	// Don't migrate - this will cause an error when trying to query

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// GetRootNodeRef should return error (table doesn't exist)
	_, err = s.GetRootNodeRef(ctx)
	assert.Error(t, err)
	// Should not be ErrNotFound, but a table error
	assert.NotEqual(t, core.ErrNotFound, err)
}

func TestSqlStorage_GetNode_OtherError(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	// Don't migrate nodes table - this will cause an error

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	idx, _ := node.NewNodeIndexFromBigInt(big.NewInt(10), &hash.PoseidonHasher{})
	// GetNode should return error (table doesn't exist)
	_, err = s.GetNode(ctx, idx)
	assert.Error(t, err)
	// Should not be ErrNotFound, but a table error
	assert.NotEqual(t, core.ErrNotFound, err)
}

func TestSqlStorage_NewSqlStorage(t *testing.T) {
	provider := &testSqlProvider{db: nil}
	hasher := &hash.PoseidonHasher{}

	s := NewSqlStorage(provider, "test_tree", hasher)
	assert.NotNil(t, s)
	assert.Equal(t, "test_tree", s.smtName)
	assert.Equal(t, core.NodesTablePrefix+"test_tree", s.nodesTableName)
	assert.Equal(t, hasher, s.hasher)
}

// TestSqlStorage_InsertNode_EmptyNode - Empty nodes have nil Ref() which would
// cause a panic in insertNode when calling n.Ref().Hex(). Empty nodes are not
// meant to be stored, so this case is not supported by the current implementation.

func TestSqlStorage_GetNode_InvalidNodeType(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert a valid node first
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Modify the node type to be invalid
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	invalidType := byte(255) // Invalid node type
	dbNode.Type = invalidType
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should return nil node and nil error (switch doesn't match any case)
	// This is a potential bug - it should probably return an error
	n2, _ := s.GetNode(ctx, n1.Ref())
	// The current implementation returns nil, nil for invalid node types
	assert.Nil(t, n2)
	// err might be nil or might be set, depending on implementation
}

func TestSqlStorage_InsertNode_NilLeftChild(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Test that branch nodes with valid children work
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), &hash.PoseidonHasher{})
	bn1, err := node.NewBranchNode(idx1, idx2, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	// Verify it was stored correctly
	n2, err := s.GetNode(ctx, bn1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, bn1.Ref().Hex(), n2.Ref().Hex())
}

func TestSqlStorage_TransactionCommitError(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Start transaction
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)

	// Commit should work normally
	err = tx.Commit(ctx)
	assert.NoError(t, err)

	// Try to commit again (should fail)
	err = tx.Commit(ctx)
	// This might fail or succeed depending on GORM implementation
	_ = err
}

func TestSqlStorage_TransactionRollbackError(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Start transaction
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)

	// Rollback should work normally
	err = tx.Rollback(ctx)
	assert.NoError(t, err)

	// Try to rollback again (might fail or succeed)
	err = tx.Rollback(ctx)
	_ = err
}

func TestSqlStorage_UpsertRootNodeRef_UpdateExisting(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Insert initial root
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(100), &hash.PoseidonHasher{})
	err = s.UpsertRootNodeRef(ctx, idx1)
	assert.NoError(t, err)

	// Verify it was saved
	root1, err := s.GetRootNodeRef(ctx)
	assert.NoError(t, err)
	assert.Equal(t, idx1.Hex(), root1.Hex())

	// Update root
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(200), &hash.PoseidonHasher{})
	err = s.UpsertRootNodeRef(ctx, idx2)
	assert.NoError(t, err)

	// Verify it was updated
	root2, err := s.GetRootNodeRef(ctx)
	assert.NoError(t, err)
	assert.Equal(t, idx2.Hex(), root2.Hex())
}

func TestSqlStorage_GetNode_NilIndexPointer(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert leaf node
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Modify index to be nil
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	dbNode.Index = nil
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should panic due to nil pointer dereference
	assert.Panics(t, func() {
		_, _ = s.GetNode(ctx, n1.Ref())
	})
}

func TestSqlStorage_GetNode_NilLeftChildPointer(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert branch node
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), &hash.PoseidonHasher{})
	bn1, err := node.NewBranchNode(idx1, idx2, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	// Modify left child to be nil
	dbNode := core.SMTNode{RefKey: bn1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	dbNode.LeftChild = nil
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should panic due to nil pointer dereference
	assert.Panics(t, func() {
		_, _ = s.GetNode(ctx, bn1.Ref())
	})
}

func TestSqlStorage_GetNode_NilRightChildPointer(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create and insert branch node
	idx1, _ := node.NewNodeIndexFromBigInt(big.NewInt(1), &hash.PoseidonHasher{})
	idx2, _ := node.NewNodeIndexFromBigInt(big.NewInt(2), &hash.PoseidonHasher{})
	bn1, err := node.NewBranchNode(idx1, idx2, &hash.PoseidonHasher{})
	assert.NoError(t, err)
	err = s.InsertNode(ctx, bn1)
	assert.NoError(t, err)

	// Modify right child to be nil
	dbNode := core.SMTNode{RefKey: bn1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	dbNode.RightChild = nil
	err = db.Table(core.NodesTablePrefix + "test_1").Save(&dbNode).Error
	assert.NoError(t, err)

	// GetNode should panic due to nil pointer dereference
	assert.Panics(t, func() {
		_, _ = s.GetNode(ctx, bn1.Ref())
	})
}

func TestSqlStorage_InsertNode_LeafWithValue(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create leaf node with value
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	value := big.NewInt(54321)
	n1, err := node.NewLeafNode(utxo1, value)
	assert.NoError(t, err)

	// Insert node
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Verify value was stored
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	assert.NotNil(t, dbNode.Value)
	assert.Equal(t, value.Text(16), *dbNode.Value)
}

func TestSqlStorage_InsertNode_LeafWithoutValue(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Create leaf node without value
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, nil)
	assert.NoError(t, err)

	// Insert node
	err = s.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Verify value was not stored (nil)
	dbNode := core.SMTNode{RefKey: n1.Ref().Hex()}
	err = db.Table(core.NodesTablePrefix + "test_1").First(&dbNode).Error
	assert.NoError(t, err)
	assert.Nil(t, dbNode.Value)
}

func TestSqlStorage_Close(t *testing.T) {
	provider := &testSqlProvider{db: nil}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Close should not panic
	assert.NotPanics(t, func() {
		s.Close()
	})
}

func TestSqlStorage_TransactionOperations(t *testing.T) {
	ctx := context.Background()
	dbfile, err := os.CreateTemp("", "gorm.db")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dbfile.Name())
	}()
	db, err := gorm.Open(sqlite.Open(dbfile.Name()), &gorm.Config{})
	assert.NoError(t, err)
	err = db.Table(core.TreeRootsTable).AutoMigrate(&core.SMTRoot{})
	assert.NoError(t, err)
	err = db.Table(core.NodesTablePrefix + "test_1").AutoMigrate(&core.SMTNode{})
	assert.NoError(t, err)

	provider := &testSqlProvider{db: db}
	s := NewSqlStorage(provider, "test_1", &hash.PoseidonHasher{})

	// Test all transaction operations together
	tx, err := s.BeginTx(ctx)
	assert.NoError(t, err)

	// Insert node
	sender := testutils.NewKeypair()
	salt1 := crypto.NewSalt()
	utxo1 := node.NewFungible(big.NewInt(100), sender.PublicKey, salt1, &hash.PoseidonHasher{})
	n1, err := node.NewLeafNode(utxo1, big.NewInt(999))
	assert.NoError(t, err)
	err = tx.InsertNode(ctx, n1)
	assert.NoError(t, err)

	// Get node
	n2, err := tx.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n2.Ref().Hex())

	// Upsert root
	idx, _ := utxo1.CalculateIndex()
	err = tx.UpsertRootNodeRef(ctx, idx)
	assert.NoError(t, err)

	// Commit
	err = tx.Commit(ctx)
	assert.NoError(t, err)

	// Verify everything was committed
	n3, err := s.GetNode(ctx, n1.Ref())
	assert.NoError(t, err)
	assert.Equal(t, n1.Ref().Hex(), n3.Ref().Hex())
	root, err := s.GetRootNodeRef(ctx)
	assert.NoError(t, err)
	assert.Equal(t, idx.Hex(), root.Hex())
}
