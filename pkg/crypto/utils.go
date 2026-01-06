package crypto

import (
	"math/big"

	"github.com/LFDT-Paladin/smt/internal/crypto"
)

func NewSalt() *big.Int {
	return crypto.NewSalt()
}

func NewRandomNumberInRange(max *big.Int) *big.Int {
	return crypto.NewRandomNumberInRange(max)
}
