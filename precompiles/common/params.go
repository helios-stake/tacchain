package common

import (
	"github.com/ethereum/go-ethereum/params"
)

const (
	Ed25519VerifyGas uint64 = 1500
	Sha512BaseGas    uint64 = params.Sha256BaseGas
	Sha512PerWordGas uint64 = params.Sha256PerWordGas
)
