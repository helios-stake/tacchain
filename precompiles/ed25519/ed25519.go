package ed25519

import (
	pcommon "github.com/Asphere-xyz/tacchain/precompiles/common"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	ed25519 "github.com/hdevalence/ed25519consensus"
)

const (
	// VerifyInputLength defines the minimum required input length (96 bytes) which is
	// the size of the the public key (32 bytes) and the signature (64 bytes).
	VerifyInputLength = 96
)

var (
	// true32Byte is returned if the ed25519 signature check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the ed25519 signature check fails.
	false32Byte = make([]byte, 32)
)

var _ vm.PrecompiledContract = &Precompile{}

// Precompile ed25519 signature verification
type Precompile struct{}

// Address defines the address of the ed25519 precompiled contract.
func (Precompile) Address() common.Address {
	return common.HexToAddress(pcommon.Ed25519PrecompileAddress)
}

// RequiredGas returns the static gas required to execute the precompiled contract.
func (p Precompile) RequiredGas(input []byte) uint64 {
	const sha512WordLength = 64

	// round up to next whole word
	lengthCeil := len(input) + sha512WordLength - 1
	words := uint64(lengthCeil / sha512WordLength)
	return pcommon.Ed25519VerifyGas + pcommon.Sha512BaseGas + (words * pcommon.Sha512PerWordGas)
}

func (p *Precompile) Run(_ *vm.EVM, contract *vm.Contract, _ bool) (bz []byte, err error) {
	input := contract.Input
	// Check the input length
	if len(input) < VerifyInputLength {
		// Input length is invalid
		return false32Byte, nil
	}

	publicKey := input[0:32]  // 32 bytes
	signature := input[32:96] // 64 bytes
	message := input[96:]     // arbitrary length

	// Verify the Ed25519 signature against the public key and message
	// uses https://github.com/hdevalence/ed25519consensus.Verify to comply with zip215 verification rules
	if ed25519.Verify(publicKey, message, signature) {
		return true32Byte, nil
	}
	return false32Byte, nil
}
