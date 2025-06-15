package ed25519_test

import (
	"testing"

	crypto_ed25519 "crypto/ed25519"

	"github.com/Asphere-xyz/tacchain/precompiles/ed25519"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/stretchr/testify/suite"
)

const (
	// PubKeySize is is the size, in bytes, of public keys as used in this package.
	PubKeySize = 32
	// PrivKeySize is the size, in bytes, of private keys as used in this package.
	PrivKeySize = 64
	// Size of an Edwards25519 signature. Namely the size of a compressed
	// Edwards25519 point, and a field element. Both of which are 32 bytes.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the
	// private key representations used by RFC 8032.
	SeedSize = 32
)

var s *PrecompileTestSuite

type PrecompileTestSuite struct {
	suite.Suite
	precompile *ed25519.Precompile
	pubkey     []byte
	privkey    []byte
}

func TestPrecompileTestSuite(t *testing.T) {
	s = new(PrecompileTestSuite)
	suite.Run(t, s)
}

func (s *PrecompileTestSuite) SetupTest() {
	pubkey, privkey, err := crypto_ed25519.GenerateKey(nil)
	s.Require().NoError(err)
	s.pubkey = pubkey
	s.privkey = privkey
	s.precompile = &ed25519.Precompile{}
}

func (s *PrecompileTestSuite) TestVerify() {
	message := []byte("Hello, world!")
	signature := crypto_ed25519.Sign(s.privkey, message)
	valid := crypto_ed25519.Verify(s.pubkey, message, signature)
	s.Require().True(valid)
}

func (s *PrecompileTestSuite) TestRun() {
	testCases := []struct {
		name      string
		sign      func() []byte
		expPass   bool
		expOutput []byte
	}{
		{
			name: "valid signature",
			sign: func() []byte {
				signature := crypto_ed25519.Sign(s.privkey, []byte("Hello, world!"))
				input := append(s.pubkey, signature...)
				return append(input, []byte("Hello, world!")...)
			},
			expPass:   true,
			expOutput: ed25519.True32Byte,
		},
		{
			name: "invalid signature",
			sign: func() []byte {
				input := make([]byte, 96)
				copy(input[:32], s.pubkey)
				copy(input[32:96], []byte("invalid signature"))
				input = append(input, []byte("Hello, world!")...)
				return input
			},
			expPass:   false,
			expOutput: ed25519.False32Byte,
		},
		{
			name: "invalid public key",
			sign: func() []byte {
				input := make([]byte, 96)
				invalidPubkey := make([]byte, 32)
				copy(invalidPubkey[:32], []byte("invalid public key"))
				copy(input[:32], invalidPubkey)

				signature := crypto_ed25519.Sign(s.privkey, []byte("Hello, world!"))
				copy(input[32:96], signature)
				input = append(input, []byte("Hello, world!")...)
				return input
			},
			expPass:   false,
			expOutput: ed25519.False32Byte,
		},
		{
			name: "invalid input length",
			sign: func() []byte {
				input := []byte("Invalid input length")
				return input
			},
			expPass:   false,
			expOutput: ed25519.False32Byte,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			input := tc.sign()
			bz, err := s.precompile.Run(nil, &vm.Contract{Input: input}, false)
			if tc.expPass {
				s.Require().NoError(err)
				s.Require().Equal(ed25519.True32Byte, bz)
			} else {
				s.Require().NoError(err)
				s.Require().Equal(ed25519.False32Byte, bz)
			}
		})
	}
}
