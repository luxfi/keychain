// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keychain

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

// mockLedger implements Ledger interface for testing
type mockLedger struct {
	addresses map[uint32]ids.ShortID
}

func newMockLedger() *mockLedger {
	return &mockLedger{
		addresses: make(map[uint32]ids.ShortID),
	}
}

func (m *mockLedger) Address(_ string, addressIndex uint32) (ids.ShortID, error) {
	if addr, ok := m.addresses[addressIndex]; ok {
		return addr, nil
	}
	// Generate a deterministic address for the index
	var addr ids.ShortID
	addr[0] = byte(addressIndex)
	m.addresses[addressIndex] = addr
	return addr, nil
}

func (m *mockLedger) GetAddresses(addressIndices []uint32) ([]ids.ShortID, error) {
	addrs := make([]ids.ShortID, len(addressIndices))
	for i, idx := range addressIndices {
		addr, err := m.Address("", idx)
		if err != nil {
			return nil, err
		}
		addrs[i] = addr
	}
	return addrs, nil
}

func (m *mockLedger) SignHash(_ []byte, _ uint32) ([]byte, error) {
	return []byte("mock-hash-signature"), nil
}

func (m *mockLedger) Sign(_ []byte, _ uint32) ([]byte, error) {
	return []byte("mock-signature"), nil
}

func (m *mockLedger) SignTransaction(_ []byte, addressIndices []uint32) ([][]byte, error) {
	sigs := make([][]byte, len(addressIndices))
	for i := range addressIndices {
		sigs[i] = []byte("mock-tx-signature")
	}
	return sigs, nil
}

func (m *mockLedger) Disconnect() error {
	return nil
}

func TestNewLedgerKeychain(t *testing.T) {
	require := require.New(t)

	ledger := newMockLedger()

	// Test with empty indices
	_, err := NewLedgerKeychain(ledger, []uint32{})
	require.ErrorIs(err, ErrInvalidIndicesLength)

	// Test with valid indices
	kc, err := NewLedgerKeychain(ledger, []uint32{0, 1, 2})
	require.NoError(err)
	require.NotNil(kc)

	// Should have 3 addresses
	addrs := kc.Addresses()
	require.Equal(3, addrs.Len())
}

func TestLedgerKeychainGetSigner(t *testing.T) {
	require := require.New(t)

	ledger := newMockLedger()
	kc, err := NewLedgerKeychain(ledger, []uint32{0, 1})
	require.NoError(err)

	// Get address for index 0
	addr0, err := ledger.Address("", 0)
	require.NoError(err)

	// Should be able to get signer for addr0
	signer, ok := kc.Get(addr0)
	require.True(ok)
	require.NotNil(signer)
	require.Equal(addr0, signer.Address())

	// Should not find unknown address
	var unknownAddr ids.ShortID
	unknownAddr[0] = 99
	_, ok = kc.Get(unknownAddr)
	require.False(ok)
}

func TestLedgerSignerSign(t *testing.T) {
	require := require.New(t)

	ledger := newMockLedger()
	kc, err := NewLedgerKeychain(ledger, []uint32{0})
	require.NoError(err)

	addr0, err := ledger.Address("", 0)
	require.NoError(err)

	signer, ok := kc.Get(addr0)
	require.True(ok)

	// Test SignHash
	sig, err := signer.SignHash([]byte("test-hash"))
	require.NoError(err)
	require.Equal([]byte("mock-hash-signature"), sig)

	// Test Sign
	sig, err = signer.Sign([]byte("test-data"))
	require.NoError(err)
	require.Equal([]byte("mock-signature"), sig)
}
