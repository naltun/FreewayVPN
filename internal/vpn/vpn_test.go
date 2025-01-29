/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package vpn

import (
	"encoding/base64"
	"net"
	"sync"
	"testing"
)

// Create test 32-byte WireGuard public key
func createTestPublicKey(id int) string {
	key := make([]byte, 32)

	for i := range key {
		key[i] = byte(id + i)
	}

	return base64.StdEncoding.EncodeToString(key)
}

func TestAddPeer(t *testing.T) {
	// Set up mock WireGuard device
	mock := NewMockClient()
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	ctrlr:= NewVPNController(mock, "wg0", net.ParseIP("10.0.0.1"), subnet)

	// Test adding a peer
	ip, err := ctrlr.AddPeer(createTestPublicKey(0))
	if err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	// Verify peer was added
	if count := mock.PeerCount(); count != 1 {
		t.Errorf("Expected 1 peer, got: %d", count)
	}

	// Verify IP allocation (e.g., first available IP should be 10.0.0.2)
	expected := net.ParseIP("10.0.0.2")
	if !ip.Equal(expected) {
		t.Errorf("Expected IP: %v, got: %v", expected, ip)
	}
}

func TestAddPeerError(t *testing.T) {
	// Set up mock WireGuard device with error condition set
	mock := NewMockClient()
	mock.SetError(true)
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	ctrlr := NewVPNController(mock, "wg0", net.ParseIP("10.0.0.1"), subnet)

	// Attempt to add peer and validate error condition
	_, err := ctrlr.AddPeer("test key")
	if err == nil {
		t.Error("Expected error when adding peer")
	}
}

func TestConcurrentPeerOperations(t *testing.T) {
	mock := NewMockClient()
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	ctrlr := NewVPNController(mock, "wg0", net.ParseIP("10.0.0.1"), subnet)

	// Add multiple peers concurrently
	var wg sync.WaitGroup
	countExpected := 10
	errors := make(chan error, countExpected)

	for i := 0; i < countExpected; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := ctrlr.AddPeer(createTestPublicKey(i))
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}

	// Verify final peer count
	if count := mock.PeerCount(); count != countExpected {
		t.Errorf("Expected %d peers, got: %d", countExpected, count)
	}
}

func TestIPAllocation(t *testing.T) {
	mock := NewMockClient()
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	ctrlr := NewVPNController(mock, "wg0", net.ParseIP("10.0.0.1"), subnet)

	// Add multiple peers and verify IP allocations
	expectedIPs := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"}

	for i, expectedIP := range expectedIPs {
		ip, err := ctrlr.AddPeer(createTestPublicKey(i))
		if err != nil {
			t.Fatalf("Failed to add peer: %d: %v", i, err)
		}

		if !ip.Equal(net.ParseIP(expectedIP)) {
			t.Errorf("Peer %d: expected IP: %v, got: %v", i, expectedIP, ip)
		}
	}
}

func TestRemovePeer(t *testing.T) {
	// Set up mock WireGuard device
	mock := NewMockClient()
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	ctrlr := NewVPNController(mock, "wg0", net.ParseIP("10.0.0.1"), subnet)

	// peer public key
	key := createTestPublicKey(0)

	// Add a peer to be removed
	_, err := ctrlr.AddPeer(key)
	if err != nil {
		t.Fatalf("Failed to add peer: %v", err)
	}

	// Test peer count is 1
	if count := mock.PeerCount(); count != 1 {
		t.Fatalf("Expected 1 peer, got: %d", count)
	}

	// Test removing peer
	err = ctrlr.RemovePeer(key)
	if err != nil {
		t.Errorf("Failed to remove peer: %v", err)
	}

	// Test peer count is 0
	if count := mock.PeerCount(); count != 0 {
		t.Errorf("Expected 0 peers, got: %d", count)
	}
}
