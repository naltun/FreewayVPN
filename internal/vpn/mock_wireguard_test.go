/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package vpn

import (
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Mock WireGuard client struct for testing
type MockWireGuardClient struct {
	mu           sync.RWMutex
	deviceConfig map[string]wgtypes.Config // Track device configuration
	peers        map[string]wgtypes.Peer   // track connected peers
	shouldError  bool                      // Simulate errors when needed
}

//
// START core API
//

// Create a new mock WireGuard client
func NewMockClient() *MockWireGuardClient {
	return &MockWireGuardClient{
		deviceConfig: make(map[string]wgtypes.Config),
		peers:        make(map[string]wgtypes.Peer),
	}
}

// Implement WireGuardClient interface
func (m *MockWireGuardClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldError {
		return fmt.Errorf("Mock error: failed to configure device")
	}

	// Handle peer operations
	if cfg.Peers != nil {
		for _, peer := range cfg.Peers {
			if peer.Remove {
				delete(m.peers, peer.PublicKey.String())
			} else {
				m.peers[peer.PublicKey.String()] = wgtypes.Peer{
					PublicKey:  peer.PublicKey,
					AllowedIPs: peer.AllowedIPs,
				}
			}
		}
	}

	// Store device configuration
	m.deviceConfig[name] = cfg

	return nil
}

// Implement WireGuardClient interface
func (m *MockWireGuardClient) Device(name string) (*wgtypes.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.shouldError {
		return nil, fmt.Errorf("Mock error: device not found")
	}

	cfg, exists := m.deviceConfig[name]
	if !exists {
		return nil, fmt.Errorf("Mock error: device \"%s\" not found", name)
	}

	// Convert peers map to slice
	peers := make([]wgtypes.Peer, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, peer)
	}

	var listenPort int
	var privKey wgtypes.Key

	if cfg.ListenPort != nil {
		listenPort = *cfg.ListenPort
	}
	if cfg.PrivateKey != nil {
		privKey = *cfg.PrivateKey
	}

	return &wgtypes.Device{
		Name:       name,
		PrivateKey: privKey,
		PublicKey:  privKey.PublicKey(),
		ListenPort: listenPort,
		Peers:      peers,
	}, nil
}

// Implement WireGuardClient interface
func (m *MockWireGuardClient) Close() error {
	return nil
}

//
// END core API
//

//
// START test helpers
//

// Return number of configured peers
func (m *MockWireGuardClient) PeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.peers)
}

// Create mock error
func (m *MockWireGuardClient) SetError(shouldError bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.shouldError = shouldError
}

//
// END test helpers
//
