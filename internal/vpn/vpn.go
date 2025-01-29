/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package vpn

import (
	"fmt"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuard client interface
type WireGuardClient interface {
	Close() error
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
}

// Controller struct to control the state of the VPN service
type Controller struct {
	client        WireGuardClient
	interfaceName string
	mu            sync.RWMutex
	peers         map[string]net.IP // Key: user's public key, Value: assigned network IP
	serverIP      net.IP
	subnet        *net.IPNet
}

//
// START private functions
//

// Find the next available IP in the subnet
func (c *Controller) nextAvailableIP() (net.IP, error) {
	ip := make(net.IP, len(c.subnet.IP))
	copy(ip, c.subnet.IP)

	// Try IPs X.X.X.2 through X.X.X.254, skipping X.X.X.0 (network), X.X.X.1 (server),
	// and X.X.X.255 (broadcast)
	for i := 2; i < 254; i++ {
		ip[len(ip)-1] = byte(i)

		inUse := false
		for _, assignedIP := range c.peers {
			if assignedIP.Equal(ip) {
				inUse = true
				break
			}
		}

		if !inUse {
			// We found our next assignable IP address!
			return ip, nil
		}
	}

	return nil, fmt.Errorf("No available IPs in subnet")
}

//
// END private functions
//

//
// START public functions
//

// Add a new network peer and assign them an IP address
func (c *Controller) AddPeer(publicKey string) (net.IP, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	parsedKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("Invalid public key: %v", err)
	}

	// Find available IP address
	peerIP, err := c.nextAvailableIP()
	if err != nil {
		return nil, err
	}

	// Configure new peer
	peer := wgtypes.PeerConfig{
		PublicKey: parsedKey,
		AllowedIPs: []net.IPNet{{
			IP:   peerIP,
			Mask: net.CIDRMask(32, 32),
		}},
	}

	// Create updated WireGuard configuration with new peer info
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	// Update service configuration
	if err := c.client.ConfigureDevice(c.interfaceName, cfg); err != nil {
		return nil, fmt.Errorf("Failed to add peer: %v", err)
	}

	// Store new peer information
	c.peers[publicKey] = peerIP

	return peerIP, nil
}

// Return map of connected peers
func (c *Controller) ListPeers() (map[string]net.IP, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make(map[string]net.IP, len(c.peers))
	for publicKey, ipAddr := range c.peers {
		peers[publicKey] = ipAddr
	}

	return peers, nil
}

// Create a new VPN controller
func NewVPNController(client WireGuardClient, interfaceName string, serverIP net.IP, subnet *net.IPNet) *Controller {
	return &Controller{
		client:        client,
		interfaceName: interfaceName,
		serverIP:      serverIP,
		subnet:        subnet,
		peers:         make(map[string]net.IP),
	}
}

// Create a new VPN controller with the default WireGuard client implementation
func NewControllerWithDefaultClient(interfaceName string, serverIP net.IP, subnet *net.IPNet) (*Controller, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("Failed to create \"default\" WireGuard client: %v", err)
	}

	return NewVPNController(client, interfaceName, serverIP, subnet), nil
}

// Remove a peer from the network
func (c *Controller) RemovePeer(publicKey string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	parsedKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("Invalid public key: %v", err)
	}

	// Create removal configuration
	peer := wgtypes.PeerConfig{
		PublicKey: parsedKey,
		Remove:    true,
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}

	// Update service configuration
	if err := c.client.ConfigureDevice(c.interfaceName, cfg); err != nil {
		return fmt.Errorf("Failed to remove peer: %v", err)
	}

	// Remove peer from being tracked
	delete(c.peers, publicKey)

	return nil
}

// Initialize the WireGuard interface
func (c *Controller) Start(port int) error {
	newKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("Failed to generate private key: %v", err)
	}

	cfg := wgtypes.Config{
		PrivateKey: &newKey,
		ListenPort: &port,
	}

	if err := c.client.ConfigureDevice(c.interfaceName, cfg); err != nil {
		return fmt.Errorf("Failed to configure WireGuard interface: %v", err)
	}

	return nil
}

//
// END public functions
//
