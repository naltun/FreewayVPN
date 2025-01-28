/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("Invalid credentials")
	ErrUserNotFound       = errors.New("User not found")
)

// User struct to represent a VPN user
type User struct {
	CreatedAt time.Time
	ID        string // Format: i-XXXX-XXXX-XXXX (X equal to an alphanumeric character)
	Email     string // Optional
	PublicKey string // WireGuard public key
}

// Manager struct to manage user authentication
type Manager struct {
	mu     sync.RWMutex
	secret []byte
	users  map[string]*User // Key: ID or Email, Value: User object
}

//
// START private functions
//

// Generate a unique ID in the format: i-XXXX-XXXX-XXXX (X equal to an alphanumeric character)
func generateID() string {
	b := make([]byte, 6)
	rand.Read(b)
	id := hex.EncodeToString(b)

	return fmt.Sprintf("i-%s-%s-%s", id[:4], id[4:8], id[8:12])
}

//
// END private functions
//

//
// START public functions
//

// Create an HMAC-based token for user
func (m *Manager) CreateToken(userID string) (string, error) {
	// Timestamp for 24 hour expiration
	ts := time.Now().Add(24 * time.Hour).Unix()

	// Create HMAC message in the format: <user ID>.<current timestamp>
	msg := fmt.Sprintf("%s.%d", userID, ts)

	// Create HMAC signature
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(msg))
	sig := hex.EncodeToString(h.Sum(nil))

	// Combine message and signature
	token := fmt.Sprintf("%s.%s", msg, sig)

	return base64.URLEncoding.EncodeToString([]byte(token)), nil
}

// Create a new user with email or generated ID
func (m *Manager) CreateUser(email string, publicKey string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if email is submitted and registered
	if email != "" {
		if _, exists := m.users[email]; exists {
			return nil, fmt.Errorf("Email already registered")
		}
	}

	// Generate a unique ID
	id := generateID()
	for _, exists := m.users[id]; exists; {
		id = generateID()
	}

	user := &User{
		CreatedAt: time.Now(),
		ID:        id,
		Email:     email,
		PublicKey: publicKey,
	}

	// Store new user
	if email != "" {
		m.users[email] = user // Store with email address as key
	} else {
		m.users[id] = user // Store with unique ID as key
	}

	return user, nil
}

// Create a new authentication manager
func New(secret []byte) *Manager {
	return &Manager{
		secret: secret,
		users:  make(map[string]*User),
	}
}

// Validate a token and return the user ID
func (m *Manager) ValidateToken(token string) (string, error) {
	// Decode
	t, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("Invalid token format: %v", err)
	}

	parts := strings.Split(string(t), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("Invalid token format")
	}

	userID := parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	// Parse and verify timestamp
	var ts int64

	if _, err := fmt.Sscanf(timestampStr, "%d", &ts); err != nil {
		return "", fmt.Errorf("Invalid timestamp")
	}

	if time.Unix(ts, 0).Before(time.Now()) {
		return "", fmt.Errorf("Token expired")
	}

	// Verify signature
	msg := fmt.Sprintf("%s.%s", userID, timestampStr)
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(msg))
	expected := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return "", fmt.Errorf("Invalid signature")
	}

	return userID, nil
}

//
// END public functions
//
