/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCreateUser(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		publicKey string
		wantError bool
	}{
		{
			name:      "Valid user with email",
			email:     "test@example.com",
			publicKey: "abc123",
			wantError: false,
		},
		{
			name:      "Valid user without email",
			email:     "",
			publicKey: "bcd234",
			wantError: false,
		},
		{
			name:      "Duplicate email",
			email:     "test@example.com",
			publicKey: "cde345",
			wantError: true,
		},
	}

	authManager := New([]byte("test secret"))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a test user
			user, err := authManager.CreateUser(test.email, test.publicKey)
			if (err != nil) != test.wantError {
				t.Errorf("CreateUser() error: %v, expected error: %v", err, test.wantError)
				return
			}

			if !test.wantError {
				if user.PublicKey != test.publicKey {
					t.Errorf("CreateUser() publicKey: %v, expected: %v", user.PublicKey, test.publicKey)
				}

				if user.Email != test.email {
					t.Errorf("CreateUser() email: %v, expected: %v", user.Email, test.email)
				}

				if user.ID == "" {
					t.Error("CreateUser() ID is empty")
				}

				if user.CreatedAt.IsZero() {
					t.Error("CreateUser() is zero")
				}
			}
		})
	}
}

func TestTokenLifecycle(t *testing.T) {
	authManager := New([]byte("test secret"))

	// Create a test user
	user, err := authManager.CreateUser("test@example.com", "test key")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name      string
		setup     func() string // Returns a token for testing
		wantID    string
		wantError bool
	}{
		{
			name: "Valid token",
			setup: func() string {
				token, err := authManager.CreateToken(user.ID)
				if err != nil {
					t.Fatalf("Failed to create token: %v", err)
				}
				return token
			},
			wantID:    user.ID,
			wantError: false,
		},
		{
			name: "Invalid format",
			setup: func() string {
				return "invalid token"
			},
			wantID:    "",
			wantError: true,
		},
		{
			name: "Expired token",
			setup: func() string {
				// Create a token which we will manipulate (e.g., modify the timestamp)
				token, err := authManager.CreateToken(user.ID)
				if err != nil {
					t.Fatalf("Failed to create token: %v", err)
				}

				// Decode token
				decoded, err := base64.URLEncoding.DecodeString(token)
				if err != nil {
					t.Fatalf("Invalid token format")
				}

				// Split decoded token into its parts (see generateID() in auth.go)
				parts := strings.Split(string(decoded), ".")
				if len(parts) != 3 {
					t.Fatalf("Invalid token format")
				}

				// Set timestamp to 48 hours before
				expiredTime := time.Now().Add(-48 * time.Hour).Unix()
				parts[1] = fmt.Sprintf("%d", expiredTime)

				// Recreate signature
				msg := fmt.Sprintf("%s.%s", parts[0], parts[1])
				h := hmac.New(sha256.New, []byte("test secret"))
				h.Write([]byte(msg))
				parts[2] = hex.EncodeToString(h.Sum(nil))

				// Encode token
				encoded := strings.Join(parts, ".")

				return base64.URLEncoding.EncodeToString([]byte(encoded))
			},
			wantID:    "",
			wantError: true,
		},
		{
			name: " Invalid signature",
			setup: func() string {
				token, err := authManager.CreateToken(user.ID)
				if err != nil {
					t.Fatalf("Failed to create token: %v", err)
				}
				// Modify the signature
				return token[:len(token)-3] + "FOO"
			},
			wantID:    "",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := test.setup()
			gotID, err := authManager.ValidateToken(token)

			if (err != nil) != test.wantError {
				t.Errorf("ValidateToken() error: %v, expected: %v", err, test.wantError)
				return
			}

			if gotID != test.wantID {
				t.Errorf("ValidateToken() ID: %v, expected: %v", gotID, test.wantID)
			}
		})
	}
}
