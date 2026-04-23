// Copyright © 2026 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClientNTLM tests creating a client with NTLM authentication
func TestNewClientNTLM(t *testing.T) {
	client, err := NewClient(Ntlm, "", "", "", "", "")
	require.NoError(t, err)
	require.NotNil(t, client)

	assert.Equal(t, Ntlm, client.authMethod)
	assert.NotNil(t, client.httpClient, "NTLM client should have httpClient set")
	assert.Nil(t, client.spnegoClient, "NTLM client should not have spnegoClient")
	assert.Nil(t, client.krb5Client, "NTLM client should not have krb5Client")
}

// TestNewClientInvalidAuthMethod tests creating a client with an invalid auth method
func TestNewClientInvalidAuthMethod(t *testing.T) {
	invalidMethod := AuthMethod(99)
	client, err := NewClient(invalidMethod, "", "", "", "", "")

	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "invalid auth method specified")
}

// TestNewClientKerberosEmptyConfig tests that Kerberos requires a config
func TestNewClientKerberosEmptyConfig(t *testing.T) {
	client, err := NewClient(Kerberos, "user", "pass", "", "REALM", "")

	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "could not load kerberos config: passed configuration is empty")
}

// TestNewClientKerberosInvalidConfig tests Kerberos with incomplete config
func TestNewClientKerberosInvalidConfig(t *testing.T) {
	// Config that parses but has no KDCs defined, causing ticket acquisition to fail
	incompleteConfig := `[libdefaults]
  default_realm = REALM

[realms]
  REALM = {
  }
`
	client, err := NewClient(Kerberos, "user", "pass", "", "REALM", incompleteConfig)

	require.Error(t, err)
	assert.Nil(t, client)
	// Error occurs during ticket acquisition due to no KDCs being defined
	assert.Contains(t, err.Error(), "could not obtain kerberos ticket")
}

// TestClientDoNTLM tests that Do() works with NTLM client
// TODO: this test can take 60 seconds to complete under certain network conditions. Reduce timeout.
func TestClientDoNTLM(t *testing.T) {
	client, err := NewClient(Ntlm, "", "", "", "", "")
	require.NoError(t, err)

	// Create a test request (note: this will fail to connect, but we're testing the method routing)
	req, err := http.NewRequest("GET", "http://invalid.local", nil)
	require.NoError(t, err)

	// The Do() call will fail because the URL is invalid, but that's expected
	// We're testing that it routes to the correct underlying client
	_, err = client.Do(req)
	assert.Error(t, err, "Expected error from invalid URL")
	// The error should be a network error, not an auth method error
	assert.NotContains(t, err.Error(), "invalid auth method")
}

// TestClientDoInvalidAuthMethod tests Do() with corrupted auth method
func TestClientDoInvalidAuthMethod(t *testing.T) {
	// Create a client with a valid method, then corrupt it
	client, err := NewClient(Ntlm, "", "", "", "", "")
	require.NoError(t, err)

	// Manually set an invalid auth method
	client.authMethod = AuthMethod(99)

	req, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid auth method specified for client")
}

// TestClientDestroy tests the Destroy method
func TestClientDestroy(t *testing.T) {
	tests := []struct {
		name  string
		setup func() *Client
	}{
		{
			name: "NTLM_NoKrb5Client",
			setup: func() *Client {
				client, _ := NewClient(Ntlm, "", "", "", "", "")
				return client
			},
		},
		{
			name: "NilKrb5Client",
			setup: func() *Client {
				return &Client{
					authMethod: Ntlm,
					krb5Client: nil,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setup()
			// Should not panic
			assert.NotPanics(t, func() {
				client.Destroy()
			})
		})
	}
}

// TestAuthMethodString tests the String() method for AuthMethod
func TestAuthMethodString(t *testing.T) {
	tests := []struct {
		name     string
		method   AuthMethod
		expected string
	}{
		{"NTLM", Ntlm, "ntlm"},
		{"Kerberos", Kerberos, "kerberos"},
		{"Invalid", AuthMethod(99), "unknown auth method: 99"},
		{"Zero", AuthMethod(0), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.method.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}
