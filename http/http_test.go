// Copyright © 2026 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package http

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRoundTripper implements http.RoundTripper for testing
type mockRoundTripper struct {
	responses []*http.Response
	errors    []error
	callCount int
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.callCount >= len(m.responses) {
		m.callCount++
		if m.callCount-1 < len(m.errors) && m.errors[m.callCount-1] != nil {
			return nil, m.errors[m.callCount-1]
		}
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("unexpected call")),
		}, nil
	}

	resp := m.responses[m.callCount]
	var err error
	if m.callCount < len(m.errors) {
		err = m.errors[m.callCount]
	}
	m.callCount++
	return resp, err
}

// TestPostAdcsRequestInvalidURL tests error handling for invalid ADCS URL
func TestPostAdcsRequestInvalidURL(t *testing.T) {
	config := &CertConfig{
		AdcsUrl:         "://invalid-url",
		OidTemplate:     "WebServer",
		AdcsAuthMethods: Ntlm,
	}

	csrs := []CsrRequest{
		{Content: []byte("fake csr"), Filename: "test.csr"},
	}

	certs, errors := PostAdcsRequest("user", "pass", csrs, config)

	assert.Empty(t, certs)
	require.Len(t, errors, 1)
	assert.Contains(t, errors[0].Error(), "invalid adcs-url")
}

// TestPostAdcsRequestEmptyCSRList tests handling of empty CSR list
func TestPostAdcsRequestEmptyCSRList(t *testing.T) {
	config := &CertConfig{
		AdcsUrl:         "https://adcs.example.com/certsrv",
		OidTemplate:     "WebServer",
		AdcsAuthMethods: Ntlm,
	}

	csrs := []CsrRequest{}

	certs, errors := PostAdcsRequest("user", "pass", csrs, config)

	assert.Empty(t, certs)
	assert.Empty(t, errors)
}

// TestCertConfig tests CertConfig methods
func TestCertConfig(t *testing.T) {
	t.Run("SetAuthMethod", func(t *testing.T) {
		config := &CertConfig{}
		config.SetAuthMethod(Ntlm)
		assert.True(t, config.HasAuthMethod(Ntlm))
		assert.False(t, config.HasAuthMethod(Kerberos))

		config.SetAuthMethod(Kerberos)
		assert.False(t, config.HasAuthMethod(Ntlm))
		assert.True(t, config.HasAuthMethod(Kerberos))
	})

	t.Run("ClearAuthMethods", func(t *testing.T) {
		config := &CertConfig{}
		config.SetAuthMethod(Ntlm)
		assert.True(t, config.HasAuthMethod(Ntlm))

		config.ClearAuthMethods()
		assert.False(t, config.HasAuthMethod(Ntlm))
		assert.False(t, config.HasAuthMethod(Kerberos))
	})

	t.Run("SetAuthMethodString", func(t *testing.T) {
		config := &CertConfig{}

		config.SetAuthMethodString("ntlm")
		assert.True(t, config.HasAuthMethod(Ntlm))

		config.SetAuthMethodString("kerberos")
		assert.True(t, config.HasAuthMethod(Kerberos))
		assert.False(t, config.HasAuthMethod(Ntlm))

		config.SetAuthMethodString("invalid")
		assert.False(t, config.HasAuthMethod(Ntlm))
		assert.False(t, config.HasAuthMethod(Kerberos))
	})
}

// TestAuthMethodMap tests the AuthMethodMap
func TestAuthMethodMap(t *testing.T) {
	assert.Equal(t, Ntlm, AuthMethodMap["ntlm"])
	assert.Equal(t, Kerberos, AuthMethodMap["kerberos"])
	assert.Equal(t, AuthMethod(0), AuthMethodMap["invalid"])
}
