// Copyright © 2026 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyContainerString tests the String() method for KeyContainer enum
func TestKeyContainerString(t *testing.T) {
	tests := []struct {
		name      string
		container KeyContainer
		expected  string
	}{
		{"PKCS1", PKCS1, "PKCS#1"},
		{"PKCS8", PKCS8, "PKCS#8"},
		{"SEC1", SEC1, "SEC 1"},
		{"Unknown", UnknownKeyContainer, "unknown container"},
		{"Invalid", KeyContainer(99), "unknown container"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.container.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestEcSizeString tests the String() method for EcSize enum
func TestEcSizeString(t *testing.T) {
	tests := []struct {
		name     string
		size     EcSize
		expected string
	}{
		{"P224", P224, "P-224/secp224r1"},
		{"P256", P256, "P-256/secp256r1"},
		{"P384", P384, "P-384/secp384r1"},
		{"P521", P521, "P-521/secp521r1"},
		{"Unknown", UnknownEcSize, "unknown EC size"},
		{"Invalid", EcSize(99), "unknown EC size"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.size.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGenerateKey tests key generation for all supported algorithms
func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name      string
		request   *KeyRequest
		expectErr bool
		validate  func(t *testing.T, key any)
	}{
		{
			name: "RSA_2048",
			request: &KeyRequest{
				Type:    x509.RSA,
				RsaSize: 2048,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				rsaKey, ok := key.(*rsa.PrivateKey)
				require.True(t, ok, "key should be *rsa.PrivateKey")
				assert.Equal(t, 2048, rsaKey.N.BitLen())
			},
		},
		{
			name: "RSA_4096",
			request: &KeyRequest{
				Type:    x509.RSA,
				RsaSize: 4096,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				rsaKey, ok := key.(*rsa.PrivateKey)
				require.True(t, ok, "key should be *rsa.PrivateKey")
				assert.Equal(t, 4096, rsaKey.N.BitLen())
			},
		},
		{
			name: "ECDSA_P224",
			request: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: P224,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				require.True(t, ok, "key should be *ecdsa.PrivateKey")
				assert.Equal(t, 224, ecdsaKey.Params().BitSize)
			},
		},
		{
			name: "ECDSA_P256",
			request: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: P256,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				require.True(t, ok, "key should be *ecdsa.PrivateKey")
				assert.Equal(t, 256, ecdsaKey.Params().BitSize)
			},
		},
		{
			name: "ECDSA_P384",
			request: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: P384,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				require.True(t, ok, "key should be *ecdsa.PrivateKey")
				assert.Equal(t, 384, ecdsaKey.Params().BitSize)
			},
		},
		{
			name: "ECDSA_P521",
			request: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: P521,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				ecdsaKey, ok := key.(*ecdsa.PrivateKey)
				require.True(t, ok, "key should be *ecdsa.PrivateKey")
				assert.Equal(t, 521, ecdsaKey.Params().BitSize)
			},
		},
		{
			name: "ECDSA_InvalidSize",
			request: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: UnknownEcSize,
			},
			expectErr: true,
		},
		{
			name: "Ed25519",
			request: &KeyRequest{
				Type: x509.Ed25519,
			},
			expectErr: false,
			validate: func(t *testing.T, key any) {
				ed25519Key, ok := key.(ed25519.PrivateKey)
				require.True(t, ok, "key should be ed25519.PrivateKey")
				assert.Equal(t, ed25519.PrivateKeySize, len(ed25519Key))
			},
		},
		{
			name: "DSA_Rejected",
			request: &KeyRequest{
				Type: x509.DSA,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.request)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, key)
				if tt.validate != nil {
					tt.validate(t, key)
				}
			}
		})
	}
}

// TestWriteKeyAndGetKey tests the WriteKey -> GetKey round-trip for all key types
func TestWriteKeyAndGetKey(t *testing.T) {
	tests := []struct {
		name      string
		genReq    *KeyRequest
		writeReq  *KeyRequest
		expectErr bool
	}{
		{
			name: "RSA_PKCS1",
			genReq: &KeyRequest{
				Type:    x509.RSA,
				RsaSize: 2048,
			},
			writeReq: &KeyRequest{
				Type:      x509.RSA,
				Container: PKCS1,
			},
			expectErr: false,
		},
		{
			name: "RSA_PKCS8",
			genReq: &KeyRequest{
				Type:    x509.RSA,
				RsaSize: 2048,
			},
			writeReq: &KeyRequest{
				Type:      x509.RSA,
				Container: PKCS8,
			},
			expectErr: false,
		},
		{
			name: "ECDSA_SEC1",
			genReq: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: P256,
			},
			writeReq: &KeyRequest{
				Type:      x509.ECDSA,
				Container: SEC1,
			},
			expectErr: false,
		},
		{
			name: "ECDSA_PKCS8",
			genReq: &KeyRequest{
				Type:   x509.ECDSA,
				EcSize: P384,
			},
			writeReq: &KeyRequest{
				Type:      x509.ECDSA,
				Container: PKCS8,
			},
			expectErr: false,
		},
		{
			name: "Ed25519_PKCS8",
			genReq: &KeyRequest{
				Type: x509.Ed25519,
			},
			writeReq: &KeyRequest{
				Type:      x509.Ed25519,
				Container: PKCS8,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			keyFile := filepath.Join(tmpDir, "test.key")

			// Generate key
			key, err := GenerateKey(tt.genReq)
			require.NoError(t, err)
			require.NotNil(t, key)

			// Write key
			tt.writeReq.Filename = keyFile
			err = WriteKey(key, tt.writeReq)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify file was created with correct permissions
			//TODO: what happens here when testing on windows filesystem?
			info, err := os.Stat(keyFile)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "key file should have 0600 permissions")

			// Read key back
			readReq := &KeyRequest{Filename: keyFile}
			readKey, err := GetKey(readReq)
			require.NoError(t, err)
			require.NotNil(t, readKey)

			// Verify type matches
			assert.Equal(t, tt.writeReq.Type, readReq.Type)
			assert.Equal(t, tt.writeReq.Container, readReq.Container)

			// Type-specific validation
			switch tt.writeReq.Type {
			case x509.RSA:
				origRSA, ok1 := key.(*rsa.PrivateKey)
				readRSA, ok2 := readKey.(*rsa.PrivateKey)
				require.True(t, ok1 && ok2)
				assert.Equal(t, origRSA.N, readRSA.N)
				assert.Equal(t, origRSA.E, readRSA.E)
			case x509.ECDSA:
				origEC, ok1 := key.(*ecdsa.PrivateKey)
				readEC, ok2 := readKey.(*ecdsa.PrivateKey)
				require.True(t, ok1 && ok2)
				assert.Equal(t, origEC.D, readEC.D)
				assert.Equal(t, origEC.X, readEC.X)
				assert.Equal(t, origEC.Y, readEC.Y)
			case x509.Ed25519:
				origEd, ok1 := key.(ed25519.PrivateKey)
				readEd, ok2 := readKey.(ed25519.PrivateKey)
				require.True(t, ok1 && ok2)
				assert.Equal(t, origEd, readEd)
			}
		})
	}
}

// TestGetKeyErrors tests error cases for GetKey
func TestGetKeyErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupFile func(t *testing.T, tmpDir string) string
		expectErr string
	}{
		{
			name: "FileNotFound",
			setupFile: func(t *testing.T, tmpDir string) string {
				return filepath.Join(tmpDir, "nonexistent.key")
			},
			expectErr: "could not read file",
		},
		{
			name: "InvalidPEM",
			setupFile: func(t *testing.T, tmpDir string) string {
				keyFile := filepath.Join(tmpDir, "invalid.key")
				err := os.WriteFile(keyFile, []byte("not a PEM file"), 0600)
				require.NoError(t, err)
				return keyFile
			},
			expectErr: "could not parse PEM block",
		},
		{
			name: "WrongPEMType",
			setupFile: func(t *testing.T, tmpDir string) string {
				keyFile := filepath.Join(tmpDir, "wrong.key")
				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("fake cert"),
				}
				err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600)
				require.NoError(t, err)
				return keyFile
			},
			expectErr: "could not parse PEM block",
		},
		{
			name: "CorruptKeyData",
			setupFile: func(t *testing.T, tmpDir string) string {
				keyFile := filepath.Join(tmpDir, "corrupt.key")
				block := &pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: []byte("corrupt key data"),
				}
				err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600)
				require.NoError(t, err)
				return keyFile
			},
			expectErr: "could not parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			keyFile := tt.setupFile(t, tmpDir)

			req := &KeyRequest{Filename: keyFile}
			key, err := GetKey(req)

			require.Error(t, err)
			assert.Nil(t, key)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// TestWriteKeyErrors tests error cases for WriteKey
func TestWriteKeyErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("PKCS1_NonRSA", func(t *testing.T) {
		key, err := GenerateKey(&KeyRequest{Type: x509.ECDSA, EcSize: P256})
		require.NoError(t, err)

		req := &KeyRequest{
			Filename:  filepath.Join(tmpDir, "test.key"),
			Type:      x509.ECDSA,
			Container: PKCS1,
		}
		err = WriteKey(key, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only RSA keys are supported")
	})

	t.Run("SEC1_NonECDSA", func(t *testing.T) {
		key, err := GenerateKey(&KeyRequest{Type: x509.RSA, RsaSize: 2048})
		require.NoError(t, err)

		req := &KeyRequest{
			Filename:  filepath.Join(tmpDir, "test2.key"),
			Type:      x509.RSA,
			Container: SEC1,
		}
		err = WriteKey(key, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only ECDSA keys are supported")
	})

	t.Run("InvalidPath", func(t *testing.T) {
		key, err := GenerateKey(&KeyRequest{Type: x509.RSA, RsaSize: 2048})
		require.NoError(t, err)

		req := &KeyRequest{
			Filename:  "/nonexistent/path/test.key",
			Type:      x509.RSA,
			Container: PKCS8,
		}
		err = WriteKey(key, req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not open file for writing")
	})
}

// TestGenerateCsr tests CSR generation with various configurations
func TestGenerateCsr(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a test key
	keyReq := &KeyRequest{Type: x509.RSA, RsaSize: 2048}
	key, err := GenerateKey(keyReq)
	require.NoError(t, err)

	tests := []struct {
		name     string
		cn       string
		c        string
		st       string
		l        string
		o        string
		ou       string
		email    string
		dns      []string
		ips      []net.IP
		validate func(t *testing.T, csr *x509.CertificateRequest)
	}{
		{
			name: "BasicCN",
			cn:   "example.com",
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.Equal(t, "example.com", csr.Subject.CommonName)
			},
		},
		{
			name:  "AllSubjectFields",
			cn:    "test.example.com",
			c:     "US",
			st:    "California",
			l:     "San Francisco",
			o:     "Example Corp",
			ou:    "Engineering",
			email: "test@example.com",
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.Equal(t, "test.example.com", csr.Subject.CommonName)
				assert.Equal(t, []string{"US"}, csr.Subject.Country)
				assert.Equal(t, []string{"California"}, csr.Subject.Province)
				assert.Equal(t, []string{"San Francisco"}, csr.Subject.Locality)
				assert.Equal(t, []string{"Example Corp"}, csr.Subject.Organization)
				assert.Equal(t, []string{"Engineering"}, csr.Subject.OrganizationalUnit)
				// Email is encoded in the subject's raw attributes, but may not be
				// directly accessible in the parsed Subject.ExtraNames after parsing
			},
		},
		{
			name: "DNSNames",
			cn:   "example.com",
			dns:  []string{"example.com", "www.example.com", "api.example.com"},
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.Equal(t, []string{"example.com", "www.example.com", "api.example.com"}, csr.DNSNames)
			},
		},
		{
			name: "IPAddresses",
			cn:   "server.example.com",
			ips:  []net.IP{net.ParseIP("10.1.2.3"), net.ParseIP("192.168.1.1")},
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.Equal(t, 2, len(csr.IPAddresses))
				assert.Equal(t, "10.1.2.3", csr.IPAddresses[0].String())
				assert.Equal(t, "192.168.1.1", csr.IPAddresses[1].String())
			},
		},
		{
			name: "DNSAndIP",
			cn:   "multi.example.com",
			dns:  []string{"multi.example.com"},
			ips:  []net.IP{net.ParseIP("10.0.0.1")},
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.Equal(t, []string{"multi.example.com"}, csr.DNSNames)
				assert.Equal(t, 1, len(csr.IPAddresses))
				assert.Equal(t, "10.0.0.1", csr.IPAddresses[0].String())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csrFile := filepath.Join(tmpDir, tt.name+".csr")

			block, err := GenerateCsr(csrFile, key, tt.cn, tt.c, tt.st, tt.l, tt.o, tt.ou, tt.email, tt.dns, tt.ips)
			require.NoError(t, err)
			require.NotNil(t, block)
			assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

			// Verify file was created
			_, err = os.Stat(csrFile)
			require.NoError(t, err)

			// Parse the CSR
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			require.NoError(t, err)

			// Verify signature
			err = csr.CheckSignature()
			require.NoError(t, err)

			// Run custom validation
			if tt.validate != nil {
				tt.validate(t, csr)
			}

			// Verify extensions are present
			hasKeyUsage := false
			hasBasicConstraints := false
			for _, ext := range csr.Extensions {
				if ext.Id.Equal([]int{2, 5, 29, 15}) {
					hasKeyUsage = true
				}
				if ext.Id.Equal([]int{2, 5, 29, 19}) {
					hasBasicConstraints = true
				}
			}
			assert.True(t, hasKeyUsage, "CSR should have Key Usage extension")
			assert.True(t, hasBasicConstraints, "CSR should have Basic Constraints extension")
		})
	}
}

// TestGenerateCsrErrors tests error cases for GenerateCsr
func TestGenerateCsrErrors(t *testing.T) {
	keyReq := &KeyRequest{Type: x509.RSA, RsaSize: 2048}
	key, err := GenerateKey(keyReq)
	require.NoError(t, err)

	t.Run("InvalidPath", func(t *testing.T) {
		_, err := GenerateCsr("/nonexistent/path/test.csr", key, "example.com", "", "", "", "", "", "", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not open file for writing")
	})
}

// TestWriteCert tests certificate writing
func TestWriteCert(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Success", func(t *testing.T) {
		certFile := filepath.Join(tmpDir, "test.crt")
		certData := []byte("-----BEGIN CERTIFICATE-----\ntest cert data\n-----END CERTIFICATE-----")

		err := WriteCert(certFile, certData)
		require.NoError(t, err)

		// Verify file was created
		//TODO: what happens here when running on windows filesystem?
		info, err := os.Stat(certFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

		// Verify contents
		readData, err := os.ReadFile(certFile)
		require.NoError(t, err)
		assert.Equal(t, certData, readData)
	})

	t.Run("InvalidPath", func(t *testing.T) {
		err := WriteCert("/nonexistent/path/test.crt", []byte("data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not open file for writing")
	})
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("GenerateCSR_EmptyOptionalFields", func(t *testing.T) {
		tmpDir := t.TempDir()
		csrFile := filepath.Join(tmpDir, "empty.csr")

		keyReq := &KeyRequest{Type: x509.RSA, RsaSize: 2048}
		key, err := GenerateKey(keyReq)
		require.NoError(t, err)

		// Only CN is required
		block, err := GenerateCsr(csrFile, key, "example.com", "", "", "", "", "", "", nil, nil)
		require.NoError(t, err)
		require.NotNil(t, block)

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "example.com", csr.Subject.CommonName)
		assert.Empty(t, csr.Subject.Country)
		assert.Empty(t, csr.Subject.Province)
		assert.Empty(t, csr.DNSNames)
		assert.Empty(t, csr.IPAddresses)
	})

	t.Run("RoundTrip_MultipleKeyTypes", func(t *testing.T) {
		tmpDir := t.TempDir()

		keyTypes := []struct {
			name    string
			keyType x509.PublicKeyAlgorithm
			genReq  *KeyRequest
		}{
			{"RSA", x509.RSA, &KeyRequest{Type: x509.RSA, RsaSize: 2048}},
			{"ECDSA", x509.ECDSA, &KeyRequest{Type: x509.ECDSA, EcSize: P256}},
			{"Ed25519", x509.Ed25519, &KeyRequest{Type: x509.Ed25519}},
		}

		for _, kt := range keyTypes {
			t.Run(kt.name, func(t *testing.T) {
				key, err := GenerateKey(kt.genReq)
				require.NoError(t, err)

				keyFile := filepath.Join(tmpDir, strings.ToLower(kt.name)+".key")
				writeReq := &KeyRequest{
					Filename:  keyFile,
					Type:      kt.keyType,
					Container: PKCS8,
				}
				err = WriteKey(key, writeReq)
				require.NoError(t, err)

				readReq := &KeyRequest{Filename: keyFile}
				readKey, err := GetKey(readReq)
				require.NoError(t, err)
				require.NotNil(t, readKey)
				assert.Equal(t, kt.keyType, readReq.Type)
			})
		}
	})
}
