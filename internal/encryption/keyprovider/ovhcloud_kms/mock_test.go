// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/ovh/okms-sdk-go"
)

type mockOkmsClient struct {
	generateDataKey func(okmsID, keyID uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error)
	decryptDataKey  func(okmsID, keyID uuid.UUID, encryptedKey string) ([]byte, error)
}

func (m *mockOkmsClient) GenerateDataKey(_ context.Context, okmsID, keyID uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error) {
	return m.generateDataKey(okmsID, keyID, name, size)
}

func (m *mockOkmsClient) DecryptDataKey(_ context.Context, okmsID, keyID uuid.UUID, encryptedKey string) ([]byte, error) {
	return m.decryptDataKey(okmsID, keyID, encryptedKey)
}

func injectMock(m *mockOkmsClient) {
	newOkmsClient = func(_ string, _ okms.ClientConfig) (okmsClient, error) {
		return m, nil
	}
	loadMTLSConfig = func(_, _ string) ([]tls.Certificate, string, error) {
		return []tls.Certificate{}, testOkmsID, nil
	}
}

// defaultMock returns a mockOkmsClient that simulates OKMS locally
func defaultMock() *mockOkmsClient {
	return &mockOkmsClient{
		generateDataKey: func(_, _ uuid.UUID, _ string, size int32) ([]byte, string, error) {
			keyBytes := make([]byte, size/8) // bits to bytes
			if _, err := rand.Read(keyBytes); err != nil {
				return nil, "", fmt.Errorf("mock: failed to generate random key: %w", err)
			}
			return keyBytes, base64.StdEncoding.EncodeToString(keyBytes), nil
		},
		decryptDataKey: func(_, _ uuid.UUID, encryptedKey string) ([]byte, error) {
			return base64.StdEncoding.DecodeString(encryptedKey)
		},
	}
}
