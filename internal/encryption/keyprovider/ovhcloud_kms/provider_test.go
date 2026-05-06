// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"testing"

	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildProvider(t *testing.T) (keyprovider.KeyProvider, keyprovider.KeyMeta) {
	t.Helper()

	injectMock(defaultMock())
	cfg := Config{
		Endpoint: testEndpoint,
		KeyID:    testKeyID,
		Cert:     testCert,
		Key:      testKey,
	}

	provider, meta, err := cfg.Build()
	require.NoError(t, err)

	return provider, meta
}

func TestProvider_KeyRotation(t *testing.T) {
	provider, meta := buildProvider(t)

	output1, encryptionMeta, err := provider.Provide(meta)
	require.NoError(t, err)

	output2, _, err := provider.Provide(encryptionMeta)
	require.NoError(t, err)

	assert.Equal(t, output1.EncryptionKey, output2.DecryptionKey)
	assert.NotEqual(t, output1.EncryptionKey, output2.EncryptionKey)
}
