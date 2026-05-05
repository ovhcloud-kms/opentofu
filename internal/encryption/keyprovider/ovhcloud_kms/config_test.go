// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_EnvVarFallbacks(t *testing.T) {
	injectMock(defaultMock())

	t.Setenv("TF_OKMS_ENDPOINT", testEndpoint)
	t.Setenv("TF_OKMS_KEY_ID", testKeyID)
	t.Setenv("TF_OKMS_CERT", testCert)
	t.Setenv("TF_OKMS_KEY", testKey)

	cfg := Config{}
	_, _, err := cfg.Build()
	require.NoError(t, err)
}

func TestConfig_HCLField(t *testing.T) {
	injectMock(defaultMock())

	t.Setenv("TF_OKMS_ENDPOINT", "test-env")

	cfg := Config{
		Endpoint: testEndpoint,
		KeyID:    testKeyID,
		Cert:     testCert,
		Key:      testKey,
	}
	_, _, err := cfg.Build()
	require.NoError(t, err)
}
