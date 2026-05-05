// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"fmt"
	"os"
	"testing"

	"github.com/opentofu/opentofu/internal/encryption/keyprovider/compliancetest"
)

const (
	testEndpoint = "https://myserver.acme.com"
	testKeyID    = "00000000-0000-0000-0000-000000000000"
	testCert     = "cert.pem"
	testKey      = "key.pem"
	testOkmsID   = "00000000-0000-0000-0000-000000000001"
)

// getTestConfig returns a Config filled with environment variables when either TF_ACC or TF_OKMS_TEST is set,
// and all five required OKMS variables are present.
// The goal to set environment variables is to run the tests on a real OVHcloud KMS.
//
// Returns nil if any variable is missing, in which case, the mock is used.
//
// Required environment variables:
//
//	TF_ACC or TF_OKMS_TEST
//	TF_OKMS_ENDPOINT
//	TF_OKMS_KEY_ID
//	TF_OKMS_CERT
//	TF_OKMS_KEY
func getTestConfig(t *testing.T) *Config {
	t.Helper()

	if os.Getenv("TF_ACC") == "" && os.Getenv("TF_OKMS_TEST") == "" {
		return nil
	}

	endpoint := os.Getenv("TF_OKMS_ENDPOINT")
	keyID := os.Getenv("TF_OKMS_KEY_ID")
	cert := os.Getenv("TF_OKMS_CERT")
	key := os.Getenv("TF_OKMS_KEY")
	if endpoint == "" || keyID == "" || cert == "" || key == "" {
		return nil
	}

	return &Config{
		Endpoint: endpoint,
		KeyID:    keyID,
		Cert:     cert,
		Key:      key,
	}
}

func TestKeyProvider(t *testing.T) {
	cfg := getTestConfig(t)
	if cfg == nil {
		cfg = &Config{
			Endpoint: testEndpoint,
			KeyID:    testKeyID,
			Cert:     testCert,
			Key:      testKey,
		}
		injectMock(defaultMock())
	}

	compliancetest.ComplianceTest(
		t,
		compliancetest.TestConfiguration[*descriptor, *Config, *keyMeta, *keyProvider]{
			Descriptor: New().(*descriptor),
			HCLParseTestCases: map[string]compliancetest.HCLParseTestCase[*Config, *keyProvider]{
				"success": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							key_id = "%s"
							cert = "%s"
							key = "%s"
						}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidHCL:   true,
					ValidBuild: true,
					Validate: func(config *Config, keyProvider *keyProvider) error {
						if config.KeyID != cfg.KeyID {
							return fmt.Errorf("incorrect key id returned")
						}
						return nil
					},
				},
				"empty": {
					HCL:        fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {}`),
					ValidHCL:   true,
					ValidBuild: false,
				},
				"missing-key-id": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							cert = "%s"
							key = "%s"
						}`, cfg.Endpoint, cfg.Cert, cfg.Key),
					ValidHCL:   true,
					ValidBuild: false,
				},
				"missing-cert": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							key_id = "%s"
							key = "%s"
						}`, cfg.Endpoint, cfg.KeyID, cfg.Key),
					ValidHCL:   true,
					ValidBuild: false,
				},
				"missing-key": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							key_id = "%s"
							cert = "%s"
						}`, cfg.Endpoint, cfg.KeyID, cfg.Cert),
					ValidHCL:   true,
					ValidBuild: false,
				},
				"invalid-key-bits": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							key_id = "%s"
							cert = "%s"
							key = "%s"
							key_bits = 2
						}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidHCL:   true,
					ValidBuild: false,
				},
				"key-bits-256": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							key_id = "%s"
							cert = "%s"
							key = "%s"
							key_bits = 256
						}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidHCL:   true,
					ValidBuild: true,
				},
				"unknown property": {
					HCL: fmt.Sprintf(`key_provider "ovhcloud_kms" "foo" {
							endpoint = "%s"
							key_id = "%s"
							cert = "%s"
							key = "%s"
							unknown = 0
						}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidHCL:   false,
					ValidBuild: false,
				},
			},

			JSONParseTestCases: map[string]compliancetest.JSONParseTestCase[*Config, *keyProvider]{
				"success": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"key_id": "%s",
				"cert": "%s",
				"key": "%s"
			}
		}
	}
}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidJSON:  true,
					ValidBuild: true,
				},
				"empty": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {}
		}
	}
}`),
					ValidJSON:  true,
					ValidBuild: false,
				},
				"missing-key-id": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"cert": "%s",
				"key": "%s"
			}
		}
	}
}`, cfg.Endpoint, cfg.Cert, cfg.Key),
					ValidJSON:  true,
					ValidBuild: false,
				},
				"missing-cert": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"key_id": "%s",
				"key": "%s"
			}
		}
	}
}`, cfg.Endpoint, cfg.KeyID, cfg.Key),
					ValidJSON:  true,
					ValidBuild: false,
				},
				"missing-key": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"key_id": "%s",
				"cert": "%s"
			}
		}
	}
}`, cfg.Endpoint, cfg.KeyID, cfg.Cert),
					ValidJSON:  true,
					ValidBuild: false,
				},
				"invalid-key-bits": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"key_id": "%s",
				"cert": "%s",
				"key": "%s",
				"key_bits": 2
			}
		}
	}
}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidJSON:  true,
					ValidBuild: false,
				},
				"key-bits-256": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"key_id": "%s",
				"cert": "%s",
				"key": "%s",
				"key_bits": 256
			}
		}
	}
}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidJSON:  true,
					ValidBuild: true,
				},
				"unknown property": {
					JSON: fmt.Sprintf(`{
	"key_provider": {
		"ovhcloud_kms": {
			"foo": {
				"endpoint": "%s",
				"key_id": "%s",
				"cert": "%s",
				"key": "%s",
				"unknown": 0
			}
		}
	}
}`, cfg.Endpoint, cfg.KeyID, cfg.Cert, cfg.Key),
					ValidJSON:  false,
					ValidBuild: false,
				},
			},

			ConfigStructTestCases: map[string]compliancetest.ConfigStructTestCase[*Config, *keyProvider]{
				"success": {
					Config:     cfg,
					ValidBuild: true,
				},
				"empty": {
					Config:     &Config{},
					ValidBuild: false,
				},
			},

			MetadataStructTestCases: map[string]compliancetest.MetadataStructTestCase[*Config, *keyMeta]{
				"empty": {
					ValidConfig: cfg,
					Meta:        &keyMeta{},
					IsPresent:   false,
					IsValid:     false,
				},
				"invalid": {
					ValidConfig: cfg,
					Meta: &keyMeta{
						EncryptedKey: "not-valid",
					},
					IsPresent: true,
					IsValid:   false,
				},
			},

			ProvideTestCase: compliancetest.ProvideTestCase[*Config, *keyMeta]{
				ValidConfig: cfg,
				ValidateKeys: func(dec []byte, enc []byte) error {
					if len(dec) == 0 {
						return fmt.Errorf("decryption key is empty")
					}
					if len(enc) == 0 {
						return fmt.Errorf("encryption key is empty")
					}
					return nil
				},
				ValidateMetadata: func(meta *keyMeta) error {
					if len(meta.EncryptedKey) == 0 {
						return fmt.Errorf("encrypted key is empty")
					}
					return nil
				},
			},
		},
	)
}
