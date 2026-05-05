// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
	"github.com/ovh/okms-sdk-go"
)

const (
	defaultKeyBits = 256
)

// Required for mocking in tests
var newOkmsClient = func(endpoint string, cfg okms.ClientConfig) (okmsClient, error) {
	return okms.NewRestAPIClient(endpoint, cfg)
}

// Required for mocking in tests
var loadMTLSConfig = func(certPath, keyPath string) ([]tls.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("could not load certificate: %w", err)
	}

	okmsID, err := getOkmsIDFromCert(cert.Leaf)
	if err != nil {
		return nil, "", err
	}
	return []tls.Certificate{cert}, okmsID, nil
}

type Config struct {
	Endpoint string `hcl:"endpoint,optional"`
	KeyID    string `hcl:"key_id,optional"`
	CA       string `hcl:"ca,optional"`
	Cert     string `hcl:"cert,optional"`
	Key      string `hcl:"key,optional"`
	KeyName  string `hcl:"key_name,optional"`
	KeyBits  int32  `hcl:"key_bits,optional"`
}

func (c Config) Build() (keyprovider.KeyProvider, keyprovider.KeyMeta, error) {
	c.Endpoint = stringEnvFallback(c.Endpoint, "TF_OKMS_ENDPOINT")
	c.KeyID = stringEnvFallback(c.KeyID, "TF_OKMS_KEY_ID")
	c.CA = stringEnvFallback(c.CA, "TF_OKMS_CA")
	c.Cert = stringEnvFallback(c.Cert, "TF_OKMS_CERT")
	c.Key = stringEnvFallback(c.Key, "TF_OKMS_KEY")
	c.KeyName = stringEnvFallback(c.KeyName, "TF_OKMS_KEY_NAME")
	c.KeyBits = int32EnvFallback(c.KeyBits, "TF_OKMS_KEY_BITS")
	if c.KeyBits == 0 {
		c.KeyBits = defaultKeyBits
	}

	if err := c.validate(); err != nil {
		return nil, nil, err
	}

	keyID, err := uuid.Parse(c.KeyID)
	if err != nil {
		return nil, nil, &keyprovider.ErrInvalidConfiguration{
			Message: fmt.Sprintf("key_id must be a valid UUID: %s", c.KeyID),
			Cause:   err,
		}
	}

	tlsConfig, okmsID, err := c.buildTLSConfig()
	if err != nil {
		return nil, nil, err
	}

	client, err := newOkmsClient(
		c.Endpoint,
		okms.ClientConfig{
			TlsCfg: tlsConfig,
		},
	)
	if err != nil {
		return nil, nil, &keyprovider.ErrInvalidConfiguration{
			Message: "failed to create OVHcloud KMS client",
			Cause:   err,
		}
	}

	return &keyProvider{
		svc:     client,
		ctx:     context.Background(),
		okmsID:  okmsID,
		keyID:   keyID,
		keyName: c.KeyName,
		keyBits: c.KeyBits,
	}, new(keyMeta), nil
}

func (c Config) validate() error {
	if c.Endpoint == "" {
		return &keyprovider.ErrInvalidConfiguration{
			Message: "endpoint is required",
		}
	}

	if c.KeyBits != 128 && c.KeyBits != 192 && c.KeyBits != 256 {
		return &keyprovider.ErrInvalidConfiguration{
			Message: fmt.Sprintf("key_bits must be 128, 192 or 256, got %d", c.KeyBits),
		}
	}

	if c.Cert == "" {
		return &keyprovider.ErrInvalidConfiguration{
			Message: "cert is required",
		}
	}
	if c.Key == "" {
		return &keyprovider.ErrInvalidConfiguration{
			Message: "key is required",
		}
	}

	return nil
}

func (c Config) buildTLSConfig() (*tls.Config, uuid.UUID, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if c.CA != "" {
		if err := loadCertPool(tlsConfig, c.CA); err != nil {
			return nil, uuid.Nil, &keyprovider.ErrInvalidConfiguration{
				Message: "failed to load CA",
				Cause:   err,
			}
		}
	}

	certs, okmsIDStr, err := loadMTLSConfig(c.Cert, c.Key)
	if err != nil {
		return nil, uuid.Nil, &keyprovider.ErrInvalidConfiguration{
			Message: "failed to load MTLS configuration",
			Cause:   err,
		}
	}
	tlsConfig.Certificates = certs

	okmsID, err := uuid.Parse(okmsIDStr)
	if err != nil {
		return nil, uuid.Nil, &keyprovider.ErrInvalidConfiguration{
			Message: fmt.Sprintf("okms_id must be a valid UUID: %s", okmsIDStr),
			Cause:   err,
		}
	}

	return tlsConfig, okmsID, nil
}

func stringEnvFallback(val string, env string) string {
	if val != "" {
		return val
	}
	return os.Getenv(env)
}

func int32EnvFallback(val int32, env string) int32 {
	if val != 0 {
		return val
	}

	if s := os.Getenv(env); s != "" {
		if n, err := strconv.ParseInt(s, 10, 32); err == nil {
			return int32(n)
		}
	}
	return val
}

func loadCertPool(tlsConfig *tls.Config, CA string) error {
	pool, err := getCertPool(CA)
	if err != nil {
		return fmt.Errorf("failed to get CA: %w", err)
	}
	tlsConfig.RootCAs = pool
	return nil
}

func getCertPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("could not load system certificates pool: %w", err)
	}

	if caFile != "" {
		caBundle, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("could not load CA file %q: %w", caFile, err)
		}
		if !pool.AppendCertsFromPEM(caBundle) {
			return nil, fmt.Errorf("invalid CA certificate: %q", caFile)
		}
	}
	return pool, nil
}

func getOkmsIDFromCert(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions {
		// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var seq asn1.RawValue
		_, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil {
			return "", err
		}
		for rest := seq.Bytes; len(rest) > 0; {
			var val asn1.RawValue
			rest, err = asn1.Unmarshal(rest, &val)
			if err != nil {
				return "", err
			}
			if val.Tag != 0 {
				continue
			}

			var oid asn1.ObjectIdentifier
			rem, err := asn1.Unmarshal(val.Bytes, &oid)
			if err != nil {
				return "", err
			}
			if !oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}) {
				continue
			}
			if _, err = asn1.Unmarshal(rem, &val); err != nil {
				return "", err
			}
			var othername string
			if _, err := asn1.Unmarshal(val.Bytes, &othername); err != nil {
				return "", err
			}
			prefix := "okms.domain:"
			if strings.HasPrefix(othername, prefix) {
				return othername[len(prefix):], nil
			}
		}
	}
	return "", errors.New("no okms domain id found")
}
