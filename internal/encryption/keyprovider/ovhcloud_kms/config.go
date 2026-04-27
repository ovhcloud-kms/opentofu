// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"strings"

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
	// OkmsID is filled automatically from the mTLS client certificate.
	// It is not an HCL field, the user can not set it.
	OkmsID string

	Endpoint string `hcl:"endpoint,optional"`
	KeyID    string `hcl:"key_id,optional"`
	CA       string `hcl:"ca,optional"`
	Cert     string `hcl:"cert,optional"`
	Key      string `hcl:"key,optional"`
	KeyBits  int32  `hcl:"key_bits,optional"`
}

func (c Config) Build() (keyprovider.KeyProvider, keyprovider.KeyMeta, error) {
	//TODO implement me
	//panic("implement me")
	return nil, nil, nil
}

func stringEnvFallback(val string, env string) string {
	if val != "" {
		return val
	}
	return os.Getenv(env)
}

func getOkmsIDFromCert(cert *x509.Certificate) (string, error) {
	for _, ext := range cert.Extensions { //
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
