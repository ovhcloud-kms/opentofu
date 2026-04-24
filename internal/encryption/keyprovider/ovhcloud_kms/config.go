// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"crypto/tls"

	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
	"github.com/ovh/okms-sdk-go"
)

var newOkmsClient = func(endpoint string, cfg okms.ClientConfig) (okmsClient, error) {
	return okms.NewRestAPIClient(endpoint, cfg)
}

// Required for mocking in tests
var tlsLoadX509KeyPair = tls.LoadX509KeyPair

type Config struct {
	OkmsID   string
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
