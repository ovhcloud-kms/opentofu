// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"context"

	"github.com/google/uuid"
	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
)

type keyMeta struct {
	EncryptedKey string `json:"encrypted_key"`
}

type okmsClient interface {
	GenerateDataKey(ctx context.Context, okmsID, keyID uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error)
	DecryptDataKey(ctx context.Context, okmsID, keyID uuid.UUID, encryptedKey string) ([]byte, error)
}

type keyProvider struct {
}

func (k keyProvider) Provide(decryptionMeta keyprovider.KeyMeta) (keysOutput keyprovider.Output, encryptionMeta keyprovider.KeyMeta, err error) {
	//TODO implement me
	//panic("implement me")
	return keyprovider.Output{}, nil, nil
}
