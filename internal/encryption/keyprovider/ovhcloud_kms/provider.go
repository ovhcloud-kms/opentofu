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

func (m *keyMeta) isPresent() bool {
	return m != nil && m.EncryptedKey != ""
}

type okmsClient interface {
	GenerateDataKey(ctx context.Context, okmsID, keyID uuid.UUID, name string, size int32) (plain []byte, encrypted string, err error)
	DecryptDataKey(ctx context.Context, okmsID, keyID uuid.UUID, encryptedKey string) ([]byte, error)
}

type keyProvider struct {
	svc     okmsClient
	ctx     context.Context
	okmsID  uuid.UUID
	keyID   uuid.UUID
	keyName string
	keyBits int32
}

func (k keyProvider) Provide(decryptionMeta keyprovider.KeyMeta) (keysOutput keyprovider.Output, encryptionMeta keyprovider.KeyMeta, err error) {
	if decryptionMeta == nil {
		return keyprovider.Output{}, nil, &keyprovider.ErrInvalidMetadata{
			Message: "bug: no metadata struct provided",
		}
	}
	//inMeta, ok := decryptionMeta.(*keyMeta)
	//if !ok {
	//	return keyprovider.Output{}, nil, &keyprovider.ErrInvalidMetadata{
	//		Message: "bug: invalid metadata struct type",
	//	}
	//}
	//
	//outMeta := &keyMeta{}
	//out := keyprovider.Output{}
	//
	//plainKey, encryptedKey, err := k.svc.GenerateDataKey(k.ctx, k.okmsID, k.keyID, k.keyName, k.keyBits)

	return keyprovider.Output{}, &keyMeta{}, nil
}
