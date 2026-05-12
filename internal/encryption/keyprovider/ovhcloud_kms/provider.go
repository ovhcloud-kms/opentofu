// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"context"
	"fmt"

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
	inMeta, ok := decryptionMeta.(*keyMeta)
	if !ok {
		return keyprovider.Output{}, nil, &keyprovider.ErrInvalidMetadata{
			Message: "bug: invalid metadata struct type",
		}
	}

	plainKey, encryptedKey, err := k.svc.GenerateDataKey(k.ctx, k.okmsID, k.keyID, k.keyName, k.keyBits)
	if err != nil {
		return keyprovider.Output{}, nil, &keyprovider.ErrKeyProviderFailure{
			Message: fmt.Sprintf("failed to generate data key (okms_id=%s, key_id=%s)", k.okmsID, k.keyID),
			Cause:   err,
		}
	}

	out := keyprovider.Output{
		EncryptionKey: plainKey,
	}
	outMeta := &keyMeta{
		EncryptedKey: encryptedKey,
	}

	if inMeta.isPresent() {
		decryptedKey, err := k.svc.DecryptDataKey(k.ctx, k.okmsID, k.keyID, inMeta.EncryptedKey)
		if err != nil {
			return out, outMeta, &keyprovider.ErrInvalidMetadata{
				Message: fmt.Sprintf("failed to decrypt data key (okms_id=%s, key_id=%s)", k.okmsID, k.keyID),
				Cause:   err,
			}
		}
		out.DecryptionKey = decryptedKey
	}

	return out, outMeta, nil
}
