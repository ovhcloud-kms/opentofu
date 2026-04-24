// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ovhcloud_kms

import (
	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
)

func New() keyprovider.Descriptor {
	return &descriptor{}
}

type descriptor struct{}

func (d descriptor) ID() keyprovider.ID {
	return "ovhcloud_kms"
}

func (d descriptor) ConfigStruct() keyprovider.Config {
	return &Config{}
}
