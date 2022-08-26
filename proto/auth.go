package proto

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"github.com/pkg/errors"

	"github.com/cybercryptio/go-kmip/ttlv"
)

// Authentication is an Authentication structure
type Authentication struct {
	ttlv.Tag `kmip:"AUTHENTICATION"`

	CredentialType  ttlv.Enum   `kmip:"CREDENTIAL_TYPE,required"`
	CredentialValue interface{} `kmip:"CREDENTIAL_VALUE,required"`
}

// BuildFieldValue builds value for CredentialValue based on CredentialType
func (a *Authentication) BuildFieldValue(name string) (interface{}, error) {
	switch a.CredentialType {
	case ttlv.CREDENTIAL_TYPE_USERNAME_AND_PASSWORD:
		return &CredentialUsernamePassword{}, nil
	default:
		return nil, errors.Errorf("unsupported credential type: %v", a.CredentialType)
	}
}

// CredentialUsernamePassword is a Credential structure for username/password authentication
type CredentialUsernamePassword struct {
	ttlv.Tag `kmip:"CREDENTIAL_VALUE"`

	Username string `kmip:"USERNAME,required"`
	Password string `kmip:"PASSWORD,required"`
}
