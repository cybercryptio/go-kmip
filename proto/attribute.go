package proto

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"time"

	"github.com/pkg/errors"

	"github.com/cybercryptio/go-kmip/ttlv"
)

// Attribute is a Attribute Object Structure
type Attribute struct {
	ttlv.Tag `kmip:"ATTRIBUTE"`

	Name  string      `kmip:"ATTRIBUTE_NAME"`
	Index int32       `kmip:"ATTRIBUTE_INDEX"`
	Value interface{} `kmip:"ATTRIBUTE_VALUE"`
}

// BuildFieldValue builds dynamic Value field
func (a *Attribute) BuildFieldValue(name string) (v interface{}, err error) {
	switch a.Name {
	case ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM:
		return ttlv.Enum(0), nil
	case ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK:
		return int32(0), nil
	case ttlv.ATTRIBUTE_NAME_UNIQUE_IDENTIFIER, ttlv.ATTRIBUTE_NAME_OPERATION_POLICY_NAME:
		return "", nil
	case ttlv.ATTRIBUTE_NAME_OBJECT_TYPE, ttlv.ATTRIBUTE_NAME_STATE:
		return ttlv.Enum(0), nil
	case ttlv.ATTRIBUTE_NAME_INITIAL_DATE, ttlv.ATTRIBUTE_NAME_LAST_CHANGE_DATE:
		return time.Time{}, nil
	case ttlv.ATTRIBUTE_NAME_NAME:
		return &Name{}, nil
	case ttlv.ATTRIBUTE_NAME_DIGEST:
		return &Digest{}, nil
	default:
		return nil, errors.Errorf("unsupported attribute: %v", a.Name)
	}
}

// Attributes is a sequence of Attribute objects which allows building and search
type Attributes []Attribute

func (attrs Attributes) Get(name string) interface{} {
	for i := range attrs {
		if attrs[i].Name == name {
			return attrs[i].Value
		}
	}

	return nil
}

// TemplateAttribute is a Template-Attribute Object Structure
type TemplateAttribute struct {
	ttlv.Tag `kmip:"TEMPLATE_ATTRIBUTE"`

	Name       Name       `kmip:"NAME"`
	Attributes Attributes `kmip:"ATTRIBUTE"`
}

// Name is a Name Attribute Structure
type Name struct {
	ttlv.Tag `kmip:"NAME"`

	Value string    `kmip:"NAME_VALUE,required"`
	Type  ttlv.Enum `kmip:"NAME_TYPE,required"`
}

// Digest is a Digest Attribute Structure
type Digest struct {
	ttlv.Tag `kmip:"DIGEST"`

	HashingAlgorithm ttlv.Enum `kmip:"HASHING_ALGORITHM,required"`
	DigestValue      []byte    `kmip:"DIGEST_VALUE"`
	KeyFormatType    ttlv.Enum `kmip:"KEY_FORMAT_TYPE"`
}
