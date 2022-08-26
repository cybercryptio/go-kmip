package proto

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"github.com/cybercryptio/go-kmip/ttlv"
)

// KeyWrappingSpecification is a Key Wrapping Specification Object
type KeyWrappingSpecification struct {
	ttlv.Tag `kmip:"KEY_WRAPPING_SPECIFICATION"`

	WrappingMethod             ttlv.Enum                  `kmip:"WRAPPING_METHOD,required"`
	EncryptionKeyInformation   EncryptionKeyInformation   `kmip:"ENCRYPTION_KEY_INFORMATION"`
	MACSignatureKeyInformation MACSignatureKeyInformation `kmip:"MAC_SIGNATURE_KEY_INFORMATION"`
	AttributeName              []string                   `kmip:"ATTRIBUTE_NAME"`
	EncodingOption             ttlv.Enum                  `kmip:"ENCODING_OPTION"`
}

// KeyWrappingData is a Key Wrapping Data Object Structure
type KeyWrappingData struct {
	ttlv.Tag `kmip:"KEY_WRAPPING_DATA"`

	WrappingMethod             ttlv.Enum                  `kmip:"WRAPPING_METHOD,required"`
	EncryptionKeyInformation   EncryptionKeyInformation   `kmip:"ENCRYPTION_KEY_INFORMATION"`
	MACSignatureKeyInformation MACSignatureKeyInformation `kmip:"MAC_SIGNATURE_KEY_INFORMATION"`
	MACSignature               []byte                     `kmip:"MAC_SIGNATURE"`
	IVCounterNonce             []byte                     `kmip:"IV_COUNTER_NONCE"`
	EncodingOption             ttlv.Enum                  `kmip:"ENCODING_OPTION"`
}

// EncryptionKeyInformation is a Key Wrapping Specification Object
type EncryptionKeyInformation struct {
	ttlv.Tag `kmip:"ENCRYPTION_KEY_INFORMATION"`

	UniqueIdentifier string       `kmip:"UNIQUE_IDENTIFIER,required"`
	CryptoParams     CryptoParams `kmip:"CRYPTOGRAPHIC_PARAMETERS"`
}

// MACSignatureKeyInformation is a MAC/Signature Key Information Object Structure
type MACSignatureKeyInformation struct {
	ttlv.Tag `kmip:"MAC_SIGNATURE_KEY_INFORMATION"`

	UniqueIdentifier string       `kmip:"UNIQUE_IDENTIFIER,required"`
	CryptoParams     CryptoParams `kmip:"CRYPTOGRAPHIC_PARAMETERS"`
}

// CryptoParams is a Cryptographic Parameters Attribute Structure
type CryptoParams struct {
	ttlv.Tag `kmip:"CRYPTOGRAPHIC_PARAMETERS"`

	BlockCipherMode               ttlv.Enum `kmip:"BLOCK_CIPHER_MODE"`
	PaddingMethod                 ttlv.Enum `kmip:"PADDING_METHOD"`
	HashingAlgorithm              ttlv.Enum `kmip:"HASHING_ALGORITHM"`
	KeyRoleType                   ttlv.Enum `kmip:"KEY_ROLE_TYPE"`
	DigitalSignatureAlgorithm     ttlv.Enum `kmip:"DIGITAL_SIGNATURE_ALGORITHM"`
	CryptographicAlgorithm        ttlv.Enum `kmip:"CRYPTOGRAPHIC_ALGORITHM"`
	RandomIV                      bool      `kmip:"RANDOM_IV"`
	IVLength                      int32     `kmip:"IV_LENGTH"`
	TagLength                     int32     `kmip:"TAG_LENGTH"`
	FixedFieldLength              int32     `kmip:"FIXED_FIELD_LENGTH"`
	InvocationFieldLength         int32     `kmip:"INVOCATION_FIELD_LENGTH"`
	CounterLength                 int32     `kmip:"COUNTER_LENGTH"`
	InitialCounterValue           int32     `kmip:"INITIAL_COUNTER_VALUE"`
	SaltLength                    int32     `kmip:"SALT_LENGTH"`
	MaskGenerator                 ttlv.Enum `kmip:"MASK_GENERATOR"`
	MaskGeneratorHashingAlgorithm ttlv.Enum `kmip:"MASK_GENERATOR_HASHING_ALGORITHM"`
	PSource                       []byte    `kmip:"P_SOURCE"`
	TrailerFIeld                  int32     `kmip:"TRAILER_FIELD"`
}

// SymmetricKey is a Managed Cryptographic Object that is a symmetric key
type SymmetricKey struct {
	ttlv.Tag `kmip:"SYMMETRIC_KEY"`

	KeyBlock KeyBlock `kmip:"KEY_BLOCK,required"`
}

// PublicKey is a Managed Cryptographic Object that is a public key
type PublicKey struct {
	ttlv.Tag `kmip:"PUBLIC_KEY"`

	KeyBlock KeyBlock `kmip:"KEY_BLOCK,required"`
}

// PrivateKey is a Managed Cryptographic Object that is a private key
type PrivateKey struct {
	ttlv.Tag `kmip:"PRIVATE_KEY"`

	KeyBlock KeyBlock `kmip:"KEY_BLOCK,required"`
}

// KeyBlock is a Key Block Object Structure
type KeyBlock struct {
	ttlv.Tag `kmip:"KEY_BLOCK"`

	FormatType             ttlv.Enum       `kmip:"KEY_FORMAT_TYPE,required"`
	CompressionType        ttlv.Enum       `kmip:"KEY_COMPRESSION_TYPE"`
	Value                  KeyValue        `kmip:"KEY_VALUE,required"`
	CryptographicAlgorithm ttlv.Enum       `kmip:"CRYPTOGRAPHIC_ALGORITHM"`
	CryptographicLength    int32           `kmip:"CRYPTOGRAPHIC_LENGTH"`
	WrappingData           KeyWrappingData `kmip:"KEY_WRAPPING_SPECIFICATION"`
}

// KeyValue is a Key Value Object Structure
type KeyValue struct {
	ttlv.Tag `kmip:"KEY_VALUE"`

	// TODO: might be structure if wrapping is used
	KeyMaterial []byte     `kmip:"KEY_MATERIAL"`
	Attributes  Attributes `kmip:"ATTRIBUTE"`
}
