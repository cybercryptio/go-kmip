package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoverVersions(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./pykmip-server/server.cert", "./pykmip-server/server.key")
	require.NoError(t, err)

	client := Client{
		Endpoint: "127.0.0.1:5696",
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}

	client.TLSConfig.InsecureSkipVerify = true
	client.TLSConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	_ = client.Connect()

	versions, err := client.DiscoverVersions([]ProtocolVersion{{Major: 1, Minor: 4}})
	require.NoError(t, err)
	require.Equal(t, []ProtocolVersion{{Major: 1, Minor: 4}}, versions)

	client.Close()
}

func TestEncryptDecrypt(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./pykmip-server/server.cert", "./pykmip-server/server.key")
	require.NoError(t, err)

	client := Client{
		Endpoint: "127.0.0.1:5696",
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}

	client.TLSConfig.InsecureSkipVerify = true
	client.TLSConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	_ = client.Connect()

	templateAttribute := TemplateAttribute{
		Attributes: Attributes{
			{
				Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
				Value: CRYPTO_AES,
			},
			{
				Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
				Value: int32(256),
			},
			{
				Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
				Value: int32(0x00000004 | 0x00000008),
			},
			{
				Name: ATTRIBUTE_NAME_NAME,
				Value: Name{
					Value: "Key1",
					Type:  NAME_TYPE_UNINTERPRETED_TEXT_STRING,
				},
			},
		},
	}

	uniqueIdentifier, err := client.Create(OBJECT_TYPE_SYMMETRIC_KEY, templateAttribute)
	require.NoError(t, err)

	err = client.Activate(uniqueIdentifier)
	require.NoError(t, err)

	cryptoParams := CryptoParams{
		BlockCipherMode:        BLOCK_MODE_GCM,
		CryptographicAlgorithm: CRYPTO_AES,
		TagLength:              32,
	}

	plaintext := []byte("plaintext")

	ciphertext, IV, authTag, err := client.Encrypt(uniqueIdentifier, cryptoParams, plaintext)
	require.NoError(t, err)

	decrypted, err := client.Decrypt(uniqueIdentifier, cryptoParams, ciphertext, IV, authTag)
	require.NoError(t, err)

	require.Equal(t, plaintext, decrypted)

	client.Close()
}

func TestNotActivated(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./pykmip-server/server.cert", "./pykmip-server/server.key")
	require.NoError(t, err)

	client := Client{
		Endpoint: "127.0.0.1:5696",
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}

	client.TLSConfig.InsecureSkipVerify = true
	client.TLSConfig.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}

	_ = client.Connect()

	templateAttribute := TemplateAttribute{
		Attributes: Attributes{
			{
				Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
				Value: CRYPTO_AES,
			},
			{
				Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
				Value: int32(256),
			},
			{
				Name:  ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
				Value: int32(0x00000004 | 0x00000008),
			},
			{
				Name: ATTRIBUTE_NAME_NAME,
				Value: Name{
					Value: "Key1",
					Type:  NAME_TYPE_UNINTERPRETED_TEXT_STRING,
				},
			},
		},
	}

	uniqueIdentifier, err := client.Create(OBJECT_TYPE_SYMMETRIC_KEY, templateAttribute)
	require.NoError(t, err)

	cryptoParams := CryptoParams{
		BlockCipherMode:        BLOCK_MODE_GCM,
		CryptographicAlgorithm: CRYPTO_AES,
		TagLength:              32,
	}

	plaintext := []byte("plaintext")

	_, _, _, err = client.Encrypt(uniqueIdentifier, cryptoParams, plaintext)
	require.Error(t, err)

	client.Close()
}
