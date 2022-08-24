package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func MakeTestClient() (Client, error) {
	cert, err := tls.LoadX509KeyPair("./pykmip-server/server.cert", "./pykmip-server/server.key")
	if err != nil {
		return Client{}, err
	}

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

	if err = client.Connect(); err != nil {
		return Client{}, err
	}

	return client, nil
}

func TestDiscoverVersions(t *testing.T) {
	client, err := MakeTestClient()
	require.NoError(t, err)
	defer client.Close()

	versions, err := client.DiscoverVersions([]ProtocolVersion{{Major: 1, Minor: 4}})
	require.NoError(t, err)
	require.Equal(t, []ProtocolVersion{{Major: 1, Minor: 4}}, versions)
}

func TestEncryptDecrypt(t *testing.T) {
	client, err := MakeTestClient()
	require.NoError(t, err)
	defer client.Close()

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
				Value: int32(CRYPTO_USAGE_MASK_ENCRYPT | CRYPTO_USAGE_MASK_DECRYPT),
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

	createReq := CreateRequest{
		ObjectType:        OBJECT_TYPE_SYMMETRIC_KEY,
		TemplateAttribute: templateAttribute,
	}

	createResp, err := client.Create(createReq)
	require.NoError(t, err)

	activateReq := ActivateRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
	}

	_, err = client.Activate(activateReq)
	require.NoError(t, err)

	cryptoParams := CryptoParams{
		BlockCipherMode:        BLOCK_MODE_GCM,
		CryptographicAlgorithm: CRYPTO_AES,
		TagLength:              32,
	}

	plaintext := []byte("plaintext")

	encryptReq := EncryptRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
		CryptoParams:     cryptoParams,
		Data:             plaintext,
	}

	encryptResp, err := client.Encrypt(encryptReq)
	require.NoError(t, err)

	decryptReq := DecryptRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
		CryptoParams:     cryptoParams,
		Data:             encryptResp.Data,
		IVCounterNonce:   encryptResp.IVCounterNonce,
		AuthTag:          encryptResp.AuthTag,
	}

	decryptResp, err := client.Decrypt(decryptReq)
	require.NoError(t, err)
	require.Equal(t, plaintext, decryptResp.Data)
}

func TestNotActivated(t *testing.T) {
	client, err := MakeTestClient()
	require.NoError(t, err)
	defer client.Close()

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
				Value: int32(CRYPTO_USAGE_MASK_ENCRYPT | CRYPTO_USAGE_MASK_DECRYPT),
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

	createReq := CreateRequest{
		ObjectType:        OBJECT_TYPE_SYMMETRIC_KEY,
		TemplateAttribute: templateAttribute,
	}

	createResp, err := client.Create(createReq)
	require.NoError(t, err)

	cryptoParams := CryptoParams{
		BlockCipherMode:        BLOCK_MODE_GCM,
		CryptographicAlgorithm: CRYPTO_AES,
		TagLength:              32,
	}

	plaintext := []byte("plaintext")

	encryptReq := EncryptRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
		CryptoParams:     cryptoParams,
		Data:             plaintext,
	}

	_, err = client.Encrypt(encryptReq)
	require.Error(t, err)
}
