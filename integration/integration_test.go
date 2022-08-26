//go:build integration

package integration

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	kc "github.com/cybercryptio/go-kmip/client"
	"github.com/cybercryptio/go-kmip/proto"
	"github.com/cybercryptio/go-kmip/ttlv"
)

// GetTLSConfig creates a TLS configuration for use with a `http.Transport`.
// If caCertPath is set the specified CA certificate is appended to the system certificate pool.
// If certPath and keyPath are set the client certificate/key will be added to the configuration.
func GetTLSConfig(caCertPath, certPath, keyPath string) (*tls.Config, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	if caCertPath != "" {
		ca, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, err
		}
		if !certPool.AppendCertsFromPEM(ca) {
			return nil, errors.New("failed to parse CA certs")
		}
	}

	certs := []tls.Certificate{}
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return &tls.Config{
		RootCAs:      certPool,
		ClientCAs:    certPool,
		Certificates: certs,
		// The Python KMIP test server does not support TLS 1.3, so we sadly can't enforce that here.
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
	}, nil
}

func MakeTestClient() (kc.Client, error) {
	tlsConf, err := GetTLSConfig(
		"./certs/root_certificate.pem",
		"./certs/client_certificate.pem",
		"./certs/client_key.pem")
	if err != nil {
		return kc.Client{}, err
	}

	client := kc.Client{
		Endpoint:  "127.0.0.1:5696",
		TLSConfig: tlsConf,
	}

	if err = client.Connect(); err != nil {
		return kc.Client{}, err
	}

	return client, nil
}

func TestDiscoverVersions(t *testing.T) {
	client, err := MakeTestClient()
	require.NoError(t, err)
	defer client.Close()

	request := proto.DiscoverVersionsRequest{
		ProtocolVersions: []proto.ProtocolVersion{{Major: 1, Minor: 4}},
	}

	versions, err := client.DiscoverVersions(request)
	require.NoError(t, err)
	require.Equal(t, proto.DiscoverVersionsResponse{[]proto.ProtocolVersion{{Major: 1, Minor: 4}}}, versions)
}

func TestEncryptDecrypt(t *testing.T) {
	client, err := MakeTestClient()
	require.NoError(t, err)
	defer client.Close()

	templateAttribute := proto.TemplateAttribute{
		Attributes: proto.Attributes{
			{
				Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
				Value: ttlv.CRYPTO_AES,
			},
			{
				Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
				Value: int32(256),
			},
			{
				Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
				Value: int32(ttlv.CRYPTO_USAGE_MASK_ENCRYPT | ttlv.CRYPTO_USAGE_MASK_DECRYPT),
			},
			{
				Name: ttlv.ATTRIBUTE_NAME_NAME,
				Value: proto.Name{
					Value: "Key1",
					Type:  ttlv.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
				},
			},
		},
	}

	createReq := proto.CreateRequest{
		ObjectType:        ttlv.OBJECT_TYPE_SYMMETRIC_KEY,
		TemplateAttribute: templateAttribute,
	}

	createResp, err := client.Create(createReq)
	require.NoError(t, err)

	activateReq := proto.ActivateRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
	}

	_, err = client.Activate(activateReq)
	require.NoError(t, err)

	cryptoParams := proto.CryptoParams{
		BlockCipherMode:        ttlv.BLOCK_MODE_GCM,
		CryptographicAlgorithm: ttlv.CRYPTO_AES,
		TagLength:              32,
	}

	plaintext := []byte("plaintext")

	encryptReq := proto.EncryptRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
		CryptoParams:     cryptoParams,
		Data:             plaintext,
	}

	encryptResp, err := client.Encrypt(encryptReq)
	require.NoError(t, err)

	decryptReq := proto.DecryptRequest{
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

	templateAttribute := proto.TemplateAttribute{
		Attributes: proto.Attributes{
			{
				Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
				Value: ttlv.CRYPTO_AES,
			},
			{
				Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
				Value: int32(256),
			},
			{
				Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
				Value: int32(ttlv.CRYPTO_USAGE_MASK_ENCRYPT | ttlv.CRYPTO_USAGE_MASK_DECRYPT),
			},
			{
				Name: ttlv.ATTRIBUTE_NAME_NAME,
				Value: proto.Name{
					Value: "Key1",
					Type:  ttlv.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
				},
			},
		},
	}

	createReq := proto.CreateRequest{
		ObjectType:        ttlv.OBJECT_TYPE_SYMMETRIC_KEY,
		TemplateAttribute: templateAttribute,
	}

	createResp, err := client.Create(createReq)
	require.NoError(t, err)

	cryptoParams := proto.CryptoParams{
		BlockCipherMode:        ttlv.BLOCK_MODE_GCM,
		CryptographicAlgorithm: ttlv.CRYPTO_AES,
		TagLength:              32,
	}

	plaintext := []byte("plaintext")

	encryptReq := proto.EncryptRequest{
		UniqueIdentifier: createResp.UniqueIdentifier,
		CryptoParams:     cryptoParams,
		Data:             plaintext,
	}

	_, err = client.Encrypt(encryptReq)
	require.Error(t, err)
}
