package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

var ErrResponseType = fmt.Errorf("unexpected response type")

// Client implements basic KMIP client
//
// Client is not safe for concurrent use
type Client struct {
	// Server endpoint as "host:port"
	Endpoint string

	// TLS client config
	TLSConfig *tls.Config

	// KMIP version to use
	//
	// Defaults to DefaultSupportedVersions[0] if not set
	Version ProtocolVersion

	// Network timeouts
	ReadTimeout, WriteTimeout time.Duration

	conn *tls.Conn
	e    *Encoder
	d    *Decoder
}

// Connect establishes connection with the server
func (c *Client) Connect() error {
	var err error

	if c.conn, err = tls.Dial("tcp", c.Endpoint, c.TLSConfig); err != nil {
		return errors.Wrap(err, "error dialing connection")
	}

	if c.ReadTimeout != 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}

	if c.WriteTimeout != 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}

	if err = c.conn.Handshake(); err != nil {
		return errors.Wrap(err, "error running tls handshake")
	}

	var zeroVersion ProtocolVersion
	if c.Version == zeroVersion {
		c.Version = DefaultSupportedVersions[0]
	}

	c.e = NewEncoder(c.conn)
	c.d = NewDecoder(c.conn)

	return nil
}

// Close connection to the server
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil

	return err
}

// DiscoverVersions with the server
func (c *Client) DiscoverVersions(versions []ProtocolVersion) (serverVersions []ProtocolVersion, err error) {
	var resp interface{}
	resp, err = c.Send(OPERATION_DISCOVER_VERSIONS,
		DiscoverVersionsRequest{
			ProtocolVersions: versions,
		})

	if err != nil {
		return
	}

	serverVersions = resp.(DiscoverVersionsResponse).ProtocolVersions
	return
}

// Create with the server
func (c *Client) Create(request CreateRequest) (CreateResponse, error) {
	resp, err := c.Send(OPERATION_CREATE, request)
	if err != nil {
		return CreateResponse{}, err
	}

	createResp, ok := resp.(CreateResponse)
	if !ok {
		return CreateResponse{}, ErrResponseType
	}

	return createResp, nil
}

// Activate with the server
func (c *Client) Activate(request ActivateRequest) (ActivateResponse, error) {
	resp, err := c.Send(OPERATION_ACTIVATE, request)
	if err != nil {
		return ActivateResponse{}, err
	}

	activateResp, ok := resp.(ActivateResponse)
	if !ok {
		return ActivateResponse{}, ErrResponseType
	}

	return activateResp, nil
}

// Encrypt with the server
func (c *Client) Encrypt(request EncryptRequest) (EncryptResponse, error) {
	resp, err := c.Send(OPERATION_ENCRYPT, request)
	if err != nil {
		return EncryptResponse{}, err
	}

	encryptResp, ok := resp.(EncryptResponse)
	if !ok {
		return EncryptResponse{}, ErrResponseType
	}

	return encryptResp, nil
}

// Decrypt with the server
func (c *Client) Decrypt(request DecryptRequest) (DecryptResponse, error) {
	resp, err := c.Send(OPERATION_DECRYPT, request)
	if err != nil {
		return DecryptResponse{}, err
	}

	decryptResp, ok := resp.(DecryptResponse)
	if !ok {
		return DecryptResponse{}, ErrResponseType
	}

	return decryptResp, nil
}

// RNGRetrieve with the server
func (c *Client) RNGRetrieve(request RNGRetrieveRequest) (RNGRetrieveResponse, error) {
	resp, err := c.Send(OPERATION_RNG_RETRIEVE, request)
	if err != nil {
		return RNGRetrieveResponse{}, err
	}

	rngRetrieveResp, ok := resp.(RNGRetrieveResponse)
	if !ok {
		return RNGRetrieveResponse{}, ErrResponseType
	}

	return rngRetrieveResp, nil
}

// Send request to server and deliver response/error back
//
// Request payload should be passed as req, and response payload will be
// returned back as resp. Operation will be sent as a batch with single
// item.
//
// Send is a generic method, it's better to implement specific methods for
// each operation (use DiscoverVersions as example).
func (c *Client) Send(operation Enum, req interface{}) (resp interface{}, err error) {
	if c.conn == nil {
		err = errors.New("not connected")
		return
	}

	request := &Request{
		Header: RequestHeader{
			Version:    c.Version,
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation:      operation,
				RequestPayload: req,
			},
		},
	}

	if c.WriteTimeout != 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}

	err = c.e.Encode(request)
	if err != nil {
		err = errors.Wrap(err, "error writing request")
		return
	}

	if c.ReadTimeout != 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}

	var response Response

	err = c.d.Decode(&response)
	if err != nil {
		err = errors.Wrap(err, "error reading response")
		return
	}

	if response.Header.BatchCount != 1 {
		err = errors.Errorf("unexepcted response batch count: %d", response.Header.BatchCount)
		return
	}

	if len(response.BatchItems) != 1 {
		err = errors.Errorf("unexpected response batch items: %d", len(response.BatchItems))
		return
	}

	if response.BatchItems[0].Operation != operation {
		err = errors.Errorf("unexpected response operation: %d", response.BatchItems[0].Operation)
		return
	}

	if response.BatchItems[0].ResultStatus == RESULT_STATUS_SUCCESS {
		resp = response.BatchItems[0].ResponsePayload
		return
	}

	err = wrapError(errors.New(response.BatchItems[0].ResultMessage), response.BatchItems[0].ResultReason)
	return
}
