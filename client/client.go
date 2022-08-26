package client

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/tls"
	"time"

	"github.com/pkg/errors"

	"github.com/cybercryptio/go-kmip/proto"
	"github.com/cybercryptio/go-kmip/ttlv"
)

// Error enhances error with "Result Reason" field
//
// Any Error instance is returned back to the caller with message and
// result reason set, any other Go error is returned as "General Failure"
type Error interface {
	error
	ResultReason() ttlv.Enum
}

type protocolError struct {
	error
	reason ttlv.Enum
}

func (e protocolError) ResultReason() ttlv.Enum {
	return e.reason
}

func WrapError(err error, reason ttlv.Enum) protocolError {
	return protocolError{err, reason}
}

var ErrResponseType = errors.New("unexpected response type")

// DefaultClientTLSConfig fills in good defaults for client TLS configuration
func DefaultClientTLSConfig(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
}

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
	// Defaults to 1.4 if not set
	Version proto.ProtocolVersion

	// Network timeouts
	ReadTimeout, WriteTimeout time.Duration

	conn *tls.Conn
	e    *ttlv.Encoder
	d    *ttlv.Decoder
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

	var zeroVersion proto.ProtocolVersion
	if c.Version == zeroVersion {
		c.Version = proto.ProtocolVersion{Major: 1, Minor: 4}
	}

	c.e = ttlv.NewEncoder(c.conn)
	c.d = ttlv.NewDecoder(c.conn)

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
func (c *Client) DiscoverVersions(request proto.DiscoverVersionsRequest) (proto.DiscoverVersionsResponse, error) {
	resp, err := c.Send(ttlv.OPERATION_DISCOVER_VERSIONS, request)
	if err != nil {
		return proto.DiscoverVersionsResponse{}, err
	}

	discoverResp, ok := resp.(proto.DiscoverVersionsResponse)
	if !ok {
		return proto.DiscoverVersionsResponse{}, ErrResponseType
	}

	return discoverResp, nil
}

// Create with the server
func (c *Client) Create(request proto.CreateRequest) (proto.CreateResponse, error) {
	resp, err := c.Send(ttlv.OPERATION_CREATE, request)
	if err != nil {
		return proto.CreateResponse{}, err
	}

	createResp, ok := resp.(proto.CreateResponse)
	if !ok {
		return proto.CreateResponse{}, ErrResponseType
	}

	return createResp, nil
}

// Activate with the server
func (c *Client) Activate(request proto.ActivateRequest) (proto.ActivateResponse, error) {
	resp, err := c.Send(ttlv.OPERATION_ACTIVATE, request)
	if err != nil {
		return proto.ActivateResponse{}, err
	}

	activateResp, ok := resp.(proto.ActivateResponse)
	if !ok {
		return proto.ActivateResponse{}, ErrResponseType
	}

	return activateResp, nil
}

// Encrypt with the server
func (c *Client) Encrypt(request proto.EncryptRequest) (proto.EncryptResponse, error) {
	resp, err := c.Send(ttlv.OPERATION_ENCRYPT, request)
	if err != nil {
		return proto.EncryptResponse{}, err
	}

	encryptResp, ok := resp.(proto.EncryptResponse)
	if !ok {
		return proto.EncryptResponse{}, ErrResponseType
	}

	return encryptResp, nil
}

// Decrypt with the server
func (c *Client) Decrypt(request proto.DecryptRequest) (proto.DecryptResponse, error) {
	resp, err := c.Send(ttlv.OPERATION_DECRYPT, request)
	if err != nil {
		return proto.DecryptResponse{}, err
	}

	decryptResp, ok := resp.(proto.DecryptResponse)
	if !ok {
		return proto.DecryptResponse{}, ErrResponseType
	}

	return decryptResp, nil
}

// RNGRetrieve with the server
func (c *Client) RNGRetrieve(request proto.RNGRetrieveRequest) (proto.RNGRetrieveResponse, error) {
	resp, err := c.Send(ttlv.OPERATION_RNG_RETRIEVE, request)
	if err != nil {
		return proto.RNGRetrieveResponse{}, err
	}

	rngRetrieveResp, ok := resp.(proto.RNGRetrieveResponse)
	if !ok {
		return proto.RNGRetrieveResponse{}, ErrResponseType
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
func (c *Client) Send(operation ttlv.Enum, req interface{}) (interface{}, error) {
	if c.conn == nil {
		return nil, errors.New("not connected")
	}

	request := &proto.Request{
		Header: proto.RequestHeader{
			Version:    c.Version,
			BatchCount: 1,
		},
		BatchItems: []proto.RequestBatchItem{
			{
				Operation:      operation,
				RequestPayload: req,
			},
		},
	}

	if c.WriteTimeout != 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}

	if err := c.e.Encode(request); err != nil {
		return nil, errors.Wrap(err, "error writing request")
	}

	if c.ReadTimeout != 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}

	var response proto.Response

	if err := c.d.Decode(&response); err != nil {
		return nil, errors.Wrap(err, "error reading response")
	}

	if response.Header.BatchCount != 1 {
		return nil, errors.Errorf("unexepcted response batch count: %d", response.Header.BatchCount)
	}

	if len(response.BatchItems) != 1 {
		return nil, errors.Errorf("unexpected response batch items: %d", len(response.BatchItems))
	}

	if response.BatchItems[0].Operation != operation {
		return nil, errors.Errorf("unexpected response operation: %d", response.BatchItems[0].Operation)
	}

	if response.BatchItems[0].ResultStatus == ttlv.RESULT_STATUS_SUCCESS {
		return response.BatchItems[0].ResponsePayload, nil
	}

	return nil, WrapError(errors.New(response.BatchItems[0].ResultMessage), response.BatchItems[0].ResultReason)
}
