package proto

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"time"

	"github.com/pkg/errors"

	"github.com/cybercryptio/go-kmip/ttlv"
)

// Response is a Response Message Structure
type Response struct {
	ttlv.Tag `kmip:"RESPONSE_MESSAGE"`

	Header     ResponseHeader      `kmip:"RESPONSE_HEADER,required"`
	BatchItems []ResponseBatchItem `kmip:"RESPONSE_BATCH_ITEM,required"`
}

// ResponseHeader is a Response Header Structure
type ResponseHeader struct {
	ttlv.Tag `kmip:"RESPONSE_HEADER"`

	Version                ProtocolVersion `kmip:"PROTOCOL_VERSION,required"`
	TimeStamp              time.Time       `kmip:"TIME_STAMP,required"`
	Nonce                  Nonce           `kmip:"NONCE"`
	AttestationType        []ttlv.Enum     `kmip:"ATTESTATION_TYPE"`
	ClientCorrelationValue string          `kmip:"CLIENT_CORRELATION_VALUE"`
	ServerCorrelationValue string          `kmip:"SERVER_CORRELATION_VALUE"`
	BatchCount             int32           `kmip:"BATCH_COUNT,required"`
}

// ResponseBatchItem is a Response Batch Item Structure
type ResponseBatchItem struct {
	Operation                   ttlv.Enum        `kmip:"OPERATION,required"`
	UniqueID                    []byte           `kmip:"UNIQUE_BATCH_ITEM_ID"`
	ResultStatus                ttlv.Enum        `kmip:"RESULT_STATUS,required"`
	ResultReason                ttlv.Enum        `kmip:"RESULT_REASON"`
	ResultMessage               string           `kmip:"RESULT_MESSAGE"`
	AsyncronousCorrelationValue []byte           `kmip:"ASYNCHRONOUS_CORRELATION_VALUE"`
	ResponsePayload             interface{}      `kmip:"RESPONSE_PAYLOAD"`
	MessageExtension            MessageExtension `kmip:"MESSAGE_EXTENSION"`
}

// BuildFieldValue builds value for ResponsePayload based on Operation
func (bi *ResponseBatchItem) BuildFieldValue(name string) (interface{}, error) {
	switch bi.Operation {
	case ttlv.OPERATION_CREATE:
		return &CreateResponse{}, nil
	case ttlv.OPERATION_CREATE_KEY_PAIR:
		return &CreateKeyPairResponse{}, nil
	case ttlv.OPERATION_GET:
		return &GetResponse{}, nil
	case ttlv.OPERATION_GET_ATTRIBUTES:
		return &GetAttributesResponse{}, nil
	case ttlv.OPERATION_GET_ATTRIBUTE_LIST:
		return &GetAttributeListResponse{}, nil
	case ttlv.OPERATION_ACTIVATE:
		return &ActivateResponse{}, nil
	case ttlv.OPERATION_REVOKE:
		return &RevokeResponse{}, nil
	case ttlv.OPERATION_DESTROY:
		return &DestroyResponse{}, nil
	case ttlv.OPERATION_DISCOVER_VERSIONS:
		return &DiscoverVersionsResponse{}, nil
	case ttlv.OPERATION_ENCRYPT:
		return &EncryptResponse{}, nil
	case ttlv.OPERATION_DECRYPT:
		return &DecryptResponse{}, nil
	case ttlv.OPERATION_SIGN:
		return &SignResponse{}, nil
	case ttlv.OPERATION_REGISTER:
		return &RegisterResponse{}, nil
	case ttlv.OPERATION_LOCATE:
		return &LocateResponse{}, nil
	case ttlv.OPERATION_REKEY:
		return &ReKeyResponse{}, nil
	case ttlv.OPERATION_QUERY:
		return &QueryResponse{}, nil
	default:
		return nil, errors.Errorf("unsupported operation: %v", bi.Operation)
	}
}

// Nonce object is a structure used by the server to send a random value to the client
type Nonce struct {
	ttlv.Tag `kmip:"NONCE"`

	NonceID    []byte `kmip:"NONCE_ID,required"`
	NonceValue []byte `kmip:"NONCE_VALUE,required"`
}
