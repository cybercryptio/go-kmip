package proto

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"time"

	"github.com/pkg/errors"

	"github.com/cybercryptio/go-kmip/ttlv"
)

// Request is a Request Message Structure
type Request struct {
	ttlv.Tag `kmip:"REQUEST_MESSAGE"`

	Header     RequestHeader      `kmip:"REQUEST_HEADER,required"`
	BatchItems []RequestBatchItem `kmip:"REQUEST_BATCH_ITEM,required"`
}

// RequestHeader is a Request Header Structure
type RequestHeader struct {
	ttlv.Tag `kmip:"REQUEST_HEADER"`

	Version                      ProtocolVersion `kmip:"PROTOCOL_VERSION,required"`
	MaxResponseSize              int32           `kmip:"MAXIMUM_RESPONSE_SIZE"`
	ClientCorrelationValue       string          `kmip:"CLIENT_CORRELATION_VALUE"`
	ServerCorrelationValue       string          `kmip:"SERVER_CORRELATION_VALUE"`
	AsynchronousIndicator        bool            `kmip:"ASYNCHRONOUS_INDICATOR"`
	AttestationCapableIndicator  bool            `kmip:"ATTESTATION_CAPABLE_INDICATOR"`
	AttestationType              []ttlv.Enum     `kmip:"ATTESTATION_TYPE"`
	Authentication               Authentication  `kmip:"AUTHENTICATION"`
	BatchErrorContinuationOption ttlv.Enum       `kmip:"BATCH_ERROR_CONTINUATION_OPTION"`
	BatchOrderOption             bool            `kmip:"BATCH_ORDER_OPTION"`
	TimeStamp                    time.Time       `kmip:"TIME_STAMP"`
	BatchCount                   int32           `kmip:"BATCH_COUNT,required"`
}

// RequestBatchItem is a Request Batch Item Structure
type RequestBatchItem struct {
	ttlv.Tag `kmip:"REQUEST_BATCH_ITEM"`

	Operation        ttlv.Enum        `kmip:"OPERATION,required"`
	UniqueID         []byte           `kmip:"UNIQUE_BATCH_ITEM_ID"`
	RequestPayload   interface{}      `kmip:"REQUEST_PAYLOAD,required"`
	MessageExtension MessageExtension `kmip:"MESSAGE_EXTENSION"`
}

// BuildFieldValue builds value for RequestPayload based on Operation
func (bi *RequestBatchItem) BuildFieldValue(name string) (interface{}, error) {
	switch bi.Operation {
	case ttlv.OPERATION_CREATE:
		return &CreateRequest{}, nil
	case ttlv.OPERATION_GET:
		return &GetRequest{}, nil
	case ttlv.OPERATION_GET_ATTRIBUTES:
		return &GetAttributesRequest{}, nil
	case ttlv.OPERATION_GET_ATTRIBUTE_LIST:
		return &GetAttributeListRequest{}, nil
	case ttlv.OPERATION_DESTROY:
		return &DestroyRequest{}, nil
	case ttlv.OPERATION_DISCOVER_VERSIONS:
		return &DiscoverVersionsRequest{}, nil
	case ttlv.OPERATION_REGISTER:
		return &RegisterRequest{}, nil
	case ttlv.OPERATION_ACTIVATE:
		return &ActivateRequest{}, nil
	case ttlv.OPERATION_LOCATE:
		return &LocateRequest{}, nil
	case ttlv.OPERATION_REVOKE:
		return &RevokeRequest{}, nil
	case ttlv.OPERATION_QUERY:
		return &QueryRequest{}, nil
	default:
		return nil, errors.Errorf("unsupported operation: %v", bi.Operation)
	}
}
