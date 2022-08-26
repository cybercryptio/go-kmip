package proto

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"bytes"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cybercryptio/go-kmip/ttlv"
)

var (
	messageCreate = []byte("\x42\x00\x78\x01\x00\x00\x01\x50\x42\x00\x77\x01\x00\x00\x00\x38\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0D\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x01\x08\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x79\x01\x00\x00\x00\xF0\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x91\x01\x00\x00\x00\xD8\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x17\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C\x67\x6F\x72\x69\x74\x68\x6D\x00\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x14\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65\x6E\x67\x74\x68\x00\x00\x00\x00\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x18\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73\x61\x67\x65\x20\x4D\x61\x73\x6B\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x28\x42\x00\x0A\x07\x00\x00\x00\x0C\x49\x6E\x69\x74\x69\x61\x6C\x20\x44\x61\x74\x65\x00\x00\x00\x00\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x30\x39")
	messageGet    = []byte("\x42\x00\x78\x01\x00\x00\x00\x90\x42\x00\x77\x01\x00\x00\x00\x38\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0D\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\x48\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63\x33\x30\x33\x38\x00\x00\x00\x00")
)

type EncoderSuite struct {
	suite.Suite
}

type DecoderSuite struct {
	suite.Suite
}

func (s *EncoderSuite) TestEncodeMessageCreate() {
	var buf bytes.Buffer

	createRequest := Request{
		Header: RequestHeader{
			Version:    ProtocolVersion{Major: 1, Minor: 1},
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation: ttlv.OPERATION_CREATE,
				RequestPayload: CreateRequest{
					ObjectType: ttlv.OBJECT_TYPE_SYMMETRIC_KEY,
					TemplateAttribute: TemplateAttribute{
						Attributes: []Attribute{
							{
								Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
								Value: ttlv.CRYPTO_AES,
							},
							{
								Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
								Value: int32(128),
							},
							{
								Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
								Value: int32(12),
							},
							{
								Name:  ttlv.ATTRIBUTE_NAME_INITIAL_DATE,
								Value: time.Unix(12345, 0),
							},
						},
					},
				},
			},
		},
	}

	err := ttlv.NewEncoder(&buf).Encode(&createRequest)
	s.Assert().NoError(err)

	s.Assert().EqualValues(messageCreate, buf.Bytes())
}

func (s *EncoderSuite) TestEncodeMessageGet() {
	var buf bytes.Buffer

	getRequest := Request{
		Header: RequestHeader{
			Version:    ProtocolVersion{Major: 1, Minor: 1},
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation: ttlv.OPERATION_GET,
				RequestPayload: GetRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
				},
			},
		},
	}

	err := ttlv.NewEncoder(&buf).Encode(&getRequest)
	s.Assert().NoError(err)

	s.Assert().EqualValues(messageGet, buf.Bytes())
}

func (s *EncoderSuite) TestEncodeMessageGetPointer() {
	var buf bytes.Buffer

	getRequest := Request{
		Header: RequestHeader{
			Version:    ProtocolVersion{Major: 1, Minor: 1},
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation: ttlv.OPERATION_GET,
				RequestPayload: &GetRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
				},
			},
		},
	}

	err := ttlv.NewEncoder(&buf).Encode(&getRequest)
	s.Assert().NoError(err)

	s.Assert().EqualValues(messageGet, buf.Bytes())
}

func (s *DecoderSuite) TestDecodeMessageCreate() {
	var m Request

	err := ttlv.NewDecoder(bytes.NewReader(messageCreate)).Decode(&m)
	s.Assert().NoError(err)
	s.Assert().Equal(
		Request{
			Header: RequestHeader{
				Version:    ProtocolVersion{Major: 1, Minor: 1},
				BatchCount: 1,
			},
			BatchItems: []RequestBatchItem{
				{
					Operation: ttlv.OPERATION_CREATE,
					RequestPayload: CreateRequest{
						ObjectType: ttlv.OBJECT_TYPE_SYMMETRIC_KEY,
						TemplateAttribute: TemplateAttribute{
							Attributes: []Attribute{
								{
									Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
									Value: ttlv.CRYPTO_AES,
								},
								{
									Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
									Value: int32(128),
								},
								{
									Name:  ttlv.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
									Value: int32(12),
								},
								{
									Name:  ttlv.ATTRIBUTE_NAME_INITIAL_DATE,
									Value: time.Unix(12345, 0),
								},
							},
						},
					},
				},
			},
		}, m)
}

func (s *DecoderSuite) TestDecodeMessageGet() {
	var m Request

	err := ttlv.NewDecoder(bytes.NewReader(messageGet)).Decode(&m)
	s.Assert().NoError(err)
	s.Assert().Equal(Request{
		Header: RequestHeader{
			Version:    ProtocolVersion{Major: 1, Minor: 1},
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation: ttlv.OPERATION_GET,
				RequestPayload: GetRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
				},
			},
		},
	}, m)
}
