package ttlv

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/pkg/errors"
)

func (d *Decoder) readInteger(expectedTag Tag) (int32, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return 0, err
	}

	if err := d.expectType(INTEGER); err != nil {
		return 0, err
	}

	if err := d.expectLength(4); err != nil {
		return 0, err
	}

	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return 0, err
	}

	return int32(binary.BigEndian.Uint32(b[:4])), nil
}

func (d *Decoder) readLongInteger(expectedTag Tag) (int64, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return 0, err
	}

	if err := d.expectType(LONG_INTEGER); err != nil {
		return 0, err
	}

	if err := d.expectLength(8); err != nil {
		return 0, err
	}

	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return 0, err
	}

	return int64(binary.BigEndian.Uint64(b[:])), nil
}

func (d *Decoder) readEnum(expectedTag Tag) (Enum, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return Enum(0), err
	}

	if err := d.expectType(ENUMERATION); err != nil {
		return Enum(0), err
	}

	if err := d.expectLength(4); err != nil {
		return Enum(0), err
	}

	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return Enum(0), err
	}

	return Enum(binary.BigEndian.Uint32(b[:4])), nil
}

func (d *Decoder) readBool(expectedTag Tag) (bool, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return false, err
	}

	if err := d.expectType(BOOLEAN); err != nil {
		return false, err
	}

	if err := d.expectLength(8); err != nil {
		return false, err
	}

	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return false, err
	}

	for i := 0; i < 7; i++ {
		if b[i] != 0 {
			return false, errors.Errorf("unexpected boolean value: %v", b)
		}
	}

	switch b[7] {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, errors.Errorf("unexpected boolean value: %v", b)
	}
}

func (d *Decoder) readByteSlice(expectedTag Tag, expectedType Type) (int, []byte, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return 0, nil, err
	}

	if err := d.expectType(expectedType); err != nil {
		return 0, nil, err
	}

	l, err := d.readLength()
	if err != nil {
		return 0, nil, err
	}

	v := make([]byte, l)
	if _, err = io.ReadFull(d.r, v); err != nil {
		return 0, nil, err
	}

	n := int(l) + 8

	// padding
	var b [8]byte
	if l%8 != 0 {
		_, err = io.ReadFull(d.r, b[:8-l%8])
		if err != nil {
			return 0, nil, err
		}
		n += int(8 - l%8)
	}

	return n, v, nil
}

func (d *Decoder) readBytes(expectedTag Tag) (int, []byte, error) {
	return d.readByteSlice(expectedTag, BYTE_STRING)
}

func (d *Decoder) readString(expectedTag Tag) (n int, v string, err error) {
	var b []byte
	n, b, err = d.readByteSlice(expectedTag, TEXT_STRING)
	return n, string(b), err
}

func (d *Decoder) readTime(expectedTag Tag) (time.Time, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return time.Time{}, nil
	}

	if err := d.expectType(DATE_TIME); err != nil {
		return time.Time{}, nil
	}

	if err := d.expectLength(8); err != nil {
		return time.Time{}, nil
	}

	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return time.Time{}, nil
	}

	return time.Unix(int64(binary.BigEndian.Uint64(b[:])), 0), nil
}

func (d *Decoder) readDuration(expectedTag Tag) (time.Duration, error) {
	if err := d.expectTag(expectedTag); err != nil {
		return time.Duration(0), err
	}

	if err := d.expectType(INTERVAL); err != nil {
		return time.Duration(0), err
	}

	if err := d.expectLength(4); err != nil {
		return time.Duration(0), err
	}

	var b [8]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return time.Duration(0), err
	}

	return time.Duration(binary.BigEndian.Uint32(b[:4])) * time.Second, nil
}
