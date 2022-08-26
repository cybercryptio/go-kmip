package proto

import (
	"github.com/cybercryptio/go-kmip/ttlv"
)

// ProtocolVersion is a Protocol Version structure
type ProtocolVersion struct {
	ttlv.Tag `kmip:"PROTOCOL_VERSION"`

	Major int32 `kmip:"PROTOCOL_VERSION_MAJOR"`
	Minor int32 `kmip:"PROTOCOL_VERSION_MINOR"`
}

// MessageExtension is a Message Extension structure in a Batch Item
type MessageExtension struct {
	ttlv.Tag `kmip:"MESSAGE_EXTENSION"`

	VendorIdentification string      `kmip:"VENDOR_IDENTIFICATION,required"`
	CriticalityIndicator bool        `kmip:"CRITICALITY_INDICATOR,required"`
	VendorExtension      interface{} `kmip:"-,skip"`
}

// RevocationReason is a Revocation Reason structure
type RevocationReason struct {
	ttlv.Tag `kmip:"REVOCATION_REASON"`

	RevocationReasonCode ttlv.Enum `kmip:"REVOCATION_REASON_CODE"`
	RevocationMessage    string    `kmip:"REVOCATION_REASON"`
}
