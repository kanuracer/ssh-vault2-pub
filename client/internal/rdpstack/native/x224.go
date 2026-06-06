package native

import (
	"encoding/binary"
	"fmt"
)

type RDPProtocol uint32

const (
	ProtocolRDP      RDPProtocol = 0x00000000
	ProtocolSSL      RDPProtocol = 0x00000001
	ProtocolHybrid   RDPProtocol = 0x00000002
	ProtocolHybridEx RDPProtocol = 0x00000008
)

type NegotiationType byte

const (
	NegotiationRequest  NegotiationType = 0x01
	NegotiationResponse NegotiationType = 0x02
	NegotiationFailure  NegotiationType = 0x03
)

type X224ConnectionConfirm struct {
	SelectedProtocol RDPProtocol
	FailureCode      uint32
	HasNegotiation   bool
}

type NegotiationFailureError struct {
	Code uint32
}

func (e NegotiationFailureError) Error() string {
	return fmt.Sprintf("RDP negotiation failed: 0x%08x", e.Code)
}

func DecodeX224ConnectionConfirm(payload []byte) (X224ConnectionConfirm, error) {
	if len(payload) < 7 {
		return X224ConnectionConfirm{}, fmt.Errorf("X.224 confirm too short: %d", len(payload))
	}
	li := int(payload[0])
	if li+1 > len(payload) {
		return X224ConnectionConfirm{}, fmt.Errorf("X.224 length exceeds packet: %d > %d", li+1, len(payload))
	}
	if payload[1] != 0xd0 {
		return X224ConnectionConfirm{}, fmt.Errorf("unexpected X.224 TPDU type: 0x%02x", payload[1])
	}
	if li == 6 {
		return X224ConnectionConfirm{HasNegotiation: false, SelectedProtocol: ProtocolRDP}, nil
	}
	if li < 14 || len(payload) < 15 {
		return X224ConnectionConfirm{}, fmt.Errorf("X.224 negotiation block too short: %d", len(payload))
	}
	block := payload[7:]
	if len(block) < 8 {
		return X224ConnectionConfirm{}, fmt.Errorf("RDP negotiation block too short: %d", len(block))
	}
	blockType := NegotiationType(block[0])
	blockLen := int(binary.LittleEndian.Uint16(block[2:4]))
	if blockLen != 8 {
		return X224ConnectionConfirm{}, fmt.Errorf("unexpected RDP negotiation block length: %d", blockLen)
	}
	if len(block) < blockLen {
		return X224ConnectionConfirm{}, fmt.Errorf("incomplete RDP negotiation block: %d < %d", len(block), blockLen)
	}
	value := binary.LittleEndian.Uint32(block[4:8])
	out := X224ConnectionConfirm{HasNegotiation: true}
	switch blockType {
	case NegotiationResponse:
		out.SelectedProtocol = RDPProtocol(value)
		return out, nil
	case NegotiationFailure:
		out.FailureCode = value
		return out, NegotiationFailureError{Code: value}
	default:
		return X224ConnectionConfirm{}, fmt.Errorf("unexpected RDP negotiation block type: 0x%02x", byte(blockType))
	}
}
