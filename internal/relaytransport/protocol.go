package relaytransport

import (
	"encoding/hex"
	"errors"
	"time"
)

const (
	ProtocolVersion       = 1
	MediaType             = "application/vnd.mossward.relay+json"
	MaximumCiphertextSize = 4 << 20
)

type MessageKind string

const (
	MessageAgentCheckIn  MessageKind = "agent_check_in"
	MessageServerReply   MessageKind = "server_reply"
	MessageAgentLogBatch MessageKind = "agent_log_batch"
	MessageTamperAlert   MessageKind = "tamper_alert"
)

type Frame struct {
	ProtocolVersion      int         `json:"protocol_version"`
	MessageID            string      `json:"message_id"`
	Kind                 MessageKind `json:"kind"`
	DownstreamEndpointID string      `json:"downstream_endpoint_id"`
	Sequence             uint64      `json:"sequence"`
	CreatedAt            time.Time   `json:"created_at"`
	Ciphertext           []byte      `json:"ciphertext"`
}

type Contract struct {
	ProtocolVersion       int           `json:"protocol_version"`
	MediaType             string        `json:"media_type"`
	AllowedMessageKinds   []MessageKind `json:"allowed_message_kinds"`
	MaximumCiphertextSize int           `json:"maximum_ciphertext_size"`
	GenericProxySupported bool          `json:"generic_proxy_supported"`
	ArbitraryDestinations bool          `json:"arbitrary_destinations_supported"`
	ForwardingEnabled     bool          `json:"forwarding_enabled"`
}

func ProtocolContract() Contract {
	return Contract{ProtocolVersion: ProtocolVersion, MediaType: MediaType, MaximumCiphertextSize: MaximumCiphertextSize,
		AllowedMessageKinds: []MessageKind{MessageAgentCheckIn, MessageServerReply, MessageAgentLogBatch, MessageTamperAlert}}
}

func ValidateFrame(frame Frame, now time.Time) error {
	if frame.ProtocolVersion != ProtocolVersion {
		return errors.New("unsupported Mossward relay protocol version")
	}
	messageID, err := hex.DecodeString(frame.MessageID)
	if err != nil || len(messageID) != 16 {
		return errors.New("relay message ID must be a 128-bit hexadecimal value")
	}
	if !allowedMessageKind(frame.Kind) {
		return errors.New("unsupported Mossward relay message kind")
	}
	if frame.DownstreamEndpointID == "" || frame.Sequence == 0 || frame.CreatedAt.IsZero() {
		return errors.New("relay endpoint identity, sequence, and creation time are required")
	}
	if frame.CreatedAt.After(now.Add(5*time.Minute)) || frame.CreatedAt.Before(now.Add(-30*24*time.Hour)) {
		return errors.New("relay message creation time is outside the accepted window")
	}
	if len(frame.Ciphertext) == 0 || len(frame.Ciphertext) > MaximumCiphertextSize {
		return errors.New("relay ciphertext size is invalid")
	}
	return nil
}

func allowedMessageKind(kind MessageKind) bool {
	for _, allowed := range ProtocolContract().AllowedMessageKinds {
		if kind == allowed {
			return true
		}
	}
	return false
}
