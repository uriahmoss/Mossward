package relaytransport

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProtocolContractProhibitsGenericProxyFields(t *testing.T) {
	contract := ProtocolContract()
	if contract.GenericProxySupported || contract.ArbitraryDestinations || contract.ForwardingEnabled {
		t.Fatalf("unsafe relay contract = %#v", contract)
	}
	frameType := reflect.TypeOf(Frame{})
	for index := 0; index < frameType.NumField(); index++ {
		name := strings.ToLower(frameType.Field(index).Name)
		for _, prohibited := range []string{"host", "address", "port", "url", "command", "protocol"} {
			if prohibited != "protocol" && strings.Contains(name, prohibited) {
				t.Fatalf("relay frame exposes generic forwarding field %q", name)
			}
		}
	}
}

func TestValidateFrameAcceptsOnlyMosswardMessageKinds(t *testing.T) {
	now := time.Now().UTC()
	frame := Frame{ProtocolVersion: ProtocolVersion, MessageID: "00112233445566778899aabbccddeeff", Kind: MessageAgentCheckIn,
		DownstreamEndpointID: "endpoint", Sequence: 1, CreatedAt: now, Ciphertext: []byte("sealed")}
	if err := ValidateFrame(frame, now); err != nil {
		t.Fatal(err)
	}
	frame.Kind = "tcp_forward"
	if err := ValidateFrame(frame, now); err == nil {
		t.Fatal("accepted generic forwarding message kind")
	}
}
