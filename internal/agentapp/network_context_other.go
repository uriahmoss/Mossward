//go:build !linux && !windows

package agentapp

func platformNetworkNameContext() map[string]networkNameContext {
	return map[string]networkNameContext{}
}
