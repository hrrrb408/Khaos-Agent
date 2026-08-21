package platform

import "testing"

func TestRPCContractIsStableAndSortedForDigest(t *testing.T) {
	if internalRPCProtocolVersion != 2 || internalRPCMinVersion != 2 || internalRPCMaxVersion != 2 {
		t.Fatalf("unexpected RPC protocol version: %d/%d-%d", internalRPCProtocolVersion, internalRPCMinVersion, internalRPCMaxVersion)
	}
	if internalRPCSchemaVersion != 1 || internalRPCMethodSchema != 1 {
		t.Fatalf("unexpected RPC schema version: %d/%d", internalRPCSchemaVersion, internalRPCMethodSchema)
	}
	first := rpcFeatureDigest()
	second := rpcFeatureDigest()
	if first == "" || first != second {
		t.Fatalf("feature digest is not deterministic: %q/%q", first, second)
	}
}
