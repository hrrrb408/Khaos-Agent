package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// The Python RPC protocol is a cross-process contract, not a transport
// implementation detail of PythonClient.  Keep its wire version and feature
// set in this small owner so callers cannot accidentally negotiate a second
// contract while changing connection code.
const (
	internalRPCProtocolVersion = 2
	internalRPCMinVersion      = 2
	internalRPCMaxVersion      = 2
	internalRPCSchemaVersion   = 1
	internalRPCMethodSchema    = 1
)

var internalRPCFeatures = []string{
	"hmac-v2",
	"project-policy-claims",
	"method-schema-v1",
	"typed-error-codes",
	"unknown-fields-reject",
}

func rpcFeatureDigest() string {
	features := append([]string(nil), internalRPCFeatures...)
	sort.Strings(features)
	raw, _ := json.Marshal(features)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
