// Package kimtest embeds the aws-default policy pack.
package kimtest2

import "embed"

// FS holds the files the policy-opa analyzer loads for the pack.
//
//go:embed PulumiPolicy.yaml pack.rego scp.rego
var FS embed.FS

// Checksum is the dirhash h1 checksum of the files in FS.
//
//go:embed CHECKSUM
var Checksum string
