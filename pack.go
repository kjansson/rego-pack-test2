// Package kimtest embeds the aws-default policy pack.
package kimtest2

import "embed"

// FS holds the files the policy-opa analyzer loads for the pack.
//
//go:embed PulumiPolicy.yaml pack.rego scp.rego
var FS embed.FS
