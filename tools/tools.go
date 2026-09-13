//go:build tools

// Package tools pins the developer tools this module shells out to, so their
// versions are recorded in go.sum and every contributor and CI run generates
// byte-identical output.
//
// Placement contract: terraform-provider-azureacme/FILE_MAP.md §2 — "`tools.go`
// build-tag file pinning developer tools (tfplugindocs, the model generator) so
// their versions are in `go.sum`."
//
// The `tools` build tag keeps this file out of every ordinary build: `go build
// ./...`, `go vet ./...` and `go list -deps ./...` all skip it, so the provider
// binary never links a documentation generator and the Azure data-plane
// dependency guard in internal/provider/dependency_guard_test.go keeps looking at
// the shipped dependency graph only.
//
// Run the pinned generator with:
//
//	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate \
//	    --provider-name azureacme --rendered-provider-name azureacme
//
// which is what `make provider-docs` does.
package tools

import (
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)
