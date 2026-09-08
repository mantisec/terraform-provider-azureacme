// Package main is the provider server entry point and nothing else.
//
// Placement contract: terraform-provider-azureacme/FILE_MAP.md §2 — "Provider
// server entry point and the registry address. Nothing else."
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/mantisec/terraform-provider-azureacme/internal/provider"
)

// version is overwritten at release time by the GoReleaser ldflags stanza.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// One-way door (terraform-provider-contract.md §1.1, D-37, F-115): the
		// second segment of this address is the resource type prefix, and there is
		// no `moved` across provider addresses.
		Address: "registry.terraform.io/mantisec/azureacme",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
