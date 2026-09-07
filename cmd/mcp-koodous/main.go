// Command mcp-koodous serves the Koodous API over MCP.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-koodous/internal/koodous"
	"github.com/sebdraven/mcp-koodous/internal/mcptools"
	"github.com/sebdraven/mcp-koodous/internal/service"
)

var version = "dev"

func main() {
	var (
		outDir  = flag.String("out", "", "default directory for downloaded APKs")
		lookup  = flag.String("lookup", "", "look up one SHA-256 and exit")
		query   = flag.String("search", "", "run one Koodous query and exit")
		showVer = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	token, err := koodous.Token()
	if err != nil {
		log.Fatalf("%v", err)
	}

	svc := service.New(koodous.New(token), *outDir)
	ctx := context.Background()

	switch {
	case *lookup != "":
		res, err := svc.Lookup(ctx, *lookup)
		exitWith(res, err)
	case *query != "":
		res, err := svc.Search(ctx, *query, "", 0)
		exitWith(res, err)
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "koodous",
		Version: version,
	}, nil)
	mcptools.Register(server, svc)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func exitWith(v any, err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encoding result: %v", err)
	}
	os.Exit(0)
}
