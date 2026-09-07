// Package mcptools exposes the service over MCP.
//
// The descriptions carry two things a model gets wrong otherwise: that Koodous
// is a community repository whose flags are analyst votes rather than vendor
// verdicts, and that its corpus is what people uploaded — absence is not
// evidence an app does not exist.
package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-koodous/internal/service"
)

type registry struct{ svc *service.Service }

func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "kd_lookup",
		Description: "Look up one APK on Koodous by SHA-256. " +
			"Returns app name, package name, developer, version, size, tags and the community flags. " +
			"Those flags are analyst opinion, not vendor verdicts: 'detected' means someone marked it as malware, 'trusted' that someone vouched for it, 'rating' is a vote tally. " +
			"'corrupted' usually means the certificate or the dex could not be read, which is common for APKs pulled off devices rather than a sign of tampering.",
	}, r.lookup)

	mcp.AddTool(s, &mcp.Tool{
		Name: "kd_search",
		Description: "Search the Koodous corpus with its query language. " +
			"Modifiers: package:, app:, developer: (or company:), version:, size:, tag:, date:, cert: (or certificate:), detected:, analyzed:, trusted:, corrupted:, rating:, installed:, hash:. " +
			"They combine with AND, OR, parentheses, and '-' for NOT; bare words match package, app and developer names at once. " +
			"Size takes bytes and comparators (size: > 125125), date takes a day or a range (date: [2021-03-25, 2021-03-26]). " +
			"cert: searches the signing certificate, which is the strongest pivot for finding a whole family from one sample. " +
			"Results are one page; pass next_cursor to continue.",
	}, r.search)

	mcp.AddTool(s, &mcp.Tool{
		Name: "kd_analysis",
		Description: "Fetch the stored analysis report for a sample: Androguard (manifest, permissions, activities, certificates), Cuckoo, and Droidbox dynamic traces. " +
			"Sub-reports that were never run come back null, and a sample with no analysis at all returns a 404 rather than an empty report. " +
			"The report is whatever was recorded at analysis time, which may predate the current sample metadata.",
	}, r.analysis)

	mcp.AddTool(s, &mcp.Tool{
		Name: "kd_matches",
		Description: "List the YARA rules that matched a sample. " +
			"Rules are written by Koodous analysts and vary in quality and intent — a match is a lead, not an attribution, and rule names are chosen by their authors.",
	}, r.matches)

	mcp.AddTool(s, &mcp.Tool{
		Name: "kd_download",
		Description: "Download APKs by SHA-256 into a directory on this machine. " +
			"Each file is verified against its hash before it takes its final name, and hashes already present are skipped. " +
			"Koodous meters downloads by account tier, and each APK costs two API calls, so concurrency is capped low. " +
			"APKs are live malware as often as not: they land on disk, they are never opened.",
	}, r.download)
}

type lookupInput struct {
	SHA256 string `json:"sha256" jsonschema:"SHA-256 of the sample, whole and untruncated"`
}

type searchInput struct {
	Query  string `json:"query" jsonschema:"Koodous query, e.g. 'package: com.parental.control.kidgy' or 'cert: 60BBF1896747E313B240EE2A54679BB0CE4A5023'"`
	Cursor string `json:"cursor,omitempty" jsonschema:"next_cursor from a previous call, to fetch the following page"`
	Limit  int    `json:"limit,omitempty" jsonschema:"trim the page to this many results"`
}

type reportInput struct {
	SHA256 string `json:"sha256" jsonschema:"SHA-256 of the sample, whole and untruncated"`
}

type downloadInput struct {
	SHA256    []string `json:"sha256" jsonschema:"SHA-256 hashes to download, whole and untruncated"`
	Directory string   `json:"directory,omitempty" jsonschema:"destination directory (default: the server's -out)"`
	Workers   int      `json:"workers,omitempty" jsonschema:"concurrent downloads, capped at 8 (default 4)"`
}

func (r *registry) lookup(ctx context.Context, _ *mcp.CallToolRequest, in lookupInput) (*mcp.CallToolResult, service.LookupResult, error) {
	if strings.TrimSpace(in.SHA256) == "" {
		return nil, service.LookupResult{}, fmt.Errorf("sha256 is required")
	}
	res, err := r.svc.Lookup(ctx, in.SHA256)
	return nil, res, err
}

func (r *registry) search(ctx context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, service.SearchResult, error) {
	res, err := r.svc.Search(ctx, in.Query, in.Cursor, in.Limit)
	return nil, res, err
}

func (r *registry) analysis(ctx context.Context, _ *mcp.CallToolRequest, in reportInput) (*mcp.CallToolResult, service.ReportResult, error) {
	if strings.TrimSpace(in.SHA256) == "" {
		return nil, service.ReportResult{}, fmt.Errorf("sha256 is required")
	}
	res, err := r.svc.Analysis(ctx, in.SHA256)
	return nil, res, err
}

func (r *registry) matches(ctx context.Context, _ *mcp.CallToolRequest, in reportInput) (*mcp.CallToolResult, service.ReportResult, error) {
	if strings.TrimSpace(in.SHA256) == "" {
		return nil, service.ReportResult{}, fmt.Errorf("sha256 is required")
	}
	res, err := r.svc.Matches(ctx, in.SHA256)
	return nil, res, err
}

func (r *registry) download(ctx context.Context, _ *mcp.CallToolRequest, in downloadInput) (*mcp.CallToolResult, service.DownloadResult, error) {
	if len(in.SHA256) == 0 {
		return nil, service.DownloadResult{}, fmt.Errorf("sha256 is required")
	}
	res, err := r.svc.Download(ctx, in.SHA256, in.Directory, in.Workers)
	return nil, res, err
}
