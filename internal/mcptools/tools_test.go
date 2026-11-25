package mcptools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-koodous/internal/koodous"
	"github.com/sebdraven/mcp-koodous/internal/service"
)

// connect registers the tools on a server backed by a Koodous stub at base,
// and returns a client session talking to it over in-memory transports.
func connect(t *testing.T, base string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{Name: "koodous", Version: "test"}, nil)
	Register(server, service.New(koodous.New("TOK", koodous.WithBaseURL(base)), t.TempDir()))

	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func textOf(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Koodous answers both report endpoints with JSON objects; the output schema
// once inferred "null or array" for the report and rejected every call.
func TestReportToolsReturnAnObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/analysis/"):
			fmt.Fprint(w, `{"androguard": {"package_name": "com.example"}, "cuckoo": null, "droidbox": null}`)
		case strings.HasSuffix(r.URL.Path, "/matches/"):
			fmt.Fprint(w, `{"next": null, "previous": null, "results": [{"rule": "banker_generic"}]}`)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	cs := connect(t, srv.URL)
	sha := strings.Repeat("a", 64)

	for _, tc := range []struct {
		tool string
		keys []string
	}{
		{"kd_analysis", []string{"androguard", "cuckoo", "droidbox"}},
		{"kd_matches", []string{"next", "previous", "results"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      tc.tool,
				Arguments: map[string]any{"sha256": sha},
			})
			if err != nil {
				t.Fatalf("%s: %v", tc.tool, err)
			}
			if res.IsError {
				t.Fatalf("%s returned a tool error: %s", tc.tool, textOf(res))
			}
			out, ok := res.StructuredContent.(map[string]any)
			if !ok {
				t.Fatalf("structured content is %T, want an object", res.StructuredContent)
			}
			report, ok := out["report"].(map[string]any)
			if !ok {
				t.Fatalf("report is %T, want an object", out["report"])
			}
			for _, k := range tc.keys {
				if _, ok := report[k]; !ok {
					t.Errorf("report has no %q key: %v", k, report)
				}
			}
		})
	}
}
