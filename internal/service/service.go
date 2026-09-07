// Package service turns the Koodous API into the operations an analyst runs:
// look a sample up, search the corpus, pull a report, get the APK on disk.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sebdraven/mcp-koodous/internal/koodous"
)

type Service struct {
	client *koodous.Client
	outDir string
}

func New(c *koodous.Client, outDir string) *Service {
	return &Service{client: c, outDir: outDir}
}

type LookupResult struct {
	FetchedAt string      `json:"fetched_at"`
	Apk       koodous.Apk `json:"apk"`
}

type SearchResult struct {
	Query      string        `json:"query"`
	FetchedAt  string        `json:"fetched_at"`
	TotalCount int64         `json:"total_matches"`
	Returned   int           `json:"returned"`
	NextCursor string        `json:"next_cursor,omitempty"`
	Results    []koodous.Apk `json:"results"`
	Note       string        `json:"note,omitempty"`
}

type ReportResult struct {
	SHA256    string          `json:"sha256"`
	FetchedAt string          `json:"fetched_at"`
	Report    json.RawMessage `json:"report"`
}

type DownloadOutcome struct {
	SHA256 string `json:"sha256"`
	Path   string `json:"path,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	Status string `json:"status"` // downloaded | skipped | error
	Error  string `json:"error,omitempty"`
}

type DownloadResult struct {
	Directory string            `json:"directory"`
	Requested int               `json:"requested"`
	Succeeded int               `json:"succeeded"`
	Skipped   int               `json:"skipped"`
	Failed    int               `json:"failed"`
	Workers   int               `json:"workers"`
	Outcomes  []DownloadOutcome `json:"outcomes"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Lookup returns what Koodous knows about one sample.
func (s *Service) Lookup(ctx context.Context, sha string) (LookupResult, error) {
	apk, err := s.client.Get(ctx, sha)
	if err != nil {
		return LookupResult{}, err
	}
	return LookupResult{FetchedAt: now(), Apk: apk}, nil
}

// Search runs a Koodous query and returns one page.
func (s *Service) Search(ctx context.Context, query, cursor string, limit int) (SearchResult, error) {
	if strings.TrimSpace(query) == "" {
		return SearchResult{}, fmt.Errorf("a query is required: Koodous has 86 million samples, an unfiltered listing is not useful")
	}
	page, err := s.client.Search(ctx, query, cursor)
	if err != nil {
		return SearchResult{}, err
	}

	results := page.Results
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	out := SearchResult{
		Query:      query,
		FetchedAt:  now(),
		TotalCount: page.Count,
		Returned:   len(results),
		NextCursor: cursorOf(page.Next),
		Results:    results,
	}
	if page.Count > int64(len(results)) {
		out.Note = fmt.Sprintf("%d samples match; this is one page. Pass next_cursor to continue, or narrow the query.", page.Count)
	}
	return out, nil
}

// cursorOf extracts the opaque cursor from a next-page URL, so callers page
// without handling absolute URLs.
func cursorOf(next string) string {
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return ""
	}
	return u.Query().Get("cursor")
}

// Analysis returns the static and dynamic report.
func (s *Service) Analysis(ctx context.Context, sha string) (ReportResult, error) {
	raw, err := s.client.Analysis(ctx, sha)
	if err != nil {
		return ReportResult{}, err
	}
	return ReportResult{SHA256: strings.ToLower(strings.TrimSpace(sha)), FetchedAt: now(), Report: raw}, nil
}

// Matches returns the YARA matches recorded against a sample.
func (s *Service) Matches(ctx context.Context, sha string) (ReportResult, error) {
	raw, err := s.client.Matches(ctx, sha)
	if err != nil {
		return ReportResult{}, err
	}
	return ReportResult{SHA256: strings.ToLower(strings.TrimSpace(sha)), FetchedAt: now(), Report: raw}, nil
}

// Download fetches APKs into dir, one file per SHA-256. Existing files are left
// alone; each download lands in a temporary file, is checked against its hash
// and only then takes its final name.
//
// Concurrency is modest on purpose: Koodous meters requests per account tier,
// and each APK costs two calls — one to mint the link, one to fetch it.
func (s *Service) Download(ctx context.Context, shas []string, dir string, workers int) (DownloadResult, error) {
	if dir = strings.TrimSpace(dir); dir == "" {
		dir = s.outDir
	}
	if dir == "" {
		return DownloadResult{}, fmt.Errorf("no output directory: pass one, or start the server with -out")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DownloadResult{}, err
	}

	clean := make([]string, 0, len(shas))
	for _, h := range shas {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if !koodous.IsSHA256(h) {
			return DownloadResult{}, fmt.Errorf("%q is not a SHA-256: Koodous downloads by SHA-256 only", h)
		}
		clean = append(clean, h)
	}
	if len(clean) == 0 {
		return DownloadResult{}, fmt.Errorf("no SHA-256 given")
	}

	if workers <= 0 {
		workers = 4
	}
	workers = min(workers, 8, len(clean))

	res := DownloadResult{Directory: dir, Requested: len(clean), Workers: workers}
	outcomes := make([]DownloadOutcome, len(clean))

	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				outcomes[i] = s.fetchOne(ctx, clean[i], dir)
			}
		}()
	}
	for i := range clean {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return res, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	for _, o := range outcomes {
		switch o.Status {
		case "downloaded":
			res.Succeeded++
		case "skipped":
			res.Skipped++
		default:
			res.Failed++
		}
	}
	res.Outcomes = outcomes
	return res, nil
}

func (s *Service) fetchOne(ctx context.Context, sha, dir string) DownloadOutcome {
	final := filepath.Join(dir, sha+".apk")
	if st, err := os.Stat(final); err == nil && st.Size() > 0 {
		return DownloadOutcome{SHA256: sha, Path: final, Bytes: st.Size(), Status: "skipped"}
	}

	// Minted immediately before the transfer: the link expires in three
	// minutes, so requesting them all up front would strand the tail of a
	// long queue.
	link, err := s.client.DownloadURL(ctx, sha)
	if err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}

	tmp, err := os.CreateTemp(dir, "."+sha+".part-*")
	if err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	n, err := s.client.Fetch(ctx, link, io.MultiWriter(tmp, h))
	closeErr := tmp.Close()
	if err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}
	if closeErr != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: closeErr.Error()}
	}

	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		return DownloadOutcome{
			SHA256: sha,
			Status: "error",
			Error:  fmt.Sprintf("content hashes to %s, not to the requested %s", got, sha),
		}
	}
	if err := os.Rename(tmpName, final); err != nil {
		return DownloadOutcome{SHA256: sha, Status: "error", Error: err.Error()}
	}
	return DownloadOutcome{SHA256: sha, Path: final, Bytes: n, Status: "downloaded"}
}
