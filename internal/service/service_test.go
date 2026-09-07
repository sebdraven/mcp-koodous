package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sebdraven/mcp-koodous/internal/koodous"
)

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var (
	apkA = []byte("PK\x03\x04 sample A")
	apkB = []byte("PK\x03\x04 sample B")
)

// stub serves the download-link endpoint and the warehouse behind it. bodies
// maps a SHA-256 to the bytes the warehouse will actually return, so mapping a
// hash to different bytes simulates a corrupted or substituted download.
func stub(t *testing.T, bodies map[string][]byte) *koodous.Client {
	t.Helper()
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/download/"):
			sha := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[1]
			if _, ok := bodies[sha]; !ok {
				http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, `{"download_url": "%s/warehouse/%s"}`, base, sha)
		case strings.HasPrefix(r.URL.Path, "/warehouse/"):
			sha := strings.TrimPrefix(r.URL.Path, "/warehouse/")
			w.Write(bodies[sha])
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	base = srv.URL
	return koodous.New("TOK", koodous.WithBaseURL(srv.URL))
}

func TestSearchRefusesAnEmptyQuery(t *testing.T) {
	svc := New(stub(t, nil), t.TempDir())
	if _, err := svc.Search(context.Background(), "   ", "", 0); err == nil {
		t.Error("an unfiltered listing of 86 million samples was accepted")
	}
}

func TestSearchExtractsTheCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count": 500, "next": "https://developer.koodous.com/apks/?cursor=cD0yMDIy", "results": [{"sha256":"abc"}]}`)
	}))
	defer srv.Close()

	svc := New(koodous.New("TOK", koodous.WithBaseURL(srv.URL)), t.TempDir())
	res, err := svc.Search(context.Background(), "package: com.example", "", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.NextCursor != "cD0yMDIy" {
		t.Errorf("NextCursor = %q, want the cursor pulled out of the next URL", res.NextCursor)
	}
	if res.Note == "" {
		t.Error("a partial page carried no note about the remaining matches")
	}
	if res.TotalCount != 500 {
		t.Errorf("TotalCount = %d", res.TotalCount)
	}
}

func TestSearchLimitTrimsThePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"count": 3, "next": "", "results": [{"sha256":"a"},{"sha256":"b"},{"sha256":"c"}]}`)
	}))
	defer srv.Close()

	svc := New(koodous.New("TOK", koodous.WithBaseURL(srv.URL)), t.TempDir())
	res, err := svc.Search(context.Background(), "x", "", 2)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Returned != 2 {
		t.Errorf("Returned = %d, want 2", res.Returned)
	}
}

func TestDownloadWritesVerifiedFile(t *testing.T) {
	shaA := hashOf(apkA)
	dir := t.TempDir()
	svc := New(stub(t, map[string][]byte{shaA: apkA}), dir)

	res, err := svc.Download(context.Background(), []string{shaA}, "", 4)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Succeeded != 1 || res.Failed != 0 {
		t.Fatalf("%d succeeded, %d failed: %+v", res.Succeeded, res.Failed, res.Outcomes)
	}
	got, err := os.ReadFile(filepath.Join(dir, shaA+".apk"))
	if err != nil {
		t.Fatalf("reading the downloaded file: %v", err)
	}
	if string(got) != string(apkA) {
		t.Errorf("file content = %q", got)
	}
}

func TestDownloadRejectsHashMismatch(t *testing.T) {
	shaA := hashOf(apkA)
	dir := t.TempDir()
	// The warehouse answers the request for A with B's bytes.
	svc := New(stub(t, map[string][]byte{shaA: apkB}), dir)

	res, err := svc.Download(context.Background(), []string{shaA}, "", 1)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("%d failed, want 1", res.Failed)
	}
	if !strings.Contains(res.Outcomes[0].Error, "hashes to") {
		t.Errorf("error = %q, want a hash mismatch", res.Outcomes[0].Error)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a rejected download left %d files behind", len(entries))
	}
}

func TestDownloadSkipsExisting(t *testing.T) {
	shaA := hashOf(apkA)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, shaA+".apk"), apkA, 0o644); err != nil {
		t.Fatal(err)
	}
	// No body registered: any call would 404 and be reported as an error.
	svc := New(stub(t, nil), dir)

	res, err := svc.Download(context.Background(), []string{shaA}, "", 1)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("%d skipped, %d failed, want 1 skipped", res.Skipped, res.Failed)
	}
}

func TestDownloadReportsMissingSample(t *testing.T) {
	dir := t.TempDir()
	svc := New(stub(t, nil), dir)

	res, err := svc.Download(context.Background(), []string{hashOf(apkB)}, "", 1)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Failed != 1 {
		t.Fatalf("%d failed, want 1", res.Failed)
	}
	if !strings.Contains(res.Outcomes[0].Error, "404") && !strings.Contains(res.Outcomes[0].Error, "not found") {
		t.Errorf("error = %q, want a 404", res.Outcomes[0].Error)
	}
}

func TestDownloadCapsWorkers(t *testing.T) {
	shas := make([]string, 0, 20)
	bodies := map[string][]byte{}
	for i := range 20 {
		b := fmt.Appendf(nil, "PK\x03\x04 sample %d", i)
		h := hashOf(b)
		shas = append(shas, h)
		bodies[h] = b
	}
	dir := t.TempDir()
	svc := New(stub(t, bodies), dir)

	res, err := svc.Download(context.Background(), shas, "", 100)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if res.Workers > 8 {
		t.Errorf("Workers = %d, above the cap: Koodous meters requests per account tier", res.Workers)
	}
	if res.Succeeded != len(shas) {
		t.Errorf("%d succeeded, want %d", res.Succeeded, len(shas))
	}
}

func TestDownloadRejectsNonSHA256AndEmpty(t *testing.T) {
	svc := New(stub(t, nil), t.TempDir())
	if _, err := svc.Download(context.Background(), []string{"deadbeef"}, "", 1); err == nil {
		t.Error("a non-SHA-256 was accepted")
	}
	if _, err := svc.Download(context.Background(), nil, "", 1); err == nil {
		t.Error("an empty hash list was accepted")
	}
}

func TestDownloadNeedsADirectory(t *testing.T) {
	svc := New(stub(t, nil), "")
	if _, err := svc.Download(context.Background(), []string{hashOf(apkA)}, "", 1); err == nil {
		t.Error("a download with no directory anywhere was accepted")
	}
}

func TestLookupCarriesFetchTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"sha256": "%s", "package_name": "com.example"}`, hashOf(apkA))
	}))
	defer srv.Close()

	svc := New(koodous.New("TOK", koodous.WithBaseURL(srv.URL)), t.TempDir())
	res, err := svc.Lookup(context.Background(), hashOf(apkA))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.FetchedAt == "" {
		t.Error("FetchedAt is empty: a live answer must carry when it was taken")
	}
	if res.Apk.PackageName != "com.example" {
		t.Errorf("PackageName = %q", res.Apk.PackageName)
	}
}
