package koodous

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSHA = "ca9139a9978f306d07da26d6b299661af67f99e6b1e2f1c19f29b11fb44eb429"

const apkJSON = `{
  "id": "bMo71eaEM2m1xR3g",
  "sha256": "ca9139a9978f306d07da26d6b299661af67f99e6b1e2f1c19f29b11fb44eb429",
  "md5": "9ec448a9b5826bff5f67deb78a332109",
  "sha1": "47b198defd13935a8cf8a44d66ab752feda5c810",
  "app": "Sticker Center",
  "package_name": "com.samsung.android.stickercenter",
  "company": "Samsung Corporation",
  "version": "2.2.00.16",
  "size": 8485692,
  "tags": ["playstore"],
  "is_trusted": false,
  "is_detected": false,
  "created_at": "2022-01-14T09:41:01.648728+01:00"
}`

func TestGetSendsTokenHeader(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Write([]byte(apkJSON))
	}))
	defer srv.Close()

	c := New("TOK", WithBaseURL(srv.URL))
	apk, err := c.Get(context.Background(), testSHA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotAuth != "Token TOK" {
		t.Errorf("Authorization = %q, want the Token scheme", gotAuth)
	}
	if gotPath != "/apks/"+testSHA+"/" {
		t.Errorf("path = %q", gotPath)
	}
	if apk.PackageName != "com.samsung.android.stickercenter" {
		t.Errorf("PackageName = %q", apk.PackageName)
	}
	if apk.Size != 8485692 {
		t.Errorf("Size = %d", apk.Size)
	}
	if len(apk.Tags) != 1 {
		t.Errorf("Tags = %v", apk.Tags)
	}
}

func TestGetRejectsNonSHA256(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the server was called for an invalid hash")
	}))
	defer srv.Close()

	c := New("TOK", WithBaseURL(srv.URL))
	// An MD5 is a valid hash but not valid here: the endpoint is SHA-256 only.
	for _, bad := range []string{"", "9ec448a9b5826bff5f67deb78a332109", strings.Repeat("z", 64)} {
		if _, err := c.Get(context.Background(), bad); err == nil {
			t.Errorf("Get(%q) was accepted", bad)
		}
	}
}

func TestNoTokenIsAnError(t *testing.T) {
	c := New("")
	if _, err := c.Get(context.Background(), testSHA); err == nil {
		t.Fatal("a request with no token succeeded")
	}
}

func TestRateLimitErrorNamesTheQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "throttled", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := New("TOK", WithBaseURL(srv.URL))
	_, err := c.Get(context.Background(), testSHA)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "rate limited") {
		t.Errorf("message does not mention rate limiting: %s", apiErr)
	}
}

func TestSearchPassesQueryAndCursor(t *testing.T) {
	var gotSearch, gotCursor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSearch = r.URL.Query().Get("search")
		gotCursor = r.URL.Query().Get("cursor")
		fmt.Fprintf(w, `{"count": 42, "next": "%s/apks/?cursor=NEXTPAGE", "results": [%s]}`, "http://x", apkJSON)
	}))
	defer srv.Close()

	c := New("TOK", WithBaseURL(srv.URL))
	page, err := c.Search(context.Background(), "package: com.samsung", "PREVCURSOR")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if gotSearch != "package: com.samsung" {
		t.Errorf("search = %q", gotSearch)
	}
	if gotCursor != "PREVCURSOR" {
		t.Errorf("cursor = %q", gotCursor)
	}
	if page.Count != 42 || len(page.Results) != 1 {
		t.Errorf("count = %d, %d results", page.Count, len(page.Results))
	}
}

func TestExtractLink(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"json object", `{"download_url": "https://warehouse.koodous.com/x.apk?sig=1"}`, "https://warehouse.koodous.com/x.apk?sig=1"},
		{"json object url key", `{"url": "https://warehouse.koodous.com/y.apk"}`, "https://warehouse.koodous.com/y.apk"},
		{"json string", `"https://warehouse.koodous.com/z.apk"`, "https://warehouse.koodous.com/z.apk"},
		{"bare url", "https://warehouse.koodous.com/w.apk\n", "https://warehouse.koodous.com/w.apk"},
	}
	for _, c := range cases {
		got, err := extractLink([]byte(c.body))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	if _, err := extractLink([]byte(`{"detail": "not found"}`)); err == nil {
		t.Error("a response with no link was accepted")
	}
}

func TestFetchDoesNotLeakTheToken(t *testing.T) {
	payload := []byte("PK\x03\x04 not really an apk")
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		w.Write(payload)
	}))
	defer srv.Close()

	c := New("TOK", WithBaseURL(srv.URL))
	var buf bytes.Buffer
	n, err := c.Fetch(context.Background(), srv.URL+"/signed/link.apk", &buf)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}
	if sawAuth {
		t.Error("the developer token was sent to a pre-signed link")
	}
}

func TestIsHashAcceptsAllThreeKinds(t *testing.T) {
	if !IsHash(testSHA) || !IsHash("47b198defd13935a8cf8a44d66ab752feda5c810") || !IsHash("9ec448a9b5826bff5f67deb78a332109") {
		t.Error("a valid hash was rejected")
	}
	if IsHash("deadbeef") {
		t.Error("a short string was taken for a hash")
	}
	if IsSHA256("47b198defd13935a8cf8a44d66ab752feda5c810") {
		t.Error("a SHA-1 was taken for a SHA-256")
	}
}
