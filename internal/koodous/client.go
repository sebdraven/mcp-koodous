// Package koodous is a client over the Koodous REST API
// (https://docs.koodous.com/api/).
//
// Unlike AndroZoo, Koodous searches server-side: there is a query language
// covering package name, developer, certificate, tags, size and dates, so no
// local catalogue is needed. Downloads are two-step — an endpoint mints a link
// that stays valid for three minutes, and the APK is fetched from that link.
package koodous

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const DefaultBaseURL = "https://developer.koodous.com"

// DownloadLinkTTL is how long a minted download link stays valid. Links are
// requested one at a time, right before the transfer, rather than in a batch
// that would start expiring while the first download runs.
const DownloadLinkTTL = 3 * time.Minute

var (
	sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	sha1Re   = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	md5Re    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
)

// Apk is the metadata Koodous holds for one sample.
type Apk struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	SHA256      string   `json:"sha256"`
	SHA1        string   `json:"sha1"`
	MD5         string   `json:"md5"`
	App         string   `json:"app"`
	PackageName string   `json:"package_name"`
	Company     string   `json:"company"`
	Version     string   `json:"version"`
	Size        int64    `json:"size"`
	Tags        []string `json:"tags"`
	Rating      int      `json:"rating"`
	IsTrusted   bool     `json:"is_trusted"`
	IsDetected  bool     `json:"is_detected"`
	IsCorrupted bool     `json:"is_corrupted"`
	CreatedAt   string   `json:"created_at"`
}

// Page is one cursor-paginated slice of a search.
type Page struct {
	Count   int64  `json:"count"`
	Next    string `json:"next"`
	Results []Apk  `json:"results"`
}

type Client struct {
	token   string
	baseURL string
	http    *http.Client
}

type Option func(*Client)

func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

func New(token string, opts ...Option) *Client {
	c := &Client{
		token:   token,
		baseURL: DefaultBaseURL,
		// No overall timeout: an APK can be hundreds of megabytes.
		http: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 60 * time.Second,
				MaxIdleConnsPerHost:   10,
			},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// APIError carries the status of a rejected request.
type APIError struct {
	StatusCode int
	Endpoint   string
	Body       string
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("koodous %s: rejected (%d) — check the developer token", e.Endpoint, e.StatusCode)
	case http.StatusNotFound:
		return fmt.Sprintf("koodous %s: not found (404)", e.Endpoint)
	case http.StatusTooManyRequests:
		return fmt.Sprintf("koodous %s: rate limited (429) — Koodous caps requests per account tier, see https://docs.koodous.com/quotas.html", e.Endpoint)
	}
	body := strings.TrimSpace(e.Body)
	if len(body) > 200 {
		body = body[:200]
	}
	return fmt.Sprintf("koodous %s: HTTP %d: %s", e.Endpoint, e.StatusCode, body)
}

// get issues an authenticated request against an API path.
func (c *Client) get(ctx context.Context, path string, q url.Values, endpoint string) (*http.Response, error) {
	if c.token == "" {
		return nil, fmt.Errorf("koodous %s: no developer token", endpoint)
	}
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("koodous %s: %w", endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &APIError{StatusCode: resp.StatusCode, Endpoint: endpoint, Body: string(body)}
	}
	return resp, nil
}

// Get returns the metadata for one sample by SHA-256.
func (c *Client) Get(ctx context.Context, sha string) (Apk, error) {
	sha = strings.TrimSpace(sha)
	if !sha256Re.MatchString(sha) {
		return Apk{}, fmt.Errorf("koodous apk: %q is not a SHA-256 — this endpoint takes SHA-256 only, use Search for other hash kinds", sha)
	}
	resp, err := c.get(ctx, "/apks/"+sha+"/", nil, "apk")
	if err != nil {
		return Apk{}, err
	}
	defer resp.Body.Close()

	var apk Apk
	if err := json.NewDecoder(resp.Body).Decode(&apk); err != nil {
		return Apk{}, fmt.Errorf("koodous apk: decoding %s: %w", sha, err)
	}
	return apk, nil
}

// Search runs a Koodous query. cursor continues a previous page; pass the Next
// value of the page before it.
func (c *Client) Search(ctx context.Context, query, cursor string) (Page, error) {
	q := url.Values{}
	if s := strings.TrimSpace(query); s != "" {
		q.Set("search", s)
	}
	if cur := strings.TrimSpace(cursor); cur != "" {
		q.Set("cursor", cur)
	}
	resp, err := c.get(ctx, "/apks/", q, "search")
	if err != nil {
		return Page{}, err
	}
	defer resp.Body.Close()

	var page Page
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return Page{}, fmt.Errorf("koodous search: decoding results: %w", err)
	}
	return page, nil
}

// Analysis returns the Androguard, Cuckoo and Droidbox report as raw JSON. Its
// shape varies with which analyses ran, so it is not modelled.
func (c *Client) Analysis(ctx context.Context, sha string) (json.RawMessage, error) {
	sha = strings.TrimSpace(sha)
	if !sha256Re.MatchString(sha) {
		return nil, fmt.Errorf("koodous analysis: %q is not a SHA-256", sha)
	}
	resp, err := c.get(ctx, "/apks/"+sha+"/analysis/", nil, "analysis")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("koodous analysis: reading %s: %w", sha, err)
	}
	return json.RawMessage(raw), nil
}

// Matches returns the YARA rule matches recorded against a sample.
func (c *Client) Matches(ctx context.Context, sha string) (json.RawMessage, error) {
	sha = strings.TrimSpace(sha)
	if !sha256Re.MatchString(sha) {
		return nil, fmt.Errorf("koodous matches: %q is not a SHA-256", sha)
	}
	resp, err := c.get(ctx, "/apks/"+sha+"/matches/", nil, "matches")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("koodous matches: reading %s: %w", sha, err)
	}
	return json.RawMessage(raw), nil
}

// DownloadURL mints a temporary link for a sample. The endpoint's response
// shape is not pinned down by the documentation, so both a JSON object and a
// bare URL string are accepted.
func (c *Client) DownloadURL(ctx context.Context, sha string) (string, error) {
	sha = strings.TrimSpace(sha)
	if !sha256Re.MatchString(sha) {
		return "", fmt.Errorf("koodous download: %q is not a SHA-256", sha)
	}
	resp, err := c.get(ctx, "/apks/"+sha+"/download/", nil, "download")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("koodous download: reading the link for %s: %w", sha, err)
	}
	link, err := extractLink(raw)
	if err != nil {
		return "", fmt.Errorf("koodous download: %s: %w", sha, err)
	}
	return link, nil
}

// extractLink pulls a URL out of whatever the download endpoint returned.
func extractLink(raw []byte) (string, error) {
	trimmed := strings.TrimSpace(string(raw))

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil && strings.HasPrefix(asString, "http") {
		return asString, nil
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, k := range []string{"download_url", "url", "link", "download"} {
			if v, ok := obj[k].(string); ok && strings.HasPrefix(v, "http") {
				return v, nil
			}
		}
	}

	if strings.HasPrefix(trimmed, "http") && !strings.ContainsAny(trimmed, " \n\t") {
		return trimmed, nil
	}

	if len(trimmed) > 200 {
		trimmed = trimmed[:200]
	}
	return "", fmt.Errorf("no download link in the response: %s", trimmed)
}

// Fetch streams the APK behind a minted link into w. The link is pre-signed,
// so the token is deliberately not sent with it.
func (c *Client) Fetch(ctx context.Context, link string, w io.Writer) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("koodous fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, &APIError{StatusCode: resp.StatusCode, Endpoint: "fetch", Body: string(body)}
	}
	return io.Copy(w, resp.Body)
}

// IsSHA256 reports whether s is a syntactically valid SHA-256.
func IsSHA256(s string) bool { return sha256Re.MatchString(strings.TrimSpace(s)) }

// IsHash reports whether s is any hash Koodous searches on.
func IsHash(s string) bool {
	s = strings.TrimSpace(s)
	return sha256Re.MatchString(s) || sha1Re.MatchString(s) || md5Re.MatchString(s)
}
