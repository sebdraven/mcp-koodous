// Command kddl downloads APKs from Koodous in bulk: from a file of hashes, or
// straight from a Koodous query.
//
//	kddl -q 'package: com.parental.control.kidgy' -manifest kidgy.csv -dry-run
//	kddl -i kidgy.csv -o ./apks/kidgy
//	kddl -q 'cert: 60BBF1896747E313B240EE2A54679BB0CE4A5023' -n 200 -dry-run
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/sebdraven/mcp-koodous/internal/koodous"
	"github.com/sebdraven/mcp-koodous/internal/service"
)

var version = "dev"

func main() {
	var (
		input    = flag.String("i", "", "file of SHA-256 hashes, one per line ('-' for stdin)")
		query    = flag.String("q", "", "Koodous query, e.g. 'package: com.whatsapp AND detected: true'")
		outDir   = flag.String("o", ".", "destination directory")
		workers  = flag.Int("w", 4, "concurrent downloads (capped at 8)")
		n        = flag.Int("n", 100, "max samples to select from a query")
		manifest = flag.String("manifest", "", "write the selected metadata to this CSV")
		dryRun   = flag.Bool("dry-run", false, "select and write the manifest, download nothing")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	token, err := koodous.Token()
	if err != nil {
		log.Fatalf("%v", err)
	}
	svc := service.New(koodous.New(token), *outDir)

	var (
		shas    []string
		entries []koodous.Apk
	)

	switch {
	case *input != "":
		shas, err = readHashes(*input)
		if err != nil {
			log.Fatalf("%v", err)
		}

	case strings.TrimSpace(*query) != "":
		entries, err = collect(ctx, svc, *query, *n)
		if err != nil {
			log.Fatalf("%v", err)
		}
		for _, e := range entries {
			shas = append(shas, e.SHA256)
		}

	default:
		log.Fatalf("nothing to do: pass -i with a file of hashes, or -q with a Koodous query")
	}

	if len(shas) == 0 {
		log.Fatalf("nothing selected")
	}
	if *manifest != "" {
		if err := writeManifest(*manifest, entries, shas); err != nil {
			log.Fatalf("%v", err)
		}
		log.Printf("manifest written to %s", *manifest)
	}
	if *dryRun {
		for _, s := range shas {
			fmt.Println(s)
		}
		return
	}

	res, err := svc.Download(ctx, shas, *outDir, *workers)
	for _, o := range res.Outcomes {
		if o.Status == "error" {
			log.Printf("%s: %s", o.SHA256, o.Error)
		}
	}
	log.Printf("%d requested, %d downloaded, %d already present, %d failed, into %s with %d workers",
		res.Requested, res.Succeeded, res.Skipped, res.Failed, res.Directory, res.Workers)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if res.Failed > 0 {
		os.Exit(1)
	}
}

// collect pages through a query until it has limit samples or the results run
// out.
func collect(ctx context.Context, svc *service.Service, query string, limit int) ([]koodous.Apk, error) {
	var (
		out    []koodous.Apk
		cursor string
	)
	for len(out) < limit {
		res, err := svc.Search(ctx, query, cursor, 0)
		if err != nil {
			return out, err
		}
		if len(res.Results) == 0 {
			break
		}
		out = append(out, res.Results...)
		if cursor = res.NextCursor; cursor == "" {
			break
		}
		// count is absent on some queries, so it is only shown when the API
		// actually reported one.
		if res.TotalCount > 0 {
			log.Printf("%d of %d collected", len(out), res.TotalCount)
		} else {
			log.Printf("%d collected", len(out))
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	log.Printf("%d samples selected for %q", len(out), query)
	return out, nil
}

// readHashes accepts a bare list of hashes or the first column of a CSV, which
// is what a manifest looks like.
func readHashes(path string) ([]string, error) {
	var rc *os.File
	if path == "-" {
		rc = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rc = f
	}

	var out []string
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, ",;\t "); i > 0 {
			line = line[:i]
		}
		line = strings.Trim(line, `"`)
		if strings.EqualFold(line, "sha256") {
			continue
		}
		if !koodous.IsSHA256(line) {
			return nil, fmt.Errorf("%s: %q is not a SHA-256", path, line)
		}
		out = append(out, strings.ToLower(line))
	}
	return out, sc.Err()
}

func writeManifest(path string, entries []koodous.Apk, shas []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if len(entries) == 0 {
		if err := w.Write([]string{"sha256"}); err != nil {
			return err
		}
		for _, s := range shas {
			if err := w.Write([]string{s}); err != nil {
				return err
			}
		}
		return w.Error()
	}

	if err := w.Write([]string{"sha256", "sha1", "md5", "package_name", "app", "company", "version", "size", "tags", "detected", "trusted", "corrupted", "rating", "created_at"}); err != nil {
		return err
	}
	for _, e := range entries {
		row := []string{
			e.SHA256, e.SHA1, e.MD5, e.PackageName, e.App, e.Company, e.Version,
			strconv.FormatInt(e.Size, 10),
			strings.Join(e.Tags, "|"),
			strconv.FormatBool(e.IsDetected),
			strconv.FormatBool(e.IsTrusted),
			strconv.FormatBool(e.IsCorrupted),
			strconv.Itoa(e.Rating),
			e.CreatedAt,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return w.Error()
}
