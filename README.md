# mcp-koodous

An MCP server and a bulk downloader for [Koodous](https://koodous.com/), the
collaborative Android malware repository.

Where AndroZoo hands you a catalogue file and downloads by hash, Koodous
searches server-side: a query language covers package name, developer,
certificate, tags, size and dates, so there is nothing to keep on disk. It also
carries what AndroZoo does not — Androguard and Droidbox reports, YARA matches,
and community annotations.

Requires a developer token, generated in the Developers area of your account
settings after signing up at <https://koodous.com>.

## Tools

| Tool | What it answers |
|---|---|
| `kd_lookup` | what Koodous records about one SHA-256 |
| `kd_search` | which samples match a query — package, developer, certificate, tag, date, size |
| `kd_analysis` | the stored Androguard / Cuckoo / Droidbox report |
| `kd_matches` | which YARA rules matched the sample |
| `kd_download` | fetch APKs by SHA-256 into a directory |

## Configuration

| Variable | Meaning |
|---|---|
| `KOODOUS_TOKEN` | the developer token; on macOS it can live in the keychain under the service name `developer.koodous.com` instead |

```json
{
  "mcpServers": {
    "koodous": {
      "command": "/path/to/mcp-koodous",
      "args": ["-out", "/data/apks"],
      "env": { "KOODOUS_TOKEN": "..." }
    }
  }
}
```

Storing the token in the keychain keeps it out of the config file:

```sh
security add-generic-password -s developer.koodous.com -a "$USER" -w
```

The `-w` with no value prompts, so the token never reaches your shell history.

## kddl

Bulk downloads, from a file of hashes or straight from a query.

```sh
kddl -q 'package: com.parental.control.kidgy' -manifest kidgy.csv -dry-run
kddl -i kidgy.csv -o ./apks/kidgy
kddl -q 'cert: 60BBF1896747E313B240EE2A54679BB0CE4A5023' -n 200 -manifest family.csv -dry-run
kddl -q 'developer: "Kidgy" AND detected: true' -n 50 -o ./apks
```

`-dry-run` selects and writes the manifest without touching a single APK, so a
query can be checked before it is acted on. The manifest holds the metadata the
APK files themselves do not carry — package, app name, developer, version,
tags, community flags — which is what turns a directory of hash-named files
back into a dataset.

Each APK lands in a temporary file, is verified against its SHA-256 and only
then takes its final name. Hashes already on disk are skipped, so a re-run is a
resume.

## Query language

Modifiers combine with `AND`, `OR`, parentheses and `-` for NOT; bare words
match package, app and developer names at once.

| Modifier | Example |
|---|---|
| `package:` | `package: com.parental.control.kidgy` |
| `app:` | `app: "Whatsapp premium"` |
| `developer:` / `company:` | `developer: "WhatsApp Inc."` |
| `cert:` / `certificate:` | `cert: 60BBF1896747E313B240EE2A54679BB0CE4A5023` |
| `version:` | `version: 2.22.4.1` |
| `size:` | `size: > 125125` (bytes) |
| `tag:` | `tag: playstore` |
| `date:` | `date: [2021-03-25, 2021-03-26]` |
| `detected:` / `trusted:` / `corrupted:` / `analyzed:` | `detected: true` |
| `rating:` | `rating: >= 2` |
| `hash:` | any of sha1, sha256, md5 |

`cert:` is the strongest pivot: one sample's signing certificate finds every
other build signed with the same key, which is how a white-label family shows
itself.

## Caveats

- **The flags are community opinion.** `detected` means an analyst marked it as
  malware, `trusted` that someone vouched for it, `rating` is a vote tally.
  None of it is a vendor verdict.
- **`corrupted` is usually benign.** It means the dex, a resource or the
  certificate could not be read — common for APKs pulled off devices, which
  frequently have no certificate.
- **Absence proves nothing.** The corpus is what people uploaded.
- **Quotas are per account tier**, and each download costs two API calls: one to
  mint a link, one to fetch it. Concurrency is capped low on purpose.
- Downloaded APKs are live malware as often as not. They land on disk. Nothing
  here opens them.
