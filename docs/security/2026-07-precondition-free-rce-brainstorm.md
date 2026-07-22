# Brainstorm: is there a precondition-free RCE from `clone repo → run grype`?

Target scenario (the one that matters):

1. A repo contains a malicious artifact.
2. Victim clones it.
3. Victim runs grype (default build, default config, default env; typically from inside the
   clone, i.e. `grype .` / `grype dir:.`).
4. The artifact triggers arbitrary command execution — **no PATH edits, no `GOFLAGS`, no
   config changes, no git protocol tweaks by the victim.**

This document records the candidate vectors, what was tested, and why a *fully*
precondition-free arbitrary-command RCE is (so far) blocked — plus the one lead still open.

---

## The base primitive (precondition-free, but not attacker code)

Confirmed and precondition-free: scanning a directory that contains a `go.mod` makes grype
run `go list … -deps … all` in that directory (see
`2026-07-go-toolchain-execution-on-scan.md`). But `go list` executes **Google's `go`
toolchain**, not repo code. Turning that into *arbitrary* code requires making `go` execute
something the attacker controls. The rest of this doc is about whether the repo alone can do
that.

## Vector A — Go `toolchain`/`go` directive → execute a `goX.Y.Z` binary

Idea: a `go.mod` with `go 1.99.0` makes `go` resolve and execute a toolchain named
`go1.99.0`. If the attacker controls that binary → RCE.

**Result: blocked for a repo-only attacker.** Read from the Go source
(`cmd/go/internal/toolchain/select.go` `Exec()`), the toolchain binary is resolved ONLY via:

1. a test-only `GOROOT`-env branch (`TestVersionSwitch`, not reachable in production),
2. `pathcache.LookPath(gotoolchain)` — an **absolute** `PATH` directory, and
3. a checksum-verified module download (extracted into `GOMODCACHE`, exec `bin/go`).

Tested negatives (markers did **not** fire):

- `goX.Y.Z` placed **inside the scanned directory** or the CWD — not used (Go uses
  `exec.LookPath`, which since Go 1.19 refuses relative/`.`-in-`PATH` matches, `ErrDot`).
- `.` present in `PATH` with the binary in the repo — not used (same `ErrDot` hardening).
- `replace golang.org/toolchain => ./local` — not used (toolchain switch precedes replaces).
- Malicious `GOPROXY` serving a fake toolchain — **Go refuses**: toolchain downloads are
  always verified against the checksum database and ignore the repo-local `go.sum`
  (`verifying module: checksum database disabled by GOSUMDB=off`, even with a matching
  `go.sum`).

The `PATH` variant (marker-proven) needs the attacker binary in an **absolute** `PATH`
directory. A repo the victim clones cannot write to `PATH`, `~/go/bin`, or `GOMODCACHE`
through clone-or-scan, so this is **not** precondition-free — it needs a separate PATH-write
foothold (real, but a precondition).

## Vector B — `.grype.yaml` in the repo → config injection → exec

Idea: grype auto-loads `./.grype.yaml` (fangs `FindInCwd`, default) when run from the clone.
The attacker ships it. See `2026-07-config-injection-go-getter-rce.md`.

**Result: not precondition-free for *arbitrary* exec.** The default-reachable payload is the
DB `update-url` → `hashicorp/go-getter` with `git`/`hg`/`file` getters. Verified that
go-getter's git commands are all `--`-guarded (`clone -- url`, `ls-remote --symref -- url`,
`fetch origin -- ref`), so no argument-injection RCE. Clean RCE there needs the git `ext`
protocol (disabled by default) or `hg` (rarely installed). Default reach is SSRF / attacker
`git clone` / local-file read — powerful, but not arbitrary command execution without an
extra environmental condition.

## Vector C — other ecosystems' parsers

**Result: none.** Empirically scanned 18 crafted files across ~15 ecosystems (npm w/
`preinstall`, `setup.py` w/ `os.system`, Ruby `.gemspec` backticks, PHP, Rust, Java, .NET,
apk, dpkg, Dart, Elixir, GitHub Actions, Terraform) under a 55-tool `PATH` shim set — only
`go` executed. All other artifact parsers are static. Static confirmation: of syft's ~40
catalogers, only `golang` imports `os/exec`/`go/packages` at runtime.

## Vector D — archive extraction (tested → CLOSED for the default path)

Default-on: `IncludeIndexedArchives: true` (grype searches within `.zip`/`.jar`). So a repo
containing a crafted jar IS unpacked during a default scan. But the extraction that actually
runs does **not** give an attacker-controlled write path:

- The Java parser reads jar metadata (`pom.properties`, `MANIFEST.MF`) **in memory** and
  extracts nested archives via `ExtractFromZipToUniqueTempFile`, which writes each entry to
  `os.CreateTemp(dir, filepath.Base(clean(name))+"-")` — a **fresh unique temp file** whose
  name is a stripped basename plus a random suffix. Attacker entry names/`../` therefore
  cannot control the destination, and because it creates a new file (not `open` on an
  existing path) there is no symlink-through write.
- The full-extraction helper `UnzipToDir` (the one that joins entry names via `SafeJoin` and
  `os.OpenFile(O_CREATE)`, i.e. the symlink-prone path) has **no callers in syft's runtime**
  (definition only) — it is never reached during cataloging.

So the archive surface does not yield an arbitrary file write via a default scan.

## Bare developer laptop — the strict case (empirical verdict)

Threat model: a developer clones a repo and runs grype (default build/config/env, from inside
the clone). No PATH edits, no `GOFLAGS`, no attacker access to the machine beyond the repo
contents.

**`strace -f -e trace=execve` of a real scan** (`grype dir:<cloned-git-repo>` where the repo
is a git repo with `go.mod` + `main.go`) shows grype's *entire* subprocess surface is:

```
execve("/usr/local/go/bin/go", ["go", "list", "-e", …, "all"], …)   # + grype itself
```

Nothing else — no `git`, `cc`, `cgo`, `pkg-config`, `sh`, or any helper. And `go list` (with
grype's exact flags) spawns **no** child of its own, even for a package with
`import "C"` + `#cgo pkg-config: …` + `#cgo CFLAGS: -B…` (verified: no `cc`/`cc1`/`pkg-config`
execve — `-compiled=false` means cgo/compiler are never invoked).

So on a bare laptop the only program grype runs is `go`, and `go` executes attacker code only
via the toolchain switch — which Vector A shows is unreachable for a repo-only attacker
(absolute-`PATH`/checksum-download only; the repo cannot write to `PATH`, `~/go/bin`, or
`GOMODCACHE` via clone-or-scan, and `go list` never runs `go install`). Even the near-universal
Go-dev setup (`~/go/bin` on `PATH`) does not help: the attacker still cannot place a binary
there.

The decompressor sub-vector of Vector B is also closed: grype's `untar` **skips
symlinks/hardlinks and rejects `..` entries**, and go-getter's zip/tgz decompressors likewise
guard `..`, so an attacker-shipped `.grype.yaml` + local archive cannot achieve an arbitrary
file write.

**Verdict:** no precondition-free arbitrary command execution was found for the bare-laptop
`clone → grype` flow. The precondition-free *trigger* (grype runs `go` on the repo) is real and
is itself worth removing, but converting it to *attacker code* needs a precondition Go's
hardening specifically denies to a repo-only attacker.

## Assessment

A **fully precondition-free arbitrary-command RCE was not found.** Every repo-content-driven
surface reachable by a default `clone → grype` is either static (Vector C), writes only to
attacker-uncontrolled temp names (Vector D), or is blocked by upstream hardening:

- **Vector A (Go toolchain)** — provably blocked for a repo-only attacker: the toolchain
  binary is resolved only via an absolute `PATH` entry or a checksum-verified download; a
  repo cannot plant it (dir-local/CWD/`.`-in-`PATH` all rejected by Go 1.19 `ErrDot`; a
  malicious `GOPROXY` cannot deliver a toolchain because Go enforces the checksum DB and
  ignores the repo `go.sum`).
- **Vector B (`.grype.yaml` + go-getter)** — default reach is SSRF / `git clone` / file read;
  arbitrary exec needs git `ext` (off by default) or `hg`, plus the victim running grype from
  inside the clone.

Each realistic RCE needs exactly **one** precondition:

| Vector | The single precondition | Reality |
|---|---|---|
| A | attacker-writable **absolute** `PATH` dir (`~/go/bin`, workspace `bin`, `GOTOOLCHAIN=path`) | common in CI/dev, not universal |
| B | grype run from inside the clone **and** git `ext`/`hg` present | CWD auto-load is default; `ext`/`hg` are not |

**Conclusion for the brainstorm:** the precondition-free *trigger* exists (a `go.mod` makes
grype run `go` on the repo, no strings attached), but converting that into *attacker* code
execution requires one of the preconditions above — Go's toolchain hardening is specifically
what stands in the way. The highest-value defensive fix remains disabling
`UsePackagesLib` (don't run the Go toolchain on untrusted input) so even the precondition-free
*trigger* disappears. If a genuinely zero-precondition RCE exists it is most likely in a
dependency's parser we treat as static but which has latent exec/deserialization behavior —
the next place to look would be fuzzing the individual language-manifest parsers for
surprising side effects, and re-checking each syft cataloger's third-party parser libs.

_Related reports: `2026-07-go-toolchain-execution-on-scan.md`,
`2026-07-config-injection-go-getter-rce.md`, `FINDINGS-INDEX.md`._
