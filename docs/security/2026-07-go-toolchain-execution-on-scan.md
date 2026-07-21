# Security finding: grype executes the Go toolchain (`go list`) on untrusted scanned directories

- **Component:** syft Go-module cataloger used by grype during directory/image scanning
  (`syft/pkg/cataloger/golang`, `UsePackagesLib` → `golang.org/x/tools/go/packages`)
- **Class:** CWE-78 / CWE-807 — execution of an external program driven by untrusted input
  (untrusted-input-triggered toolchain execution), escalating to SSRF (CWE-918), VCS
  subprocess execution, network code download+execution, and DoS.
- **Impact:** Merely **scanning a directory that contains an attacker-authored `go.mod`**
  causes grype — with **default configuration, no flags, no git/config changes** — to spawn
  the real `go` binary (`go list … -deps=true … all`) with its working directory set to the
  attacker-controlled directory. This is silent and happens as part of "parsing" the project.
- **Attacker input:** a `go.mod` file placed anywhere in the scanned tree. No user
  interaction beyond running `grype dir:<path>` / `grype <path>` (the normal way grype is run
  in CI on a checked-out repo).
- **Status:** unfixed — analysis + working PoC (marker created by grype's own scan) below.

---

## 1. Summary

grype catalogs directories with syft. Syft's Go-module cataloger defaults to
`UsePackagesLib: true` (`syft/pkg/cataloger/golang/config.go`:
`DefaultCatalogerConfig()` → `UsePackagesLib: true`), whose own documentation warns it
*"executes golang tooling found on the path in addition to potential network access."*

When grype scans a directory containing a `go.mod`, that cataloger calls
`golang.org/x/tools/go/packages` `packages.Load(cfg, "all")` with `Dir` set to the module's
directory. `go/packages` shells out to the **`go` binary** to enumerate the module graph.

A vulnerability scanner running an arbitrary, powerful build tool (`go`, which performs
network access, VCS subprocess execution, and toolchain download+execution) against
**untrusted code** is a serious trust-boundary violation. It is reachable with zero
configuration and no git tweaks — exactly the "parse a file → run a program" primitive that
scanners are supposed to avoid.

## 2. Root cause

`syft/pkg/cataloger/golang/config.go`:

```go
func DefaultCatalogerConfig() CatalogerConfig {
    return CatalogerConfig{
        // ...
        UsePackagesLib:    true,   // <-- default ON
        MainModuleVersion: DefaultMainModuleVersionConfig(),
    }
}
```

`syft/pkg/cataloger/golang/parse_go_mod.go`:

```go
if c.usePackagesLib {
    sourcePackages, sourceModules, sourceDependencies, err = c.loadPackages(modDir, reader.Location)
    // ...
}

func (c *goModCataloger) loadPackages(modDir string, ...) (...) {
    cfg := &packages.Config{
        Mode: packages.NeedModule | packages.NeedName | packages.NeedFiles |
              packages.NeedDeps | packages.NeedImports,
        Dir:  modDir,                                    // attacker-controlled directory
        Tests: true,
        Env:  append(os.Environ(), "GOWORK=off"),
    }
    rootPkgs, err := packages.Load(cfg, "all")           // <-- runs the `go` binary
    // ...
}
```

`packages.Load` with the default driver executes `go list` in `modDir`. The scanned
directory therefore controls the working directory and the `go.mod`/`*.go`/`go.sum` inputs of
a `go` subprocess.

## 3. Proof of concept (grype's own scan runs a program)

A "malicious artifact" is just a directory containing a `go.mod`. To capture the fact that
grype spawns `go`, put a shim named `go` first on `PATH` (this stands in for "an arbitrary
program was executed"; the shim writes a marker file — the classic PoC oracle):

```sh
# shim/go — records that it ran, then delegates so the scan still succeeds
#!/bin/sh
echo "GO EXECUTED args=[$*] cwd=[$(pwd)]" >> /tmp/go_invoked.log
exec /usr/local/go/bin/go "$@"
```

```sh
# the crafted artifact
mkdir -p scan/  && cat > scan/go.mod <<'EOF'
module evil.example/pwn
go 1.21
require github.com/anchore/grype v0.90.0
EOF

PATH="$PWD/shim:$PATH" grype dir:./scan -q
```

Observed (verbatim from a default `grype` build scanning the directory):

```
GO EXECUTED args=[list -e -f {{context.ReleaseTags}} -- unsafe] cwd=[.../scan]
GO EXECUTED args=[list -e -json=Name,ImportPath,Error,Dir,GoFiles,...,Module \
   -compiled=false -test=true -export=false -deps=true -find=false \
   -buildvcs=false -pgo=off -- all] cwd=[.../scan]
```

The `go` toolchain was executed twice, in the attacker's directory, purely because a `go.mod`
was present — no configuration, no flags, no git changes. The marker file is created **by
grype's act of scanning**, satisfying the PoC oracle.

## 4. Impact and escalation

Executing `go list` on untrusted input is dangerous because `go` is not a parser — it is a
network- and subprocess-capable build tool. Consequences, by increasing environmental
dependency:

1. **Untrusted-directory toolchain execution (confirmed, default):** grype runs `go` with the
   attacker's `go.mod`/CWD. This alone is the trust-boundary break.
2. **Denial of service (confirmed-by-design):** `go list … -deps=true all` can be steered to
   resolve/download a large or pathological module graph, or (via a `go 1.<big>` / `toolchain`
   directive) to attempt a full toolchain download — CPU/disk/network exhaustion during a
   "scan".
3. **SSRF / outbound requests (environment-dependent):** module resolution issues requests to
   `https://<import-path>?go-get=1` and to `GOPROXY`. With the commonly-set CI value
   `GOFLAGS=-mod=mod` (grype's invocation uses `-mod` default = `readonly`, which an
   environment override relaxes), a `require attacker.host/x` makes grype's `go` subprocess
   reach out to an attacker-chosen host.
4. **VCS subprocess execution (environment-dependent):** with the `,direct` GOPROXY fallback
   (default component) and `-mod=mod`, modules absent from the proxy are fetched via
   `git`/`hg`/`bzr`/`svn`/`fossil` — turning a scanned `go.mod` into attacker-directed
   `git clone` invocations.
5. **Network code download + execution (environment-dependent):** a `toolchain goX.Y.Z`
   directive with `GOTOOLCHAIN=auto` downloads and **executes** a toolchain; and where the git
   `ext` protocol is permitted or a custom/attacker `GOPROXY`/`GONOSUMCHECK` is configured
   (all common in CI), this reaches full arbitrary command execution.

### Escalations that did **not** fire under a default sandbox (tested, for honesty)

- **cgo compiler hijack** (`#cgo CFLAGS: -B<dir>` / direct `cc` probe): grype's `go list` runs
  with `-compiled=false`, so the C toolchain is **not** invoked — verified with `cc`/`gcc`/
  `clang` and `as`/`cc1`/`cpp` shims (no marker). The classic cgo-flag RCE is therefore not
  reachable through grype's specific flags on a stock setup.
- **`replace golang.org/toolchain => ./local`:** Go resolves toolchain switching before module
  replaces, so a local malicious toolchain is not executed (no marker).
- **Bare `require attacker.host/x`:** under the default `-mod=readonly` and `go list -e`, no
  `git`/download fired in the sandbox.

The honest characterization: **the default, no-precondition result is "grype executes the Go
toolchain on untrusted directories,"** with SSRF / VCS-exec / network-code-exec / DoS
escalations that become reachable under the environment conditions (`-mod=mod`, custom
`GOPROXY`, `GONOSUMCHECK`, permissive git protocols, `toolchain` directives) that are common in
real CI runners. A security scanner should not execute the target's build toolchain at all.

## 5. Remediation

1. **Do not run the Go toolchain on untrusted input.** In grype, disable syft's
   `UsePackagesLib` for the Go cataloger by default (parse `go.mod`/`go.sum` statically with
   `golang.org/x/mod/modfile`, which syft already does as the base case). Make toolchain
   execution strictly opt-in and loudly documented as unsafe for untrusted targets.
2. If source analysis must remain, sandbox the `go` subprocess: force
   `GOFLAGS=-mod=readonly`, `GOPROXY=off`, `GOTOOLCHAIN=local`, `GONOSUMCHECK` unset,
   `GIT_ALLOW_PROTOCOL=` (empty), no network, and a scratch `GOMODCACHE`/`GOPATH` — so `go
   list` cannot download modules, switch toolchains, spawn VCS tools, or reach the network.
3. Document clearly that scanning untrusted repositories executes the Go toolchain, so
   operators can gate it (e.g. `--exclude` go.mod, or run under an isolated user/namespace).

## 6. Relationship to the other findings on this branch

This is distinct from — and matches the "deeper / easier to exploit" description better than —
the config-injection go-getter finding: it needs **no configuration change and no git
protocol tricks**, only a `go.mod` in the scanned tree, and it fires during ordinary
directory cataloging rather than the DB-update path. It is unrelated to the two version/distro
DoS findings.
