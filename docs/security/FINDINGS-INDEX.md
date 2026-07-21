# Grype security research — findings index

First-principles code analysis + fuzzing + empirical PoCs against a fresh, default grype.
Ground rules: no upstream diffing/changelogs to locate bugs. Each finding has a standalone
report; this file is the map.

Branch: `claude/grype-zero-day-next-round-vo8xrv`.

| # | Finding | Class | Trigger | Default-reachable? | Status | Report |
|---|---------|-------|---------|--------------------|--------|--------|
| 1 | Distro `parseVersion` out-of-bounds panic | DoS (CWE-125→248) | distro `VERSION_ID=v` / `v+ch` | yes | **fixed** (branch) | `2026-07-distro-version-parse-panic.md` |
| 2 | Version-comparator cache-poisoning nil deref | DoS (CWE-476→248) | RHEL distro + non-semver version | yes | **fixed** (branch) | `2026-07-version-comparator-cache-panic.md` |
| 3 | Working-dir config injection → go-getter exec/SSRF | Code exec / SSRF (CWE-15/829/78/918) | `.grype.yaml` in CWD sets `db.update-url` | yes (CWD config on by default) | analyzed + PoC | `2026-07-config-injection-go-getter-rce.md` |
| 4 | Go toolchain execution while scanning | Code exec (CWE-78/829) | `go.mod` in scanned tree | yes | analyzed + PoC + fix proto | `2026-07-go-toolchain-execution-on-scan.md` |

Consolidated DoS write-up (findings 1–2, operator-facing): `REPORT-2026-07-pre-match-dos-findings.md`.

---

## Severity ranking (most to least severe / easiest to exploit)

1. **#4 Go toolchain execution (RCE-class, file-only trigger).** Merely scanning a directory
   that contains a `go.mod` runs the `go` toolchain in the attacker's directory (default, no
   config, no flags, no git). Escalates to arbitrary local command execution via a
   `go`/`toolchain` version directive that makes `go` execute a `goX.Y.Z` binary from `PATH`
   (marker-proven), plus toolchain-download/SSRF/VCS-exec/DoS. The cleanest and "deepest" issue.

2. **#3 go-getter config injection (RCE-class, needs untrusted CWD).** A `.grype.yaml` in the
   directory the victim runs grype from redirects the default pre-scan DB auto-update through
   `hashicorp/go-getter` with `git`/`hg`/`file` getters enabled and no validation → SSRF,
   local-file read, git/hg subprocess exec, and full RCE where git `ext` is permitted (PoC
   reached a git-spawned `sh -c`). Needs the victim's CWD to be attacker-controlled (common CI
   clone-and-scan), so slightly higher bar than #4's "any go.mod in the tree."

3. **#1 / #2 Denial of service (fixed on this branch).** Single crafted artifact
   (`/etc/os-release` or SBOM `distro` block) deterministically crashes the whole grype process
   in the pre-match phase (no `recover`). Both root-caused and fixed with regression tests.

---

## Cross-cutting observations

- **Two independent code-execution surfaces**, reached by different paths:
  the **DB-update path** (#3, go-getter) and the **cataloging path** (#4, go toolchain).
  Both stem from grype invoking powerful, network-/subprocess-capable machinery on
  attacker-influenced input by default.
- **Ecosystem survey (for #4):** empirically, of grype's ~15 supported package ecosystems,
  **only Go executes anything at parse time.** npm `preinstall`, Ruby `.gemspec` backticks, and
  `setup.py` are parsed statically. So the parse-time RCE is Go-specific; other artifact types
  are not a parse-time exec vector.
- **The pre-match phase has no `recover()`** (only `callMatcherSafely` wraps the matcher),
  so any panic there (#1, #2) is a full process crash — a recurring theme worth systemic
  hardening (wrap cataloging/context assembly in recovery, or fuzz these paths in CI).

## Suggested remediation priorities

1. #4: default `cfg.Packages.Golang.UsePackagesLib = false` in grype (fix prototype in that
   report); never run the Go toolchain on untrusted targets, or sandbox it hard.
2. #3: restrict go-getter to `http(s)` getters, validate the update URL scheme for all getters
   (including the listing `GetFile`), and don't auto-load config from an untrusted CWD.
3. #1/#2: already fixed here; consider adding a top-level `recover()` around pre-match assembly
   as defense in depth, plus native fuzz targets in CI for the decoders and version/distro
   parsers.
