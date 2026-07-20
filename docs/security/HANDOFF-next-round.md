# Session handoff — grype zero-day discovery

Purpose: let a fresh Claude Code session resume this security-research task with full
context. The previous session's conversation does not carry over; this file + the git
branch + PR #1 are the durable record.

## How to resume (first steps in the new session)

1. Make sure you're on the working branch:
   ```
   git fetch origin claude/grype-zero-day-discovery-oie81z
   git checkout claude/grype-zero-day-discovery-oie81z
   ```
2. Read this file and `docs/security/2026-07-distro-version-parse-panic.md`.
3. Confirm the build now works (see "Environment" below):
   ```
   go build ./... && go test ./grype/distro/...
   ```

## What's already done (Finding #1 — COMPLETE)

Process-crashing panic (DoS) in `grype/distro.parseVersion`.

- Root cause: `version[0]` indexed after `strings.TrimPrefix(version, "v")`; input `v`
  or `v+<channel>` reduces to `""` → out-of-bounds read → uncaught panic.
- Why fatal: runs in the pre-match parsing phase, which has NO `recover()`. The only
  recover in the tree is `callMatcherSafely` in `grype/vulnerability_matcher.go`, which
  wraps the matcher phase only.
- Reachable via a normal scan:
  - `grype dir:/image` — `/etc/os-release` with `ID=alpine`, `VERSION_ID=v`.
  - `grype sbom:file.json` — syft-JSON `"distro": {"id":"alpine","versionID":"v"}`
    (omit `version` so `NewFromRelease` falls back to `versionID`).
- Fix (already committed): add `len(version) > 0 &&` guard in `grype/distro/distro.go`.
- Tests (already committed): `Test_parseVersion_shortVersionNoPanic`,
  `Test_NewFromRelease_shortVersionIDNoPanic` in `grype/distro/distro_test.go`.
- Report: `docs/security/2026-07-distro-version-parse-panic.md`.
- PR: https://github.com/matiasinsaurralde/grype/pull/1 (branch -> main).

## Environment notes (why the previous session was limited)

- `go.mod` pins `go 1.25.8`; the image had only `go 1.24.7`.
- Egress previously blocked `proxy.golang.org` / toolchain download, so the full module
  graph could not be fetched and grype could not be compiled or fuzzed. Only the
  self-contained `parseVersion` logic was reproduced standalone.
- FIX APPLIED for this new session: environment network access set to **Trusted**
  (or Custom incl. Go hosts). Go module/toolchain downloads should now work.
- If build still fails on toolchain: `go env -w GOTOOLCHAIN=auto` and retry
  `go build ./...`; it should fetch `golang.org/toolchain@go1.25.8`.

## Next round — hypotheses to pursue (ordered by promise)

Goal: a second, more severe chain (ideally RCE-class), or additional distinct crashes.
Focus on code paths that run BEFORE matching (no recover) or that recover cannot catch
(stack overflow, OOM, concurrent map read/write, `runtime.throw`).

1. **syft format decoders invoked by grype's `format.Decode`** (HIGH).
   grype/pkg/{syft_sbom_provider,cpe_provider,purl_provider}.go call
   `github.com/anchore/syft/syft/format.Decode` in the pre-match phase. Targets:
   - CycloneDX (`github.com/CycloneDX/cyclonedx-go`) JSON/XML decoder.
   - SPDX (tag-value + json) decoder.
   - syft-json decoder.
   Build fuzz harnesses that feed crafted SBOM bytes to `format.Decode` and watch for
   panic/OOM/stack-overflow. Attacker fully controls the file.

2. **`packageurl-go` (`github.com/anchore/packageurl-go`) FromString** (MEDIUM).
   Reached in `pkg.New` via enhancers for purl/cpe/non-syftjson SBOM inputs
   (`grype/pkg/package.go:77`) and in `javaGroupArtifactIDFromPurl`. Malformed PURL
   qualifiers/encoded bytes → check for panics or pathological behavior.

3. **Archive handling (`github.com/mholt/archives`)** (MEDIUM).
   If any scan path unpacks nested archives (jars within jars, image layers), look for
   zip-slip, decompression bombs (OOM), or infinite loops. Confirm whether grype or
   syft drives extraction during a normal scan.

4. **Version parsers reachable pre-match** (LOW — mostly recover-protected).
   Matching-phase parses are caught by `callMatcherSafely`. BUT look for parses that
   run pre-match or that cause stack overflow (unbounded recursion on attacker version
   string) / concurrent map writes — those bypass recover. Candidates to re-audit:
   `grype/version/portage_version.go` (nil-deref on `versionRegexp.FindStringSubmatch`
   when the version has no digit — currently recover-protected, verify it can't be hit
   earlier), `gem_version.go`, `pacman_version.go`, `rpm_version.go`.

5. **Presenters (post-match, no recover)** (LOW — needs operator to pick the format).
   `grype/presenter/sarif/presenter.go` indexes `m.MatchDetails[0]`, `Locations[0]`,
   `Vulnerability.URLs[0]` without length guards. A match with empty details/locations
   would panic, but reachability depends on `-o sarif` being selected. Lower priority
   because it's not purely artifact-driven.

## Reproduction assets

- Standalone repro of Finding #1 (verbatim parseVersion + NewFromRelease selection)
  was kept in the session scratchpad only (not committed). It is trivial to recreate
  from the report if needed.
- PoC SBOM distro block: `{"id":"alpine","versionID":"v"}` (no `version`).
- PoC os-release: `ID=alpine` + `VERSION_ID=v`.

## Ground rules (from the task)

- First-principles code analysis only. Do NOT diff against upstream/patched grype, and
  do NOT use changelogs, git history, or the internet to locate the bug.
- Cloning arbitrary dependency GitHub repos is blocked by the GitHub proxy (session is
  scoped to matiasinsaurralde/grype), but `go mod download` fetches all dependency
  source into the module cache — audit from there.
- Develop on `claude/grype-zero-day-discovery-oie81z`; commit and push there.
