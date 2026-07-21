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

## What's already done (Finding #2 — COMPLETE, this round)

Process-crashing panic (DoS) from version-comparator **cache poisoning**, reached during
pre-match distro construction via the default RHEL fix channel.

- Root cause: `grype/version.Version.getComparator` cached a comparator even when
  construction failed; the cache-hit path returns a `nil` error, so a later call handed
  back a zero-value `semanticVersion{obj: nil}` as if valid → `Compare` dereferences the
  nil inner version → uncaught panic.
- Trigger: an artifact marked `ID=rhel` (matches `DefaultFixChannels()` eus channel,
  `>= 8.0`) with a **non-empty** version that fails semver parsing, e.g.
  `VERSION_ID=test`. `NewFromRelease` validates (poisons cache), then `applyChannels`
  compares the same `*Version` against the channel constraint (uses poisoned cache) → crash.
- Reachable via `grype dir:/image` (`/etc/os-release`) and `grype sbom:file.json`
  (`"distro": {"id":"rhel","versionID":"test"}`), all pre-match (no `recover()`).
- Fix (committed): don't cache failed comparators in `grype/version/version.go`.
- Tests (committed): `Test_getComparator_doesNotCacheFailures`,
  `Test_Compare_afterValidate_unparseable` (`grype/version/version_test.go`);
  `Test_NewFromRelease_unparseableVersionWithFixChannelNoPanic` (`grype/distro/distro_test.go`).
- Report: `docs/security/2026-07-version-comparator-cache-panic.md`.

### Ruled out this round (audited + fuzzed, no pre-match crash found)

- syft `format.Decode` decoders (syft-json, cyclonedx json/xml, spdx json/tag-value):
  byte-level and structure-aware (template) fuzzing, plus hand audit of the
  `to_syft_model` conversions. JSON and XML nesting are depth-capped by the stdlib
  (`encoding/json`, `encoding/xml` both return "exceeded max depth", no stack overflow).
- `packageurl-go` `FromString`/`Normalize`, `cpe.New` → nvdtools `wfn.Parse` (URI + FSB):
  fuzzed and audited; bounds-safe.
- All `grype/version` format constructors + `Compare`/`Validate` swept by fuzzing after the
  fix — no further panics (this also covers the hypothesis-#4 portage/gem/pacman/rpm concern).

## What's already done (Finding #1 — COMPLETE, prior round)

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

Goal: a third distinct chain, or a more severe class. Focus on code paths that run BEFORE
matching (no recover) or that recover cannot catch (stack overflow, OOM, concurrent map
read/write, `runtime.throw`). Hypotheses #1, #2, #4 from the prior list are now RULED OUT
(see "Ruled out this round" above) — do not re-fuzz them without a new angle.

1. **Archive / layer handling during image and dir scans** (HIGH, was #3).
   If any scan path unpacks nested archives (jars within jars, image layers, tar), look
   for zip-slip, decompression bombs (OOM), or infinite loops. Confirm whether grype or
   syft drives extraction during a normal `grype dir:`/`grype <image>` scan (syft is the
   cataloger; check where grype invokes it and whether attacker-controlled archive bytes
   reach an extractor with no size/entry cap). This is the largest un-audited surface.

2. **Concurrent map access / data races in the pre-match assembly** (MEDIUM).
   `removePackagesByOverlap`, `FromPackages`, and the syft catalog build run over
   attacker-sized collections. Look for a map written from multiple goroutines
   (`runtime.throw("concurrent map ...")` bypasses recover). Run the matcher end-to-end
   under `-race` with a large crafted SBOM.

3. **Presenters (post-match, no recover)** (LOW — needs operator to pick the format).
   `grype/presenter/sarif/presenter.go` indexes `m.MatchDetails[0]`, `Locations[0]`,
   `Vulnerability.URLs[0]` without length guards. A match with empty details/locations
   would panic, but reachability depends on `-o sarif` being selected. Lower priority
   because it's not purely artifact-driven.

4. **DB / vulnerability provider ingestion** (MEDIUM, new).
   The vulnerability DB is normally trusted, but if any provider parses attacker-adjacent
   data (e.g. version constraints from the DB compared against attacker versions), a
   crafted constraint string could misbehave. Lower confidence on attacker control.

## Reproduction assets

- Fuzz harnesses for this round (native Go fuzzing over `format.Decode`, `cpe.New`,
  `packageurl.FromString`, the distro parsers, and every `version.*` format) were kept in
  the session scratchpad only (not committed) — a throwaway `internal/fuzzsbom` package
  whose seed loader hardcoded the syft module-cache path. Recreate from the reports if
  needed; the durable coverage lives in the regression tests.
- Finding #1 — PoC SBOM distro block: `{"id":"alpine","versionID":"v"}` (no `version`);
  PoC os-release: `ID=alpine` + `VERSION_ID=v`.
- Finding #2 — PoC SBOM distro block: `{"id":"rhel","versionID":"test"}`;
  PoC os-release: `ID=rhel` + `VERSION_ID=test`.

## Ground rules (from the task)

- First-principles code analysis only. Do NOT diff against upstream/patched grype, and
  do NOT use changelogs, git history, or the internet to locate the bug.
- Cloning arbitrary dependency GitHub repos is blocked by the GitHub proxy (session is
  scoped to matiasinsaurralde/grype), but `go mod download` fetches all dependency
  source into the module cache — audit from there.
- Develop on the round's designated branch; commit and push there. Finding #1 was on
  `claude/grype-zero-day-discovery-oie81z`; Finding #2 (this round) is on
  `claude/grype-zero-day-next-round-vo8xrv` (which was based on the discovery branch).
