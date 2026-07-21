# Grype pre-match denial-of-service findings — consolidated report

**Date:** 2026-07-21
**Scope:** `github.com/anchore/grype` (this fork: `matiasinsaurralde/grype`)
**Research method:** first-principles code analysis + native Go fuzzing of attacker-reachable
pre-match code paths. No upstream diffing, changelogs, or git history were used to locate the
defects.
**Branch:** `claude/grype-zero-day-next-round-vo8xrv` (based on
`claude/grype-zero-day-discovery-oie81z`).

---

## 1. Executive summary

Two independent, reliably-triggerable **denial-of-service** defects were found in Grype's
**pre-match parsing phase** — the code that runs while Grype ingests an artifact (image,
directory, or SBOM) and builds its internal package/context model, *before* any vulnerability
matching begins.

Why the phase matters: Grype has exactly **one** `recover()` in its entire tree,
`callMatcherSafely` in `grype/vulnerability_matcher.go`, and it wraps only the matcher
execution. Anything that panics *before* matching propagates to the top of the goroutine and
**crashes the whole process**. Both findings live in that unguarded window and are driven
entirely by attacker-controlled artifact content.

| # | Title | Component | Class | Trigger (artifact content) | Status |
|---|-------|-----------|-------|-----------------------------|--------|
| 1 | Out-of-bounds read in distro version parsing | `grype/distro.parseVersion` | CWE-125 → CWE-248 (DoS) | distro `VERSION_ID=v` (or `v+<ch>`) | Fixed (prior round) |
| 2 | Nil-pointer deref from version-comparator cache poisoning | `grype/version.getComparator` (reached from `grype/distro`) | CWE-476 → CWE-248 (DoS) | RHEL distro + non-semver version, e.g. `VERSION_ID=test` | Fixed (this round) |

Both are **availability-only**: the Go runtime converts the bad memory access into a safe
panic rather than a controllable write, so neither yields memory corruption or RCE on its own.

This report focuses on **Finding #2** (the latest) and its runbook; Finding #1 is documented
in full in `docs/security/2026-07-distro-version-parse-panic.md` and summarized here for
completeness.

---

## 2. Finding #2 — version-comparator cache poisoning (latest)

### 2.1 What happens

Grype crashes with:

```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation]
  github.com/anchore/go-version.(*Version).Compare(0x0, ...)
  grype/version.semanticVersion.Compare(...)
  grype/version.Version.Compare(...)
  grype/distro.applyChannels(...)
  grype/distro.NewFromRelease(...)
```

when it constructs a distro for a **Red Hat–family** artifact (`ID=rhel`) whose version
string **cannot be parsed as a semantic version** (for example `VERSION_ID=test`).

### 2.2 Root cause

`grype/version/version.go`, `Version.getComparator` memoizes per-format comparators:

```go
func (v *Version) getComparator(format Format) (Comparator, error) {
	if v.comparators == nil {
		v.comparators = make(map[Format]Comparator)
	}
	if comparator, ok := v.comparators[format]; ok {
		return comparator, nil          // (A) cache hit ALWAYS returns nil error
	}
	var comparator Comparator
	var err error
	switch format {
	case SemanticFormat:
		comparator, err = newSemanticVersion(v.Raw, false)  // fail => semanticVersion{obj: nil}, err
	...
	}
	v.comparators[format] = comparator  // (B) caches even when err != nil
	return comparator, err
}
```

Two facts combine:

1. **(B)** stores the comparator *even when construction failed*. A failed
   `newSemanticVersion` returns the zero value `semanticVersion{obj: nil}` next to the error.
2. **(A)** the cache-hit path returns the cached comparator with a **`nil` error**, discarding
   the fact that construction failed.

So the **first** interaction that fails (typically `Validate()`, which just calls
`getComparator` and returns its error) *poisons the cache*. The **second** interaction
retrieves `semanticVersion{obj: nil}` with `err == nil`. Callers trust the nil error and use
the comparator:

```go
func (v semanticVersion) Compare(other *Version) (int, error) {
	...
	return v.obj.Compare(o.obj), nil   // v.obj == nil -> (*go-version.Version).Compare on nil receiver -> panic
}
```

The defect is a **two-step latch**: one call to poison, one call to detonate. The distro path
performs both on the same `*Version`.

### 2.3 Reachability (call chain)

```
scanned artifact  (grype dir:/<image>  with /etc/os-release,  or  grype sbom:file.json  with a "distro" block)
    │  grype/pkg/{syft_provider,syft_sbom_provider}.go  ->  distroFromSBOM
    ▼
distro.FromRelease(release)  ->  distro.NewFromRelease(release, DefaultFixChannels())
    │
    │  (a) version-selection loop validates each candidate as semver:
    │        for _, ver := range []string{release.VersionID, release.Version} {
    │            if ver == "" { continue }
    │            selectedVersionObj = version.New(ver, SemanticFormat)
    │            if selectedVersionObj.Validate() == nil { ...; break }   // <-- POISONS cache on failure
    │        }
    │      both candidates fail  =>  selectedVersionObj carries a poisoned cache
    │
    ▼  (b) distro.New(...) then:
        d.Channels = applyChannels(release, selectedVersionObj, d.Channels, channels)
            │  default RHEL "eus" channel (IDs=["rhel"], Versions=">= 8.0") matches release.ID:
            ▼
            channel.Versions.Satisfied(selectedVersionObj)
                ▼
                Version.Compare / Is  ->  getComparator returns cached {obj: nil}, nil err
                                      ->  semanticVersion.Compare  ->  nil deref  ->  PANIC
```

Key conditions:

- `TypeFromRelease` must return a channel-matching type. The **default** fix channels ship
  exactly one (`rhel`, in `DefaultFixChannels()` / `grype/distro/fix_channel.go`), so
  `ID=rhel` reaches the vulnerable comparison **with no special configuration**.
- The version must be **non-empty** and fail semver parsing (empty strings are skipped by the
  loop and never reach the comparison).

| `ID`     | `VERSION_ID` / `VERSION` | Outcome |
|----------|--------------------------|---------|
| `rhel`   | `test`                   | **panic** |
| `rhel`   | `v`                      | **panic** |
| `rhel`   | `abc` / `x`              | **panic** |
| `rhel`   | `8.10`                   | ok (valid semver) |
| `alpine` | `test`                   | ok (no matching fix channel → no comparison) |

---

## 3. Impact

- **Type:** Denial of service (availability). A single crafted artifact deterministically
  terminates the `grype` process during ingestion, before results are produced.
- **Not memory-corruption / RCE:** the faulting access is a nil-pointer **read**; Go turns it
  into a panic, not a controllable write.
- **Attacker control:** total. The distro `id`/`versionID` come from either
  `/etc/os-release` inside a scanned directory or image layer, or the `distro` block of an
  input SBOM — all attacker-authored.
- **Who is exposed:** any workflow that runs `grype` unattended over untrusted input, e.g.:
  - CI/CD pipelines scanning pulled images or third-party SBOMs.
  - Registry / SBOM ingestion services and batch scanners.
  - "Scan-on-upload" gates where the artifact author is not the operator.
  A crash there breaks the gate or aborts the batch — a cheap, reliable way for an attacker to
  evade or disrupt scanning.
- **Preconditions:** none beyond default configuration. The RHEL `eus` fix channel is enabled
  by default, so no flags are required to reach Finding #2.
- **CVSS (informal):** `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → ~7.5 (High) when Grype scans
  network-supplied artifacts; lower in purely local/manual use.

---

## 4. Reproduction runbook

> All commands assume a Go 1.25.8 toolchain (`go.mod` pins it; `GOTOOLCHAIN=auto` will fetch
> it) and a checkout of this branch. Run these **before** applying the fix to observe the
> crash, and **after** to confirm it is resolved.

### 4.1 Fastest path — isolated unit repro (no grype binary needed)

Create `grype/version/zzrepro_test.go`:

```go
package version

import "testing"

func TestReproCachePoison(t *testing.T) {
	v := New("", SemanticFormat) // "" is not valid semver
	_ = v.Validate()             // step 1: poisons the cache
	// step 2: detonates — panics before the fix, returns an error after it
	_, _ = v.Compare(New("1.0.0", SemanticFormat))
}
```

```console
$ go test ./grype/version/ -run TestReproCachePoison
--- FAIL: TestReproCachePoison
panic: runtime error: invalid memory address or nil pointer dereference   # BEFORE FIX
```

Delete the file afterward.

### 4.2 End-to-end via distro construction (the real reach)

Create `grype/distro/zze2e_test.go`:

```go
package distro

import (
	"testing"
	"github.com/anchore/syft/syft/linux"
)

func TestReproE2E(t *testing.T) {
	rel := linux.Release{ID: "rhel", VersionID: "test"}
	_ = FromRelease(&rel, DefaultFixChannels()) // panics before the fix
}
```

```console
$ go test ./grype/distro/ -run TestReproE2E
panic: runtime error: invalid memory address or nil pointer dereference   # BEFORE FIX
  ... grype/distro.applyChannels
  ... grype/distro.NewFromRelease
```

### 4.3 Real scan — SBOM input

`poc-sbom.json` (a minimal, structurally valid syft-JSON SBOM):

```json
{
  "artifacts": [],
  "artifactRelationships": [],
  "source": { "type": "directory", "target": "." },
  "distro": { "id": "rhel", "versionID": "test" },
  "descriptor": { "name": "syft", "version": "1.0.0" },
  "schema": {
    "version": "16.0.0",
    "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"
  }
}
```

```console
$ go run ./cmd/grype sbom:./poc-sbom.json     # or: grype ./poc-sbom.json / cat poc-sbom.json | grype
panic: runtime error: invalid memory address or nil pointer dereference    # BEFORE FIX
```

### 4.4 Real scan — directory / image

```console
$ mkdir -p ./malicious/etc
$ printf 'ID=rhel\nVERSION_ID=test\n' > ./malicious/etc/os-release
$ go run ./cmd/grype dir:./malicious
panic: runtime error: invalid memory address or nil pointer dereference    # BEFORE FIX
```

The same `/etc/os-release` embedded in a container image crashes an image scan.

### 4.5 Fuzzing (how it was originally surfaced)

A throwaway `internal/fuzzsbom` package (not committed) drove native Go fuzzing at the
attacker-reachable parsers. The minimal harness that catches Finding #2:

```go
func FuzzSemanticVersionPreMatch(f *testing.F) {
	for _, s := range []string{"1.2.3", "v1.0", "", "v"} { f.Add(s) }
	f.Fuzz(func(t *testing.T, s string) {
		v := version.New(s, version.SemanticFormat)
		_ = v.Validate()                                  // poison
		_, _ = v.Compare(version.New("1.0.0", version.SemanticFormat)) // detonate
	})
}
```

`go test -run '^$' -fuzz FuzzSemanticVersionPreMatch` fails on `seed#3` (`""`) within
milliseconds before the fix.

---

## 5. Detection (are you affected / being targeted?)

- **Version:** any Grype build whose `grype/version/version.go` `getComparator` caches on the
  failure path and returns a nil error on cache hit (i.e. before the fix in this branch).
- **Crash signature in logs / core dumps:**
  `runtime error: invalid memory address or nil pointer dereference` with a stack containing
  `grype/version.semanticVersion.Compare` ← `grype/distro.applyChannels` ←
  `grype/distro.NewFromRelease`.
- **Suspicious input to hunt for** (attacker probing this bug):
  - SBOMs whose `distro.id` is `rhel` with a `versionID`/`version` that is not a valid semver
    (e.g. `test`, `v`, `abc`, codenames, empty-after-`v`).
  - Scanned images/dirs whose `/etc/os-release` pairs `ID=rhel` (or an `ID_LIKE` mapping to
    rhel) with a malformed `VERSION_ID`.
- **Quick triage:** re-run the failing scan with the isolated repro in §4.1 against your
  vendored `grype/version` — a panic confirms exposure.

---

## 6. Remediation

### 6.1 The fix (applied in this branch)

`grype/version/version.go` — do **not** cache a comparator whose construction failed, so the
nil-error cache-hit path can never hand back a zero-value comparator:

```diff
+	// only cache successfully constructed comparators. Caching a failed construction would
+	// poison the cache: the cache-hit path above returns a nil error, so a later call would
+	// hand back a zero-value comparator (e.g. semanticVersion{obj: nil}) as if it were valid,
+	// and comparing against it would dereference the nil inner value and panic. This is
+	// reachable pre-match (no recover) during distro construction, so keep failures uncached.
+	if err != nil {
+		return comparator, err
+	}
+
 	v.comparators[format] = comparator
-	return comparator, err
+	return comparator, nil
```

Effect: a failed parse is never memoized, so every subsequent call re-attempts the parse and
consistently returns the error; `Compare`/`Is`/`Satisfied` receive that error and handle it
gracefully instead of dereferencing nil. Successful comparators are still cached, so the
memoization performance benefit is preserved for the common path.

### 6.2 Why this location (defense in depth)

Fixing the cache is the **root cause** and repairs the entire class — not just the distro
crash. The same poisoning could otherwise cause a "successful comparison against a nil
version" anywhere the comparator cache is shared (it is used by every matcher). Two
complementary hardening options, not required by this fix but worth considering upstream:

- Make `semanticVersion.Compare` (and peers) defensive against a nil inner object, returning
  an error rather than dereferencing.
- Extend `callMatcherSafely`-style recovery to wrap distro/context assembly, so a future
  pre-match panic degrades to a logged error instead of a process crash.

### 6.3 Operational mitigations (if you cannot patch immediately)

- Run `grype` as a short-lived child process per artifact and treat a non-zero/panic exit as
  "scan failed" rather than "artifact clean", so a crash cannot be used to bypass a gate.
- Sandbox/resource-limit the scanner and pre-validate SBOM `distro` blocks / `os-release`
  where feasible. These reduce blast radius but do **not** fix the bug — apply the patch.

---

## 7. Verification

### 7.1 Regression tests added

- `grype/version/version_test.go`
  - `Test_getComparator_doesNotCacheFailures` — asserts the poison→use sequence returns an
    error and does not panic (verified to **fail** without the fix at the cache-hit error
    check, and pass with it).
  - `Test_Compare_afterValidate_unparseable` — sweeps every version format.
- `grype/distro/distro_test.go`
  - `Test_NewFromRelease_unparseableVersionWithFixChannelNoPanic` — end-to-end via the default
    RHEL fix channel with `versionID` ∈ {`test`, `v`, `abc`/`x`}.

### 7.2 Commands

```console
$ go build ./...
$ go test ./grype/version/... ./grype/distro/...
ok  	github.com/anchore/grype/grype/version
ok  	github.com/anchore/grype/grype/distro
```

(The Docker-dependent `grype/pkg` image tests are unrelated and require a Docker daemon not
present in the research sandbox; the non-Docker `grype/pkg` unit tests pass.)

### 7.3 Negative control

Reverting only the `getComparator` change makes
`Test_getComparator_doesNotCacheFailures` fail with
`An error is expected but got nil` — confirming the test pins the exact defect.

---

## 8. Scope of the round & what was ruled out

To ensure Finding #2 was the strongest remaining pre-match crash, the following surfaces were
fuzzed (native Go fuzzing) **and** hand-audited without finding a further pre-match panic:

- syft `format.Decode` decoders: syft-json, CycloneDX JSON/XML, SPDX json + tag-value,
  including the `to_syft_model` conversions. JSON and XML nesting are depth-capped by the
  standard library (`encoding/json` and `encoding/xml` both return an "exceeded max depth"
  error rather than overflowing the stack).
- `github.com/anchore/packageurl-go` `FromString`/`Normalize`.
- `cpe.New` → `github.com/facebookincubator/nvdtools` `wfn.Parse` (both URI and formatted-
  string binders).
- Every `grype/version` format constructor plus `Compare`/`Validate` (post-fix sweep) — this
  also covers the previously-flagged portage/gem/pacman/rpm parser concern.

Remaining un-audited surface, ranked, is recorded for the next round in
`docs/security/HANDOFF-next-round.md` (top candidate: archive/layer extraction during image
and directory scans — decompression bombs / zip-slip / infinite loops).

---

## 9. References

- Technical report (Finding #2): `docs/security/2026-07-version-comparator-cache-panic.md`
- Technical report (Finding #1): `docs/security/2026-07-distro-version-parse-panic.md`
- Session handoff / next-round plan: `docs/security/HANDOFF-next-round.md`
- Fix commit: `fix(version): don't cache failed comparators to prevent nil-deref panic`
- Affected code: `grype/version/version.go` (`getComparator`),
  `grype/distro/distro.go` (`NewFromRelease`), `grype/distro/fix_channel.go`
  (`applyChannels`, `DefaultFixChannels`).
