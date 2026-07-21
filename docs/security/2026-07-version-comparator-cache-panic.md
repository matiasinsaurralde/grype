# Security finding: process-crashing panic from version-comparator cache poisoning

- **Component:** `grype/version` (version comparator cache), reached from `grype/distro`
  during pre-match distro construction
- **Class:** CWE-476 NULL pointer dereference → uncaught `panic` → CWE-248 uncaught
  exception (Denial of Service)
- **Impact:** A single crafted artifact reliably crashes the entire `grype` process
  before any matching happens.
- **Attacker input:** fully attacker-controlled (`/etc/os-release` in a scanned
  directory/image, or the `distro` block of an input SBOM).
- **Status:** fixed in this branch (cache no longer stores failed comparators + regression
  tests).

---

## 1. Summary

`grype` crashes with an unrecoverable `runtime error: invalid memory address or nil
pointer dereference` when it constructs a distro for a Red Hat–family artifact whose
version string cannot be parsed as a semantic version (for example `VERSION_ID=test`).

The panic occurs in the **pre-match parsing phase** (distro construction), which — unlike
the matcher phase — is not protected by any `recover()`. The result is a hard crash of the
whole process: a denial-of-service triggerable by anyone who can influence the artifact a
victim scans (a container image, a directory, or an SBOM file).

This is a distinct root cause from the earlier `parseVersion` out-of-bounds panic
(`2026-07-distro-version-parse-panic.md`); it lives in the version-comparator cache and is
reached through a different code path (`applyChannels` / fix-channel version constraints).

## 2. Root cause

`grype/version/version.go`, `Version.getComparator`:

```go
func (v *Version) getComparator(format Format) (Comparator, error) {
	if v.comparators == nil {
		v.comparators = make(map[Format]Comparator)
	}
	if comparator, ok := v.comparators[format]; ok {
		return comparator, nil          // (A) cache hit discards any construction error
	}

	var comparator Comparator
	var err error
	switch format {
	case SemanticFormat:
		comparator, err = newSemanticVersion(v.Raw, false)   // on failure: semanticVersion{obj: nil}, err
	...
	}

	v.comparators[format] = comparator  // (B) caches even when err != nil
	return comparator, err
}
```

Two facts combine into the bug:

1. **(B)** stores the comparator in the cache **even when construction failed**. For
   `SemanticFormat`, a failed `newSemanticVersion` returns the zero value
   `semanticVersion{obj: nil}` alongside the error.
2. **(A)** the cache-hit path returns the cached comparator with a **`nil` error**,
   throwing away the fact that construction had failed.

So the first call that fails (typically `Validate()`, which calls `getComparator` and
returns its error) *poisons* the cache. A **second** call then retrieves
`semanticVersion{obj: nil}` with `err == nil`. Callers such as `Version.Compare` trust the
nil error and invoke the comparator:

```go
func (v semanticVersion) Compare(other *Version) (int, error) {
	...
	return v.obj.Compare(o.obj), nil   // v.obj is nil -> (*go-version.Version).Compare(nil, ...) -> panic
}
```

`(*github.com/anchore/go-version.Version).Compare` dereferences its nil receiver (via
`String()`), producing an uncaught nil-pointer panic.

The defect requires **two** interactions with the same `*Version` (one to poison, one to
use). The distro path below does exactly that.

## 3. Why it crashes the whole process

`grype` has exactly **one** `recover()` in its entire tree, in `callMatcherSafely`
(`grype/vulnerability_matcher.go`), which wraps individual matcher execution. Distro
construction happens **before** matching, during package/context assembly, so this recover
never applies. The panic propagates to the top of the goroutine and terminates the process.

## 4. Reachability (call chain)

```
scanned artifact (dir:/image with /etc/os-release, or sbom: with a "distro" block)
    │  grype/pkg/{syft_provider,syft_sbom_provider}.go -> distroFromSBOM
    ▼
distro.FromRelease(release)  ->  distro.NewFromRelease(release, DefaultFixChannels())
    │
    │  (a) version selection loop validates each candidate as semver:
    │      for _, ver := range []string{release.VersionID, release.Version} {
    │          if ver == "" { continue }
    │          selectedVersionObj = version.New(ver, SemanticFormat)
    │          if selectedVersionObj.Validate() == nil { ... break }   // POISONS cache on failure
    │      }
    │      // both candidates fail -> selectedVersionObj carries a poisoned cache
    │
    ▼  (b) distro.New(...) then:
        d.Channels = applyChannels(release, selectedVersionObj, d.Channels, channels)
            │  the default RHEL "eus" channel (IDs=["rhel"], Versions=">= 8.0") matches:
            ▼
            channel.Versions.Satisfied(selectedVersionObj)
                ▼
                Version.Compare / Is  ->  getComparator returns cached {obj: nil}, nil err
                                      ->  semanticVersion.Compare  ->  nil deref  ->  PANIC
```

Notes:

- `TypeFromRelease` must return a non-empty, channel-matching type. The **default** fix
  channels ship exactly one such channel: `rhel` (`DefaultFixChannels()` in
  `grype/distro/fix_channel.go`), so `ID=rhel` reaches the vulnerable comparison with no
  special configuration.
- The trigger needs a **non-empty** version that fails to parse as semver
  (`hashicorp/go-version`), so both the `VersionID` and `Version` candidates fail and
  `selectedVersionObj` remains the poisoned object. Empty strings are skipped by the loop
  and do not reach the comparison.

| `ID`   | `VERSION_ID` / `VERSION` | outcome |
|--------|--------------------------|---------|
| `rhel` | `test`                   | panic   |
| `rhel` | `v`                      | panic   |
| `rhel` | `abc` / `x`              | panic   |
| `rhel` | `8.10`                   | ok (valid semver) |
| `alpine` | `test`                 | ok (no matching fix channel → no version comparison) |

## 5. Proof of concept

### 5a. SBOM input

A syft-JSON SBOM whose `distro` block marks the artifact as RHEL with an unparseable
version:

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
$ grype sbom:./poc.json     # also: grype ./poc.json, or piped on stdin
panic: runtime error: invalid memory address or nil pointer dereference
  ... github.com/anchore/go-version.(*Version).Compare(0x0, ...)
  ... grype/version.semanticVersion.Compare(...)
  ... grype/version.Version.Compare(...)
  ... grype/distro.applyChannels(...)
  ... grype/distro.NewFromRelease(...)
```

### 5b. Directory / image scan

```
# ./malicious/etc/os-release
ID=rhel
VERSION_ID=test
```

```console
$ grype dir:./malicious
panic: runtime error: invalid memory address or nil pointer dereference
```

The same `/etc/os-release` embedded in a container image crashes an image scan.

### 5c. Isolated reproduction of the exact defect

```go
v := version.New("", version.SemanticFormat)
_ = v.Validate()                                   // fails, poisons the cache
_, err := v.getComparator(version.SemanticFormat)  // returns err == nil (bug)
_, _ = v.Compare(version.New("1.0.0", version.SemanticFormat)) // PANIC: nil deref
```

## 6. Fix

Do not cache a comparator whose construction failed; return the error instead. This keeps
the cache-hit path (which reports a `nil` error) from ever handing back a zero-value
comparator.

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
 }
```

With the fix, a failed parse is never cached, so every subsequent call re-attempts the
parse and consistently returns the error; `Compare`/`Is`/`Satisfied` receive that error and
handle it gracefully instead of dereferencing a nil value.

Regression tests added:

- `grype/version/version_test.go`:
  `Test_getComparator_doesNotCacheFailures` (unit-level: the poison→use sequence returns an
  error and does not panic) and `Test_Compare_afterValidate_unparseable` (sweeps every
  format).
- `grype/distro/distro_test.go`:
  `Test_NewFromRelease_unparseableVersionWithFixChannelNoPanic` (end-to-end via the default
  RHEL fix channel).

## 7. Severity

Denial of service. The dereference is a nil-pointer **read** that the Go runtime turns into
a safe panic rather than a controllable memory write, so this bug does not by itself lead to
memory corruption or remote code execution. Its value to an attacker is reliably terminating
`grype` — relevant where `grype` runs unattended over untrusted artifacts (CI pipelines,
registry/SBOM ingestion, scanning services), where a crash can break a gate or a batch job.

## 8. Notes for future rounds

- The version-comparator cache is shared machinery used by every matcher. Although the
  matcher phase is `recover()`-protected, the same poisoning could produce confusing
  "successful comparison against a nil version" behaviour elsewhere; the fix removes that
  class of surprise entirely, not only the distro crash.
- A broad sweep (native Go fuzzing) of every `version.*` format constructor plus
  `Compare`/`Validate` did not surface additional panics once failed comparators are no
  longer cached. The syft format decoders (`format.Decode`), `packageurl-go`,
  `cpe.New`/nvdtools `wfn`, and the SPDX/CycloneDX → syft-model conversions were also fuzzed
  and hand-audited without finding a further pre-match crash; JSON and XML nesting are
  depth-capped by the standard library (`encoding/json` and `encoding/xml` both return an
  "exceeded max depth" error rather than overflowing the stack).
