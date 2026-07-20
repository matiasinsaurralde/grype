# Security finding: process-crashing panic in distro version parsing

- **Component:** `grype/distro` (distro construction during artifact parsing)
- **Class:** CWE-125 out-of-bounds read → uncaught `panic` → CWE-248 uncaught exception (Denial of Service)
- **Impact:** A single crafted artifact reliably crashes the entire `grype` process
  before any matching happens.
- **Attacker input:** fully attacker-controlled (`/etc/os-release` in a scanned
  directory/image, or the `distro` block of an input SBOM).
- **Status:** fixed in this branch (one-line guard + regression tests).

---

## 1. Summary

`grype` crashes with an unrecoverable `runtime error: index out of range [0] with
length 0` when it parses an artifact whose distro version string consists solely of
the `v` prefix (for example `v`, or `v+<channel>` whose core reduces to empty).

The panic occurs in the **pre-match parsing phase**, which — unlike the matcher
phase — is not protected by any `recover()`. The result is a hard crash of the whole
process: a denial-of-service triggerable by anyone who can influence the artifact a
victim scans (a container image, a directory, or an SBOM file).

## 2. Root cause

`grype/distro/distro.go`, function `parseVersion`:

```go
func parseVersion(version string) (major, minor, remaining, versionWithoutSuffix string, channels []string) {
	if version == "" {
		return "", "", "", "", nil
	}

	versionWithoutSuffix = version
	var channelStr string
	if strings.Contains(version, "+") {
		vParts := strings.SplitN(version, "+", 2)
		version = vParts[0]          // "v+eus" -> version = "v"
		versionWithoutSuffix = version
		channelStr = vParts[1]
	}

	version = strings.TrimPrefix(version, "v")   // "v" -> ""

	// if starts with a digit, then assume it's a version ...
	if version[0] >= '0' && version[0] <= '9' {  // <-- panics: version is ""
		...
	}
	...
}
```

The function guards the empty-string case **on entry**, but then mutates `version`
twice:

1. the `+` split can reduce `version` to just `"v"` (e.g. `"v+eus"` → `"v"`), and
2. `strings.TrimPrefix(version, "v")` then turns `"v"` into `""`.

After those transformations `version` can be empty again, yet `version[0]` is
indexed with no re-check. Indexing byte `0` of an empty string is an out-of-bounds
read, which Go converts into a runtime panic.

Trigger inputs (the `v` prefix is only stripped when lowercase):

| input        | after `+` split | after `TrimPrefix("v")` | result |
|--------------|-----------------|-------------------------|--------|
| `"v"`        | `"v"`           | `""`                    | panic  |
| `"v+eus"`    | `"v"`           | `""`                    | panic  |
| `"v+1"`      | `"v"`           | `""`                    | panic  |
| `"V"`        | `"V"`           | `"V"` (not trimmed)     | no panic |
| `"1.2.3"`    | `"1.2.3"`       | `"1.2.3"`               | no panic |

## 3. Why it crashes the whole process

`grype` has exactly **one** `recover()` in its entire tree, in `callMatcherSafely`
(`grype/vulnerability_matcher.go`), which wraps individual matcher execution:

```go
func callMatcherSafely(m match.Matcher, vp vulnerability.Provider, p pkg.Package) (... err error) {
	defer func() {
		if e := recover(); e != nil {
			err = match.NewFatalError(m.Type(), fmt.Errorf("%v at:\n%s", e, string(debug.Stack())))
		}
	}()
	return m.Match(vp, p)
}
```

Distro construction happens **before** matching, during package/context assembly, so
this recover never applies. The panic propagates to the top of the goroutine and
terminates the process.

## 4. Reachability (call chain)

```
scanned artifact
    │
    ├─ dir:/image scan ──► syft catalogs /etc/os-release ──► linux.Release{ID, VersionID, Version}
    │        grype/pkg/syft_provider.go:54   distroFromSBOM ─► distro.FromRelease
    │
    └─ sbom: input     ──► syft-JSON "distro" block        ──► linux.Release{ID, VersionID, Version}
             grype/pkg/syft_sbom_provider.go:39   distroFromSBOM ─► distro.FromRelease
                                                              │
                                                              ▼
                                     distro.NewFromRelease(release, channels)
                                                              │
             selects a version from [VersionID, Version]; each is tried as semver,
             and if none validates it FALLS BACK to release.VersionID:
                                                              │
                for _, ver := range []string{release.VersionID, release.Version} {
                    if ver == "" { continue }
                    if version.New(ver, SemanticFormat).Validate() == nil { selectedVersion = ver; break }
                }
                if selectedVersion == "" { selectedVersion = release.VersionID }   // "v"
                                                              │
                                                              ▼
                             distro.New(t, "v", codename, idLikes...)
                                                              │
                                                              ▼
                                        parseVersion("v")  ──►  PANIC
```

Notes:

- `TypeFromRelease` must return a non-empty type, so `ID` (or `ID_LIKE`/`NAME`) must
  be a recognized distro such as `alpine`, `ubuntu`, `debian`, `rhel`, etc.
- `version.New("v", SemanticFormat).Validate()` fails (hashicorp go-version requires
  a numeric core), so `"v"` never validates as semver and the fallback assigns it to
  `selectedVersion` regardless. The panic is therefore deterministic, not
  probabilistic.

## 5. Proof of concept

### 5a. Directory / image scan

Create a directory whose `/etc/os-release` marks it as a known distro with a
degenerate `VERSION_ID`:

```
# ./malicious/etc/os-release
ID=alpine
VERSION_ID=v
```

```console
$ grype dir:./malicious
panic: runtime error: index out of range [0] with length 0
  ... grype/distro.parseVersion(...)
  ... grype/distro.New(...)
  ... grype/distro.NewFromRelease(...)
```

The same `/etc/os-release` embedded in a container image crashes an image scan.

### 5b. SBOM input

A syft-JSON SBOM whose `distro` block has a recognized `id`, a `versionID` of `v`,
and no valid `version`:

```json
{
  "artifacts": [],
  "artifactRelationships": [],
  "source": { "type": "directory", "target": "." },
  "distro": { "id": "alpine", "versionID": "v" },
  "descriptor": { "name": "syft", "version": "1.0.0" },
  "schema": {
    "version": "16.0.0",
    "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.0.json"
  }
}
```

```console
$ grype sbom:./poc.json     # also: grype ./poc.json, or piped on stdin
panic: runtime error: index out of range [0] with length 0
```

### 5c. Isolated reproduction of the exact code

Because the two functions are self-contained, the panic can be reproduced with the
verbatim `parseVersion` body and the verbatim `NewFromRelease` selection logic:

```
id="alpine" versionID="v"   version=""  => selectedVersion="v"   => PANIC (process crash)
id="alpine" versionID="v+1" version=""  => selectedVersion="v+1" => PANIC (process crash)
id="alpine" versionID="3.19" version="" => selectedVersion="3.19" => ok
```

With the fix applied, all three cases complete without panicking.

## 6. Fix

Restore the length guard that must precede the byte index:

```diff
 	version = strings.TrimPrefix(version, "v")

 	// if starts with a digit, then assume it's a version and extract the major, minor, and remaining versions
-	if version[0] >= '0' && version[0] <= '9' {
+	if len(version) > 0 && version[0] >= '0' && version[0] <= '9' {
```

An empty core version now simply yields empty major/minor/remaining components (the
same behaviour as any other non-numeric version), and the distro is constructed
without crashing.

Regression tests added in `grype/distro/distro_test.go`:

- `Test_parseVersion_shortVersionNoPanic` — exercises `parseVersion` directly with
  `"v"`, `"V"`, `"v+eus"`, `"v+1"`, `"+"`, `""`.
- `Test_NewFromRelease_shortVersionIDNoPanic` — exercises the end-to-end
  `NewFromRelease` path with `VERSION_ID` values that reduce to empty.

## 7. Severity

Denial of service. The out-of-bounds access is a **read**, which the Go runtime
turns into a safe panic rather than a controllable memory write, so this specific
bug does not by itself lead to memory corruption or remote code execution. Its value
to an attacker is reliably terminating `grype` — relevant where `grype` runs
unattended over untrusted artifacts (CI pipelines, registry/SBOM ingestion, scanning
services), where a crash can break a gate or a batch job.
