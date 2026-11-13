# Release and integration status

The unpublished release candidate is 1.0.0-rc.1. Confirmed reports through
PR #17 have merged runtime corrections. PR #18 addresses a subsequent confirmed
internal-CALL failure by refusing overwritten callee destinations before
publication. Release publication is blocked until that correction and its
exact-head native/negative-control checks are reviewed. Earlier #17 benchmark
and package evidence stays pinned to its original source, not these new bytes.

## Library release gates

| Gate | Evidence / completion criterion |
| --- | --- |
| Correctness and publication | Candidate portable sanitizers and all seven native configurations pass, including genuine PUSH source/generated unwind, overlap reservation, cleanup and exact negative controls. See [Validation](VALIDATION.md). |
| Installed package and DLL identity | All seven fresh consumers link/run with matching CRT settings; candidate version consent and DLL numeric/full/prerelease metadata match VERSION. |
| Comparative performance | Review the candidate's exact-head five-environment run, raw recipe/checksums, source/binary identities and recomputed results. Earlier #12 measurements remain historical. See [Benchmarks](BENCHMARKS.md). |
| Release content | Review the changelog, documented support/refusal scope, GPL/BSD provenance and versioned validation artifacts. VERSION and package/resource metadata must agree. |
| Publication | The owner selects the immutable release commit, tag and assets after reviewing these gates. A release candidate is not a published stable 1.0.0. See [Release preparation](RELEASE.md). |

## Next engineering phase: Citrine integration

Library publication can precede integration. Citrine still uses its existing
adapter/vendor input. Integrate the selected immutable MithrilHook package/API,
then validate actual application behavior without transferring hosted fixture
results into a game-acceptance claim.

- Preserve closed original-call admission, callback draining and module/code
  ownership through partial failures and teardown.
- Recheck all actual target prologues on the identified deployment Windows/CPU
  and verify startup, detour/original behavior and recovery paths.
- Complete shutdown/DLL unload with every callback drained and all native owners
  retired. This is application acceptance, not a prerequisite for writing an
  independently versioned library candidate.

Citrine [native acceptance #20](https://github.com/raleonys/citrine-eclipse-mirage/issues/20),
[connect error-path #22](https://github.com/raleonys/citrine-eclipse-mirage/issues/22)
and [Registry coverage #109](https://github.com/raleonys/citrine-eclipse-mirage/issues/109)
retain their own acceptance criteria. This library work does not close them.

## Documented engineering boundaries

A final observation-to-write/release thread-birth window requires host
coordination. Multi-hook writes are sequential, with physical progress and
retryable repair retained. Unwind/ISA support is finite; chained/unknown source
formats, untranslated handler-bearing bodies, interior nonleaf entries and
undescribed stack/frame changes remain refused. Generated nonleaf metadata
requires Windows 10 or later. Mapping lifetime, loader-lock avoidance, original
admission and callback drain remain consumer obligations.

Optional work includes broader decoding/unwind support, richer allocation
observability and reduced multi-hook retirement cost. These are not all release
blockers or evidence of a confirmed current failure. Detailed review of every
nonofficial MinHook fork is not complete; targeted research does not certify the
entire fork network. The excluded proposals in metadata/FIXES.json retain their
recorded reasons and are not automatically imported.
