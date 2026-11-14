# Release and integration status

**Library version: 1.0.4.** The official release incorporates all reviewed
corrections through PR #23: strict ownership, peer/batch repair, bounded generated
unwind, relocation refusals, occupied-slot tracking and complete byte-window
stack scanning. The owner authorized tag/release publication after the final
source/package/evidence checks. Earlier prepared versions were not published.
[Release assets](https://github.com/raleonys/mithrilhook/releases/tag/v1.0.4)
retain the selected source and validation identities. Citrine integration is
the next independent engineering phase.

## Library release gates

| Gate | Evidence / completion criterion |
| --- | --- |
| Correctness and publication | Current-source portable sanitizers and all seven native configurations pass, including genuine PUSH source/generated unwind, overlap reservation, cleanup and exact negative controls. See [Validation](VALIDATION.md). |
| Installed package and DLL identity | All seven fresh consumers link/run with matching CRT settings; stable numeric version compatibility and DLL numeric/full/prerelease metadata match VERSION. |
| Comparative performance | Review the selected source's exact-head five-environment run, raw recipe/checksums, source/binary identities and recomputed results. Earlier #12 measurements remain historical. See [Benchmarks](BENCHMARKS.md). |
| Release content | Review the changelog, documented support/refusal scope, GPL/BSD provenance and versioned validation artifacts. VERSION and package/resource metadata must agree. |
| Publication | The authorized v1.0.4 release pins the selected commit, packages, raw evidence and checksums. See [Release and packages](RELEASE.md). |

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
  independently versioned library.

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
