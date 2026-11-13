# Changelog

VERSION is the canonical distribution version. This history groups changes
by their resulting behavior and links the implementing pull requests.

## [1.0.1]

### Added

- Independent Windows x86/x64 library identity: MithrilHook.h, the MTH_* API,
  MithrilHook::mithrilhook CMake target and mithrilhook DLL. There are thirteen
  public exports and no legacy compatibility aliases.
- Strict peer preparation with owned handles, context validation, retryable
  completion/cleanup and generated-code retirement checks. The core includes
  the separately authorized SAFE-FREEZE work and the Citrine #362/#363 fixes.
- Bounded generated version-2 x64 unwind metadata for supported registered
  source prologues, with registry and storage ownership retained through
  failures. Registry operations run outside owned peer-suspension windows.
- A comparison of eight hook engines over 38 workloads and five Windows,
  architecture and compiler environments. Immutable inputs, raw samples,
  negative controls, binary receipts and recomputed statistics are retained.
- Independent installed-package consumers across static/shared, Debug/Release,
  MSVC/clang-cl and x64/Win32 builds, with actual hook/original/retirement calls.
- A canonical VERSION file and consistent 1.0.1 CMake/package/DLL metadata,
  release resource flags and versioned validation artifacts.

### Fixed

- Correct single-disable peer IP mapping, repair peer IPs against physically
  committed writes after partial failures, and retain failed cleanup owners.
  Observe late peers after suspension; the final observation window remains
  a documented host-coordination boundary. ([#1], [#3])
- Check signed RIP displacement range, EIP wrapping, VEX/relative forms and
  bounded instruction/padding reads. Use alignment-safe decoder accesses and
  refuse same-thread recursive mutations. ([#1])
- Register and retain supported nonleaf x64 trampoline metadata through cache,
  registry and storage failures; cover the complete jump-back. ([#4])
- Refuse ambiguous 66-prefixed near branches. Normalize byte-register aliases
  before protected stack/frame checks, retaining valid unrelated writes. ([#9])
- Refuse CALL-next address-discovery idioms and unsupported copied REX2/APX
  forms before publication; keep ordinary supported CALL behavior. ([#12])
- Resolve internal JMP/Jcc/LOOP targets through the completed instruction map,
  including backward branches after expansion; refuse unmapped boundaries.
  Preserve conservative forward-span growth refusals. ([#14])
- Refuse RIP-relative accesses overlapping the hook patch. Require proven
  access ranges, account for 512-byte FXSAVE/FXRSTOR operands, and refuse
  unmodeled indexed/segment/vector forms. LEA remains address-only. ([#15])
- Reserve complete normal/hotpatch write intervals even while disabled.
  Refuse intersecting owners while preserving adjacent and disjoint alternate
  hotpatch placements. ([#16])
- Apply effective REX.W precedence over 66 when calculating PUSH memory width.
  Cover prefix orders, both patch boundaries and genuine Windows generated
  unwind/publication/retirement behavior. ([#17])
- Refuse copied relative CALL destinations inside the five-byte entry patch
  before original publication, including valid instruction boundaries. Keep
  ordinary outside CALL execution, generated unwind and retirement. ([#18])
- Refuse copied x87 operations whose relocated instruction pointer can escape
  through FNSTENV/FSTENV, FNSAVE/FSAVE or a later state save. Keep fixed-size
  FXSAVE/FXRSTOR without copied x87 producers and bodies outside the copied
  prefix. Refuse unproven extended-state layouts before publication. ([#19])

### Packaging and compatibility

- The installed package exposes version 1.0.1 without a prerelease suffix.
  Numeric requests, including exact 1.0.1, work without prerelease opt-in.
  CMake and Windows fixed metadata use 1.0.1; DLL prerelease flags are clear.
  Static/shared consumers retain their matching MSVC runtime configuration.
- Distribution remains GPL-3.0-only. Original MinHook/HDE BSD notices and the
  separately authorized SAFE-FREEZE notice remain intact; these are not three
  alternative licenses for the full fork. Branding and the approved logo are
  preserved. ([#2])
- Supported instruction and unwind forms are finite. Generated nonleaf metadata
  requires Windows 10 or later; unknown/chained formats and untranslated
  handler-bearing bodies remain refused. Multi-hook writes remain sequential.

### Validation and release boundary

Exact revisions, configurations and completed runs are recorded in
[Validation](docs/VALIDATION.md), [Benchmarks](docs/BENCHMARKS.md) and the
current PR [#19]. Earlier results keep their original source identities.
Library publication is owner-controlled after the selected source's correctness,
package, performance and source/license review. Citrine integration and actual
application/game lifecycle acceptance are the following engineering phase.

## Development history before the first release

The earlier 0.1.0 and 1.0.0-rc.1 identifiers represented development work,
not prior stable releases. The initial independent core, branding, thread/batch
review, generated unwind support and evidence audit were developed in PRs
[#1], [#2], [#3], [#4] and [#5]. Benchmark/package infrastructure was merged in
[#6]; subsequent reviewed corrections are grouped above by resulting behavior.
Report-only review PRs are not counted as additional software releases.

[#1]: https://github.com/raleonys/mithrilhook/pull/1
[#2]: https://github.com/raleonys/mithrilhook/pull/2
[#3]: https://github.com/raleonys/mithrilhook/pull/3
[#4]: https://github.com/raleonys/mithrilhook/pull/4
[#5]: https://github.com/raleonys/mithrilhook/pull/5
[#6]: https://github.com/raleonys/mithrilhook/pull/6
[#9]: https://github.com/raleonys/mithrilhook/pull/9
[#12]: https://github.com/raleonys/mithrilhook/pull/12
[#14]: https://github.com/raleonys/mithrilhook/pull/14
[#15]: https://github.com/raleonys/mithrilhook/pull/15
[#16]: https://github.com/raleonys/mithrilhook/pull/16
[#17]: https://github.com/raleonys/mithrilhook/pull/17
[#18]: https://github.com/raleonys/mithrilhook/pull/18
[#19]: https://github.com/raleonys/mithrilhook/pull/19
