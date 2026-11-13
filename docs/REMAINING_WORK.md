# Remaining work and acceptance status

A library stable release may precede Citrine integration: validate and version
the independent library, integrate that fixed version, then validate the actual
application. A release candidate can be used for early integration feedback.
No tag or release is created without owner direction.

The scoped core changes F01–F19 are implemented and merged through PR #4.
The exact native result and source revision are recorded in
[Validation](VALIDATION.md). There is no published stable release. Repository
issues are disabled; an empty open-issue/PR list does not close the work below.

## Open acceptance work

| Item | Current evidence | Completion criterion |
| --- | --- | --- |
| Comparative hook-engine performance | NOT MEASURED; no retained paired timing suite/results | Implement the separate adapters and correctness gates in [Benchmarks](BENCHMARKS.md), then retain identified native raw results and analysis for the selected baselines. |
| Citrine integration | The core is independent; the application still uses its existing adapter/vendor input | Integrate the MTH API/package deliberately, preserve closed original-call admission and module ownership through failures, and validate every actual target on the identified host. |
| Application/game lifecycle acceptance | Controlled engine fixtures and eleven create/remove targets pass; actual Windows API hooks are not enabled by that probe | Observe named-host startup, live detour/original behavior, partial-failure recovery, shutdown and DLL unload with callbacks drained and all owners retired. |
| Deployment Windows/CPU matrix | Native CI is Windows Server 2022 x64/Win32; generated nonleaf metadata requires Windows 10 or later | Record the supported deployment builds/CPUs and execute the relevant compatibility, unwind and lifecycle cases there. Version-sensitive API prologues must be rechecked. |
| First stable release | CMake version 0.1.0; no published release/tag | After the independent library correctness, benchmark and package-consumption gates, the owner reviews supported platforms, notices, changelog and evidence and chooses a stable tag/release. Citrine then integrates that immutable version; its game/lifecycle acceptance remains a separate application gate. |

Related application issues remain owned by Citrine. In particular,
[native acceptance #20](https://github.com/raleonys/citrine-eclipse-mirage/issues/20),
[connect error-path #22](https://github.com/raleonys/citrine-eclipse-mirage/issues/22)
and [Registry provenance/coverage #109](https://github.com/raleonys/citrine-eclipse-mirage/issues/109)
are not automatically closed by MithrilHook's core tests. Review their own
acceptance criteria during integration; this document does not change them.

## Documented scope boundaries

These are explicit contracts or optional future extensions, not hidden claims
that the existing tests already prove them:

- A final thread-observation-to-write/release window remains. Stronger birth or
  admission coordination requires cooperation from the host; the core does not
  provide a universal process-wide barrier.
- Multi-hook writes are sequential. A partial failure records the committed
  prefix and repairs peer IPs; whole-batch byte rollback is not promised.
- X64 source metadata/instruction support is bounded. Source chains, arbitrary
  language-handler body translation, interior nonleaf entries and undescribed
  stack/frame changes remain unsupported. Older/unknown Windows versions refuse
  prefixes that require generated nonleaf metadata. See [Unwind](UNWIND.md).
- Code/module mapping, a single coordinated patch owner, loader-lock avoidance,
  callback drain and trampoline lifetime remain consumer obligations. Bounded
  stack scans can conservatively defer retirement.

The unimported upstream proposals in `metadata/FIXES.json` remain deliberate
review decisions. #151's loader-lock/fixed-PEB-offset approach is excluded;
#175 has no demonstrated truncation within the bounded instruction count;
#176 still needs process-handle/error-ownership review before adoption. Their
existence does not establish an outstanding confirmed defect in this core.

Use this distinction when describing completion: the implemented core scope has
passed its recorded gates; comparative performance, deployment/application
acceptance and release publication remain open.
