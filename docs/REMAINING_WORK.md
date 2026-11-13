# Remaining work and acceptance status

A library stable release may precede Citrine integration: validate and version
the independent library, integrate that fixed version, then validate the actual
application. A release candidate can be used for early integration feedback.
No tag or release is created without owner direction.

The scoped core changes F01–F19 are implemented and merged through PR #4.
Review findings #7/#8 require runtime changes, not just their documentation:
F20/F21 are implemented in PR #9 and passed 153 native executions at its recorded
head. They remain a stable-release blocker until owner review/merge. The
benchmark candidate includes those same corrected runtime bytes.
The exact native result and source revision are recorded in
[Validation](VALIDATION.md). There is no published stable release. Repository
issues are disabled; an empty open-issue/PR list does not close the work below.

## Open acceptance work

| Item | Current evidence | Completion criterion |
| --- | --- | --- |
| Comparative hook-engine performance | The eight-engine native suite covers 38 workloads, five environments, seven paired rounds and source/unwind probes | Review the exact-head raw artifacts and recomputed comparisons in [Benchmarks](BENCHMARKS.md); preserve semantic/retirement differences and deployment gaps when selecting release scope. |
| Citrine integration | The core is independent; the application still uses its existing adapter/vendor input | Integrate the MTH API/package deliberately, preserve closed original-call admission and module ownership through failures, and validate every actual target on the identified host. |
| Application/game lifecycle acceptance | Controlled engine fixtures and eleven create/remove targets pass; actual Windows API hooks are not enabled by that probe | Observe named-host startup, live detour/original behavior, partial-failure recovery, shutdown and DLL unload with callbacks drained and all owners retired. |
| Deployment Windows/CPU matrix | Library correctness runs on Windows Server 2022; benchmark/source-form/API observations also cover Server 2025. Generated nonleaf metadata requires Windows 10 or later | Record the supported deployment builds/CPUs and execute the relevant compatibility, unwind and lifecycle cases there. Version-sensitive API prologues must be rechecked. |
| First stable release | CMake version 0.1.0; no published release/tag; installed-consumer coverage added to every native cell | After the independent library correctness, benchmark and installed-consumer gates, the owner reviews supported platforms, notices, changelog and evidence and chooses a stable tag/release. Citrine then integrates that immutable version; its game/lifecycle acceptance remains a separate application gate. |

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

Use this distinction when describing completion: each implemented core revision has
its own recorded gates; confirmed review findings still require reviewed fixes; comparative performance, deployment/application
acceptance and release publication remain open.
