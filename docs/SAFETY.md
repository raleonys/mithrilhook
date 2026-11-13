# Safety and ownership

MithrilHook refuses unresolved native preparation/completion/retirement rather
than discarding the owner and reporting success. This favors preservation of
code and resource ownership. A persistent OS failure can leave peers suspended,
resources retained, or shutdown pending; availability is not guaranteed under
an unrecoverable failure.

## Consumer obligations

- Keep target code and callbacks mapped, with a single coordinated patch owner.
- Invoke initialization, mutation and teardown outside DllMain/loader lock.
- Serialize higher-level lifetime decisions. Do not recursively operate on the
  engine from a callback entered during its operation. Same-thread entry is
  refused; arbitrary cross-thread host-lock inversion is not solved.
- Queue a batch and apply once when appropriate. A batch still writes targets
  sequentially. A later error can leave an earlier target transitioned.
- Preserve the owner, original-call pointers and callback context after failure.
  Retry cleanup explicitly. Partial block retirement is shutdown-only.
- Disable, stop admitting new original calls, drain callback users, and only
  then remove/uninitialize. Conservative peer-range checks complement this
  protocol; they do not replace callback/module lifetime management.
- Never call a trampoline after the hook/engine successfully retires it.

## Remaining engineering boundaries

1. Enumeration is a bounded peer observation. A new thread may be born after
   it; there is no universal thread-birth barrier. Upstream PR #151's loader-lock
   and fixed PEB-offset proposal is not imported.
2. Context relocation and multi-hook writes are not an all-or-nothing hardware
   transaction or a complete rollback journal for every peer.
3. Readable code snapshots do not authorize arbitrary concurrent unmapping or
   foreign patching. The consumer must control those lifetimes.
4. The decoder and relocated instruction forms are finite. The #363 changes
   improve specific RIP/EIP/VEX/relative cases, not all future ISA encodings.
5. x64 exception/unwind behavior for arbitrary relocated functions is not
   universally established. Unsupported cases require additional bounded
   reproductions and native evidence before being advertised as supported.
6. Stack/register scans can find stale pointer values and conservatively defer
   cleanup. The scan budget is bounded; incomplete reads reject retirement.
7. Actual arbitrary host/game unload acceptance remains independent of controlled
   peer and leaf-call tests. DLL module leases and application quiescence remain
   the consumer's responsibility.

Do not remove checks or accept unrelated crashes/timeouts to make a test green.
