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
  Before releasing peers, the engine reconciles their IPs from the captured
  original IPs and only the transitions whose bytes were actually written.
  Failed reconciliation retains the suspended owners and blocks new mutations.
- Preserve the owner, original-call pointers and callback context after failure.
  Retry cleanup explicitly. Partial block retirement is shutdown-only.
- Disable, stop admitting new original calls, drain callback users, and only
  then remove/uninitialize. Conservative peer-range checks complement this
  protocol; they do not replace callback/module lifetime management.
  Keep that admission closed across the retirement scan, peer resumption and
  subsequent runtime-table/storage release. Runtime registry operations run
  outside owned suspension windows to avoid freezing a registry-lock holder.
- Never call a trampoline after the hook/engine successfully retires it.

## Remaining engineering boundaries

1. Enumeration is a bounded peer observation. A second scan after suspension
   refuses any observed live peer not covered by the owned suspended set.
   A thread may still be born after that final observation; there is no universal
   thread-birth barrier. The caller must coordinate creation/admission for a
   stronger guarantee. Upstream PR #151's loader-lock and fixed PEB-offset
   proposal is not imported.
2. Multi-hook writes remain sequential, with a committed prefix on failure.
   Peer repair follows physical state, not queued intent; it does not roll back
   all target bytes or create an all-or-nothing hardware transaction.
3. Readable code snapshots do not authorize arbitrary concurrent unmapping or
   foreign patching. The consumer must control those lifetimes.
4. The decoder and relocated instruction forms are finite. The #363 changes
   improve specific RIP/EIP/VEX/relative cases, not all future ISA encodings.
   A relocated RIP-relative load or store of the five-byte hook patch is
   refused; LEA and accesses outside that window are unchanged. Copied
   REX2/APX forms are refused: recognizing their lengths does not provide
   a complete engine register/unwind/mitigation contract. No APX execution is
   implied by decoder or refusal tests. CALL-next address-discovery idioms are
   also refused before publication. More generally, a relocated CALL changes
   the return address observed by its callee; arbitrary return-address
   introspection is outside this engine's semantic-preservation contract.
5. Supported version-1 x64 prefixes receive owned version-2 unwind metadata
   on Windows 10 and later. Older/unknown systems retain refusal when generated
   nonleaf metadata is needed. An explicit empty epilogue set and synthetic
   prologue covering the jump-back avoid false tail-epilogue interpretation.
   Handler-bearing bodies outside the original prologue,
   chained/unknown source formats, nonleaf interior entries and undescribed
   body stack/frame changes remain unsupported. Unregistered source code must
   already satisfy the Windows leaf-unwind contract; invalid custom metadata
   is not repaired. See UNWIND.md for the exact subset and lifecycle.
6. Stack/register scans cover every byte of allocated code/metadata slots,
   excluding free slots and allocator bookkeeping. Stale values that match an
   occupied slot can still conservatively defer cleanup. Stack storage is scanned
   at every byte offset using complete pointer-width windows, with overlap across
   reads and adjacent readable regions of the same allocation. The scan budget
   remains 64 MiB; short/failed reads and inaccessible regions reject retirement.
7. Actual arbitrary host/game unload acceptance remains independent of controlled
   peer and leaf-call tests. DLL module leases and application quiescence remain
   the consumer's responsibility.

Do not remove checks or accept unrelated crashes/timeouts to make a test green.

The audit cases and exact scope are described in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
