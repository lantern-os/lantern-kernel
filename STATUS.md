# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); first prototype code merged (capability/IPC core; no boot integration yet).

## Done
- Kernel scope fixed to five responsibilities ([RFC-0002](../lantern-rfcs/rfcs/0002-microkernel-architecture.md), Accepted; see [ADR-0004](../lantern-rfcs/adr/0004-kernel-responsibilities-and-tcb-boundary.md)).
- Object model sketched and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)); fixed a "TCB" (Trusted Computing Base vs. thread control block) terminology collision during review.
- Component threat model drafted and reviewed ([THREAT_MODEL.md](./THREAT_MODEL.md)).
- Syscall/IPC ABI and Phase 1 scheduling-context model accepted
  ([RFC-0005](../lantern-rfcs/rfcs/0005-syscall-ipc-abi-and-phase1-scheduling.md); see
  [ADR-0008](../lantern-rfcs/adr/0008-kernel-syscall-ipc-abi.md) and
  [ADR-0009](../lantern-rfcs/adr/0009-phase1-scheduling-context-model.md)).
- Concurrency model accepted ([RFC-0006](../lantern-rfcs/rfcs/0006-kernel-concurrency-model.md);
  see [ADR-0010](../lantern-rfcs/adr/0010-kernel-concurrency-model.md)): single-stack,
  run-to-completion kernel, one kernel stack per hart, seL4-style — resolves the last
  open question from RFC-0002/ADR-0004.
- **First prototype code merged** (`src/`): capability/rights model and Phase 1 flat CSpace
  (`cap`), the kernel object model — Untyped/CNode/TCB/Endpoint/Notification/
  SchedulingContext (`object`) — a fixed-size TCB pool with a real round-robin scheduler
  (`state`/`scheduler`), and the full IPC fast path: `Send`/`NBSend`/`Recv`/`Call`/`Reply`
  on endpoints and `Signal`/`Wait`/`Poll` on notifications (`ipc`), all with real
  synchronous-rendezvous logic, not stubs. `CNodeInvoke`'s `Mint`/`Copy`/`Move`/`Delete`
  (`cnode`) enforce monotone attenuation for real. Context switching needed no new
  `lantern-hal` primitive: it's implemented as swapping which thread's saved registers
  occupy the one `TrapFrame` before returning, a direct consequence of ADR-0010.
  28 unit tests pass (including a full `Call`→`Recv`→`Reply` round trip driven through
  `dispatch`), `cargo clippy -D warnings` clean on host and
  `riscv64gc-unknown-none-elf` (debug and release).
- Two ABI details ADR-0008 left to implementation are now fixed in code, documented in
  `src/abi.rs`: the invoked capability's CPtr is `mr0` (payload is `mr1..mr3`), and on
  delivery the receiver's `mr0` becomes the sender's endpoint badge. `CNodeInvoke`'s
  `label` values (`Mint`/`Copy`/`Move`/`Delete`/`Revoke`) are fixed in `src/cnode.rs`.

## Known Phase 1 gaps (documented in code, not silent)
- `UntypedRetype` carves objects from a count-based budget, not real physical memory —
  there's no memory map without `lantern-boot`.
- `TCBConfigure` cannot set a VSpace root — no HAL paging support yet
  ([`lantern-hal`](../lantern-hal)'s remaining surface).
- `Revoke` is cleanly refused (`IllegalOperation`), not implemented — needs a
  capability-derivation tree; `Delete` doesn't reclaim the underlying pooled object either
  (no refcounting yet).
- No idle thread: a blocking operation with no other ready thread refuses with an error
  (reusing `SyscallError::Timeout`, an imperfect semantic fit) rather than stranding the
  hart. Needs a boot-provided idle loop.
- VSpace/Frame/IRQ-handler objects don't exist yet (same HAL-paging/interrupt-controller
  dependency as `TCBConfigure`'s gap).
- **Not yet exercised under QEMU or any real hardware** — every test runs on the host
  against a freshly constructed `KernelState`; nothing has driven this through an actual
  trap yet.

## Next
- Exercise this through a real trap once `lantern-boot` exists enough to drive it.
- VSpace/Frame objects, once `lantern-hal` has paging support.
- The capability-derivation tree `Revoke`/proper `Delete` reclaim need.
- An idle thread, once `lantern-boot` can provide one.

## Blocked on
- Nothing for further in-kernel work (CSpace/object-model/IPC refinement, VSpace object
  shape) — but real end-to-end validation needs [`lantern-boot`](../lantern-boot)'s minimal
  loader (itself blocked on [`lantern-crypto`](../lantern-crypto)'s implementation, not just
  its now-ratified primitive set) and `lantern-hal` paging support.
