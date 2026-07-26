# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); first prototype code merged and validated running under real QEMU via `lantern-boot`.

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

## Validated under real QEMU
[`lantern-boot`](../lantern-boot)'s two-thread demo drives a full `Call`→`Recv`→`Reply`
round trip through real `riscv64` traps under `qemu-system-riscv64`, cold-starting the
first thread via the new `lantern_hal::enter_first_thread`/`Hal::enter_thread` primitives
and switching to the second via the normal trap-return path. This is the first time any
of this crate's logic ran through `lantern-hal`'s actual trap-entry assembly rather than a
unit test's fabricated `TrapFrame` — and it caught a real bug in that assembly (see
`lantern-hal/STATUS.md`): the `riscv64` trampoline only ever wrote back `mr0..mr3`/the tag
to real registers, silently discarding every context switch. Fixed there, not here — this
crate's own logic (already covered by the `full_call_recv_reply_round_trip` unit test)
needed no changes.

## Known Phase 1 gaps (documented in code, not silent)
- `UntypedRetype` carves objects from a count-based budget, not real physical memory —
  `lantern-boot` doesn't parse the DTB memory map yet.
- `TCBConfigure` cannot set a VSpace root — no HAL paging support yet
  ([`lantern-hal`](../lantern-hal)'s remaining surface). The QEMU demo's two threads run
  in the kernel's own address space at kernel privilege — no real isolation yet.
- `Revoke` is cleanly refused (`IllegalOperation`), not implemented — needs a
  capability-derivation tree; `Delete` doesn't reclaim the underlying pooled object either
  (no refcounting yet).
- No idle thread: a blocking operation with no other ready thread refuses with an error
  (reusing `SyscallError::Timeout`, an imperfect semantic fit) rather than stranding the
  hart. The QEMU demo sidesteps this by construction (always ≥1 ready thread when either
  blocks) rather than by fixing it.
- VSpace/Frame/IRQ-handler objects don't exist yet (same HAL-paging/interrupt-controller
  dependency as `TCBConfigure`'s gap).

## Next
- VSpace/Frame objects, once `lantern-hal` has paging support — needed for actual
  confinement, not just the IPC mechanism the QEMU demo already proves.
- The capability-derivation tree `Revoke`/proper `Delete` reclaim need.
- An idle thread, once `lantern-boot` can provide one.
- `x86-64`: exercise this crate's logic there too, once `x86-64` boot work starts
  (deferred, see `lantern-boot/STATUS.md`) — `Hal::enter_thread` is still an
  `unimplemented!()` stub on that target.

## Blocked on
- Nothing for further in-kernel work (CSpace/object-model/IPC refinement, VSpace object
  shape) — the IPC core is now validated end-to-end on `riscv64`. Real confinement
  (the "**confined** hello service" RFC-0004 calls for, vs. the mechanism-only demo running
  today) needs `lantern-hal` paging support.
