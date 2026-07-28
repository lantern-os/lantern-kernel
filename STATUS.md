# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); RFC-0004's exit criterion (a confined "hello service" reachable only via a granted capability) is met, validated running under real QEMU via `lantern-boot`'s ELF loader.

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
- **VSpace/Frame capability objects and `FrameInvoke`** ([RFC-0008](../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
  [ADR-0012](../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md)) — the
  syscall table's 13th entry, resolving the "VSpace/Frame invocation label tables" RFC-0005
  explicitly deferred. `Frame` has an explicit size class (`FrameSize::Small`/`Mega`; `Mega`
  is what `lantern-boot` actually uses, exclusively, per `lantern-hal/STATUS.md`'s QEMU
  workaround). `Untyped` gained an *optional* real physical bump range
  (`Untyped::bump`/`with_memory`) — count-based budgeting (`remaining`) is unchanged and
  still governs every object type, but `VSpace`/`Frame*` retype additionally needs (and
  consumes) real memory, since unlike `CNode`/`Endpoint`/etc. they *name* physical pages
  rather than just occupying a kernel pool slot. `TCBConfigure` gained a fourth, optional
  argument (a VSpace capability) — retiring the direct `Tcb.address_space` field poke
  `lantern-boot`'s old demo used. 41 unit tests pass (13 new, including memory-backed-Untyped
  `Map`/`Unmap` tests that genuinely dereference real host buffers, the same technique
  `lantern-hal/riscv64_paging.rs`'s own tests use), `cargo clippy -D warnings` clean on host
  and `riscv64gc-unknown-none-elf`.

## Validated under real QEMU
[`lantern-boot`](../lantern-boot)'s loader (`src/loader.rs`, RFC-0008) drives a full
`Call`→`Recv`→`Reply` round trip through real `riscv64` traps under `qemu-system-riscv64`,
between two independently-built, separately-loaded programs, each running under its own
real VSpace built via this crate's real `admin::untyped_retype`/`frame::invoke` functions
— not a fabricated `TrapFrame`, and not (any more) a direct-field-poke shortcut either. This
is also where `lantern-hal`'s `riscv64` trap trampoline bug was originally caught (see
`lantern-hal/STATUS.md`): the trampoline only ever wrote back `mr0..mr3`/the tag to real
registers, silently discarding every context switch. Fixed there, not here — this crate's
own logic (covered by the `full_call_recv_reply_round_trip` unit test) needed no changes.

## Known Phase 1 gaps (documented in code, not silent)
- `Untyped`'s count-based budget (`remaining`) still isn't backed by a *general* physical
  memory map — `lantern-boot` doesn't parse the DTB yet. `VSpace`/`Frame*` retype now *does*
  consume real memory (see "Done" above), but from a single hardcoded range
  `lantern-boot/pmm.rs` seeds at boot, not real discovery.
- `Revoke` is cleanly refused (`IllegalOperation`), not implemented — needs a
  capability-derivation tree; `Delete` doesn't reclaim the underlying pooled object either
  (no refcounting yet).
- No idle thread: a blocking operation with no other ready thread refuses with an error
  (reusing `SyscallError::Timeout`, an imperfect semantic fit) rather than stranding the
  hart. The QEMU demo sidesteps this by construction (always ≥1 ready thread when either
  blocks) rather than by fixing it.
- IRQ-handler objects don't exist yet (interrupt-controller HAL support is a separate,
  unstarted dependency — `lantern-hal/STATUS.md`).
- `cnode::invoke`'s `Copy`/`Move` only operate on slots *within a single CNode* — there's no
  cross-CNode capability-transfer primitive yet, so `lantern-boot/loader.rs` still places
  the one capability each loaded program needs (the shared endpoint) via a direct pool
  write rather than a real invocation. Pre-existing gap, not new from RFC-0008.

## Next
- The capability-derivation tree `Revoke`/proper `Delete` reclaim need.
- An idle thread, once `lantern-boot` can provide one.
- A cross-CNode capability-transfer primitive, to close the one remaining direct-pool-write
  gap `loader.rs` still has.
- `x86-64`: exercise this crate's logic there too, once `x86-64` boot work starts
  (deferred, see `lantern-boot/STATUS.md`) — `Hal::enter_thread` is still an
  `unimplemented!()` stub on that target.

## Blocked on
- Nothing for further in-kernel work (CSpace/object-model/IPC refinement) — the IPC core is
  now validated end-to-end on `riscv64`, including real per-program Sv39 address spaces
  built through real capability invocations and real U-mode execution
  (`lantern-boot/STATUS.md`). RFC-0004's "**confined** hello service" exit criterion is met.
