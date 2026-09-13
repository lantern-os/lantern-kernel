# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — opened per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md), **closed** per [RFC-0009](../lantern-rfcs/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](../lantern-rfcs/adr/0014-phase-1-complete-phase-2-opened.md): a confined "hello service" reachable only via a granted capability, validated under real QEMU via `lantern-boot`'s ELF loader, with IPC latency benchmarked ([ADR-0013](../lantern-rfcs/adr/0013-ipc-latency-benchmark.md), `lantern-boot/STATUS.md`). This crate's own remaining "Next" items below continue as ordinary engineering work — the Roadmap's phase gate has moved on to Phase 3 (RFC-0017/ADR-0021), this crate's Phase 1 backlog hasn't.

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
- Added `two_call_reply_round_trips_in_a_row_client_runs_first`, a host-side reproduction of
  the real QEMU IPC round-trip-loss bug's dispatch sequence (see "Known Phase 1 gaps" below)
  — it passes, ruling out this crate's own dispatch logic as the cause. 42 unit tests pass.
- **Single-capability IPC transfer** ([RFC-0010](../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md),
  kernel-side prototype), in `src/ipc.rs`: `tag.extra_caps == 1` is now real, not just
  reserved wire-format space. `Send`/`Call` read `mr1` as the sender's CPtr for a capability
  to transfer (payload shrinks to `mr2`/`mr3`), gated on `Rights::GRANT` — the first real
  consumer anywhere in the tree of a rights bit that has existed, unenforced, since RFC-0003.
  `Recv` reads its own `mr1` as the receiver's destination CPtr, registered up front (at
  block time if no sender is waiting yet) so a transfer against a receiver with no or an
  occupied destination slot fails the *entire* rendezvous atomically — nothing is consumed,
  no capability is dropped. `ArrayQueue` gained `front()` (peek without popping) to make that
  atomicity possible: validate the destination before dequeuing the other party. This is a
  real, cross-process, capability-gated transfer — not `lantern-boot/loader.rs`'s existing
  direct-pool-write shortcut, and not yet used to replace it (see "Next"). `extra_caps > 1`
  still has nowhere to go (no in-memory IPC buffer) and stays rejected, same as `length > 0`.
  `Reply`'s return leg does **not** support a transfer yet and explicitly rejects any nonzero
  `extra_caps` — RFC-0010 left `Call`'s reply-path register layout as an open question (the
  original caller has no spare register at `Call` time to register a destination slot the
  way `Recv`'s callers do). 51 unit tests pass (8 new, in `ipc::transfer_tests`), `cargo
  clippy -D warnings` clean on host and `riscv64gc-unknown-none-elf`; `lantern-boot` still
  builds unchanged against the `ThreadState::BlockedRecv`/`BlockedSend` shape change.
- **`CNodeInvoke::CopyCross`** ([RFC-0010](../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md),
  `src/cnode.rs`, label 6): copies a capability from a slot in one CNode into a slot in a
  *different* CNode, gated on the caller already holding capabilities to both (the same
  trust level ordinary same-CNode `Copy` already has). Added after discovering, while
  trying to migrate `lantern-boot/loader.rs` onto the `extra_caps == 1` live-IPC transfer
  above, that live transfer structurally *cannot* do this job: `Recv`ing requires already
  holding a capability to rendezvous on, so it can't bootstrap a program's very first
  capability (chicken-and-egg). `CopyCross` is the administrative operation that actually
  fills `cnode.rs`'s long-standing "no cross-CNode transfer primitive" gap — a real,
  capability-checked kernel invocation, not a pool poke, but a deliberately different
  mechanism from RFC-0010's `Rights::GRANT`-gated live transfer, not built on top of it.
  54 unit tests pass (3 new), `cargo clippy -D warnings` clean on host and
  `riscv64gc-unknown-none-elf`. See `lantern-boot/STATUS.md` for the real-QEMU validation:
  `loader.rs` now uses this instead of its old direct pool write, and the full two-program
  IPC benchmark demo still passes end to end.
- **`Reply`'s return-leg transfer** (RFC-0010's own "Unresolved questions" item, now
  resolved), in `src/ipc.rs`: `Reply` supports `tag.extra_caps == 1` with the same `mr1`
  convention `Send` uses. The actual open question — where does the *original caller*
  register a destination slot, given `Call` has no spare register once `mr1` names an
  outbound transfer — is resolved by giving `extra_caps` a second, `Call`-only meaning:
  `== 1` still means "attach an outbound capability" (unchanged), `== 2` now means "no
  outbound transfer this call, but `mr1` is my own destination slot for a capability the
  `Reply` might attach." The two are mutually exclusive per call — Phase 1's three payload
  words have no room for both at once, so `Call` picks one meaning for `mr1`, never two.
  `ThreadState::BlockedSend` gained a `reply_dest_slot` field to carry this from `Call`
  through to `ThreadState::BlockedReply` (now `{ dest_slot: Option<CPtr> }` instead of a
  unit variant) once a `Recv` actually picks the caller up; the immediate-rendezvous path
  sets it directly. Same atomicity discipline as the rest of RFC-0010's transfer work: a
  `Reply` attempting a transfer against a caller with no registered destination fails
  cleanly (`IllegalOperation`) *before* consuming the `reply_to` link, so the caller isn't
  stranded and can be replied to again. `abi::require_no_extra_caps` is gone — `Reply` now
  shares `require_fast_path_only` with `Send`/`Recv` (accepts `0` or `1`); `Call` gets its
  own `require_call_tag` (accepts `0`, `1`, or `2`). 57 unit tests pass (3 new; 2 existing
  `ipc::transfer_tests` updated for the `ThreadState::BlockedReply` shape change), `cargo
  clippy -D warnings` clean on host and `riscv64gc-unknown-none-elf`; `lantern-boot`'s full
  two-program QEMU demo (2000-round-trip benchmark, plain `Call`/`Reply`, `extra_caps == 0`
  throughout) re-verified unaffected, same latency range as before.

- **`Frame` may now be mapped into up to two VSpaces at once** (2026-09-13,
  [ADR-0022](../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md) Part 2 —
  see its "Implementation note"). `Frame::mapped_at` widened from
  `Option<(VSpaceId, usize)>` to `[Option<(VSpaceId, usize)>; MAX_FRAME_MAPPINGS]`
  (`MAX_FRAME_MAPPINGS == 2`, deliberately not a general N-way sharing primitive — exactly
  the RFC-0019 shared `(runtime, service)` `Frame` case). `map` now finds any free slot
  instead of refusing a second mapping outright; `FrameInvoke::Unmap` gained an `mr1`
  argument (which VSpace's mapping to remove — mirrors `Map`'s own `mr1`), since "the"
  mapping is no longer unambiguous once there can be two. Confirmed no Phase 1/2 caller
  ever invoked `Unmap` for real before this (only this crate's own tests did) — a clean
  ABI widening, not a break. 5 new/rewritten tests (a second simultaneous mapping now
  succeeds, a third is rejected once both slots are full, `Unmap` clears only the VSpace it
  names and leaves the other mapping intact) — 59 total, `cargo clippy --all-targets -D
  warnings` clean host + `riscv64`. `THREAT_MODEL.md` updated (a new asset entry + K9: the
  kernel enforces only the mapping *count*, never a third VSpace; content-level races
  across the two mappers are each service's own copy-in-before-validate discipline,
  RFC-0019, not a kernel-enforced property).

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
`lantern-boot`'s third demo (`lantern-boot-frame-demo`, 2026-09-13) now also validates the
new two-mapping `Frame` support for real: one 4 KiB `Frame` mapped into two independently
loaded, mutually confined programs' VSpaces at once, with real bytes (`Channel::call`'s
request, transformed, `Channel::reply`'s response) crossing through it — 3/3 reproducible
runs.

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
- `cnode::invoke`'s original `Copy`/`Move` still only operate on slots *within a single
  CNode* — that part is unchanged and still true. Cross-CNode placement is now possible via
  the separate `CopyCross` operation (RFC-0010, above), used by `lantern-boot/loader.rs`
  instead of its old direct pool write.
- **IPC round-trip loss under real QEMU, not reproducible on host.** Found while building
  `lantern-boot`'s IPC benchmark: the first `Call`/`block_current` a thread issues right
  after a warm-up round trip occasionally never actually resumes the receiver, despite
  `block_current` returning `true` and `scheduler.current` being set correctly — see
  `lantern-boot/STATUS.md`'s "IPC round-trip loss" entry for the full investigation.
  `syscall::tests::two_call_reply_round_trips_in_a_row_client_runs_first` reproduces the
  identical dispatch sequence against portable `KernelState` (no real paging) and passes,
  which is evidence this crate's own `ipc::call`/`block_current` logic is *not* the cause —
  the bug lives somewhere in the real trap-entry/exit or address-space-switch path this
  crate's host tests structurally cannot exercise. Not root-caused; worked around at the
  `lantern-boot` call site with extra tolerated round trips, not fixed here.
  **A new, much more deterministic manifestation, found 2026-09-13 building
  `lantern-boot-keystore-demo`** (a confined `lantern_crypto::Keystore`'s live
  `request_key_access`+`deliver_grant_via_reply` grant round, then the granted client
  using the badge to `Call` again): the client's **first** `Call` issued right after being
  resumed via the *service's* `Reply` (`tag.extra_caps == 1`, a real capability transfer)
  **never reaches the service at all — 100% reproducibly, not occasionally.** Diagnostic
  instrumentation in the trap handler (`lantern-boot`, temporary, removed) directly
  inspected kernel state across this exact trap and found: the transferred capability is
  present and correct at the destination (right `EndpointId`, right badge, right
  `Rights::WRITE | Rights::GRANT`); the target endpoint's queue is `Empty` (no
  interference); `Scheduler::has_ready()` is `true`; no `SyscallError` is raised
  (`tag`'s error flag stays clear, `mr0` unchanged from its input value) — and yet
  **neither thread's `ThreadState` nor `scheduler.current` changes across the trap at
  all**, as if `ipc::call`'s body never ran past its capability/tag resolution. A `dev`
  profile build (debug assertions on) hit no panic either, including at
  `ipc::call`'s `debug_assert!(switched, "has_ready() was checked immediately above")`.
  Structurally the closest-precedent difference from `lantern-boot`'s own
  IPC-latency-benchmark client (which *does* successfully `Call` again immediately after
  being resumed via a Reply's `switch_to`, ~2000 times per run): this `Call` carries a
  nonzero message-tag `label` (RFC-0019/ADR-0024's op code,
  `lantern_abi::sys::call_with_label`) and targets a *freshly badge-transferred* CPtr
  rather than a capability the loader pre-granted — neither individually ruled out as the
  trigger. Not root-caused. Blocks `lantern-boot-keystore-demo`'s Phase 2 (the actual
  RFC-0019 wire exchange) and, by the same shape, would block any confined service's
  *second* client interaction generally — a real, higher-priority reason to finally
  root-cause this class of bug, not just tolerate it via extra round trips.

## Next
- **Root-cause the IPC round-trip-loss bug — now genuinely urgent, not just tolerated.**
  The 2026-09-13 manifestation (above) is 100% reproducible and blocks real functionality
  (`lantern-boot-keystore-demo`'s Phase 2), unlike the ~1-in-2000 rate the original
  hello-service benchmark tolerates. Candidates not yet tried, in priority order given the
  new evidence: (1) isolate whether a nonzero `MessageTag.label` on `Call` is the trigger
  — build a minimal demo that issues a labelled `Call` immediately after being resumed via
  a plain (no-capability-transfer) `Reply`, to separate that variable from "freshly
  badge-transferred CPtr"; (2) QEMU GDB-stub single-stepping across the exact failing trap
  (`-s -S`, `riscv64-unknown-elf-gdb`) to see directly whether `ipc::call` is entered at
  all for this specific trap, since kernel-state inspection alone couldn't distinguish
  "never entered" from "entered but every mutation silently no-op'd"; (3) compare the
  `MessageTag` packing/unpacking specifically for a *nonzero* `label` through
  `lantern-hal`'s riscv64 trap trampoline register save/restore path (a real repeat
  offender — see this file's fixed trampoline-bug history above) — every prior use of a
  nonzero label in this project (`CNodeInvoke`) has been a *fast, uninterrupted* call, not
  one crossing a thread suspend/resume boundary.
- The capability-derivation tree `Revoke`/proper `Delete` reclaim need — more pressing in
  Phase 3: [RFC-0018](../lantern-rfcs/rfcs/0018-confined-execution-port.md) (Accepted;
  [ADR-0022](../lantern-rfcs/adr/0022-confined-service-model-and-call-transport.md)/[ADR-0023](../lantern-rfcs/adr/0023-wasmtime-no-std-pulley-hosting.md))
  needs real `Revoke` for "a revocable capability set" on a still-running app; it does not
  block that work's v0 (tear the process down instead).
- An idle thread, once `lantern-boot` can provide one — RFC-0018's synchronous
  request/reply service mesh never reaches "all threads blocked", but `lantern-network`'s
  first blocking socket read will need it.
- RFC-0010's kernel-side scope is now fully implemented (outbound transfer, `CopyCross`,
  reply-leg transfer). `lantern-capabilities`' `Broker` (see its own `STATUS.md`) still
  grants over a plain `Send`, not `Call`/`Reply` — updating it to use the now-real
  reply-leg transfer for the more natural request/response grant shape is unstarted.
- `x86-64`: exercise this crate's logic there too, once `x86-64` boot work starts
  (deferred, see `lantern-boot/STATUS.md`) — `Hal::enter_thread` is still an
  `unimplemented!()` stub on that target.

## Blocked on
- Nothing for further in-kernel work (CSpace/object-model/IPC refinement) — the IPC core is
  now validated end-to-end on `riscv64`, including real per-program Sv39 address spaces
  built through real capability invocations and real U-mode execution
  (`lantern-boot/STATUS.md`). RFC-0004's "**confined** hello service" exit criterion is met.
