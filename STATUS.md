# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); design complete (ABI, scheduling, concurrency all fixed), no code merged yet.

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

## Next
- Phase 1 prototype: boot → address spaces → threads → IPC fast-path → capability mechanism,
  on `riscv64`/x86-64 under QEMU, against the ADR-0008/ADR-0009/ADR-0010 design. This is
  now the kernel's first code — every design question blocking it is resolved.

## Blocked on
- Nothing on the kernel's own design — the syscall/IPC ABI, scheduling-context model, and
  concurrency model are all fixed (ADR-0008/0009/0010), and `lantern-hal`'s `riscv64`/
  `x86-64` trap entries are implemented. Actually *running* the prototype under QEMU still
  needs `lantern-boot`'s minimal loader ([`lantern-boot`](../lantern-boot), itself blocked
  on `lantern-crypto`), but writing and unit-testing kernel code against the fixed ABI does
  not.
