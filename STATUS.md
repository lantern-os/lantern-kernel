# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md); design complete, no code merged yet.

## Done
- Kernel scope fixed to five responsibilities ([RFC-0002](../lantern-rfcs/rfcs/0002-microkernel-architecture.md), Accepted; see [ADR-0004](../lantern-rfcs/adr/0004-kernel-responsibilities-and-tcb-boundary.md)).
- Object model sketched and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)); fixed a "TCB" (Trusted Computing Base vs. thread control block) terminology collision during review.
- Component threat model drafted and reviewed ([THREAT_MODEL.md](./THREAT_MODEL.md)).
- Syscall/IPC ABI and Phase 1 scheduling-context model accepted
  ([RFC-0005](../lantern-rfcs/rfcs/0005-syscall-ipc-abi-and-phase1-scheduling.md); see
  [ADR-0008](../lantern-rfcs/adr/0008-kernel-syscall-ipc-abi.md) and
  [ADR-0009](../lantern-rfcs/adr/0009-phase1-scheduling-context-model.md)).

## Next
- Concurrency model (single-stack vs. process-kernel) — still open post-RFC-0002, not
  addressed by RFC-0005; see [ADR-0004](../lantern-rfcs/adr/0004-kernel-responsibilities-and-tcb-boundary.md).
- Phase 1 prototype: boot → address spaces → threads → IPC fast-path → capability mechanism,
  on `riscv64`/x86-64 under QEMU, against the ADR-0008/ADR-0009 ABI.

## Blocked on
- HAL seam definition ([`lantern-hal`](../lantern-hal)) — now specified by ADR-0008's
  "HAL contract this ABI requires," awaiting implementation.
