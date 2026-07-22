# lantern-kernel — Status

**Phase:** 1 (Microkernel prototype) — open per [RFC-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0004-phase-0-to-phase-1-transition.md); design complete, no code merged yet.

## Done
- Kernel scope fixed to five responsibilities ([RFC-0002](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0002-microkernel-architecture.md), Accepted; see [ADR-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0004-kernel-responsibilities-and-tcb-boundary.md)).
- Object model sketched and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)); fixed a "TCB" (Trusted Computing Base vs. thread control block) terminology collision during review.
- Component threat model drafted and reviewed ([THREAT_MODEL.md](./THREAT_MODEL.md)).

## Next
- Resolve scheduling-context and concurrency models (still open post-RFC-0002; see
  [ADR-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0004-kernel-responsibilities-and-tcb-boundary.md)).
- Specify the syscall/IPC ABI.
- Phase 1 prototype: boot → address spaces → threads → IPC fast-path → capability mechanism,
  on `riscv64`/x86-64 under QEMU.

## Blocked on
- HAL seam definition ([`lantern-hal`](https://github.com/lantern-os/lantern-hal)).
