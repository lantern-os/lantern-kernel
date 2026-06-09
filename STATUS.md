# lantern-kernel — Status

**Phase:** 0 (Foundations) — design only, no code.

## Done
- Kernel scope fixed to five responsibilities ([RFC-0002](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0002-microkernel-architecture.md), Proposed).
- Object model sketched ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Component threat model drafted ([THREAT_MODEL.md](./THREAT_MODEL.md)).

## Next (gated on RFC-0002 → Accepted)
- Resolve scheduling-context and concurrency models.
- Specify the syscall/IPC ABI.
- Phase 1 prototype: boot → address spaces → threads → IPC fast-path → capability mechanism,
  on `riscv64`/x86-64 under QEMU.

## Blocked on
- HAL seam definition ([`lantern-hal`](https://github.com/lantern-os/lantern-hal)).
- Acceptance of [RFC-0002](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0002-microkernel-architecture.md) and
  [RFC-0003](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0003-capability-model.md).
