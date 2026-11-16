# lantern-kernel

The LanternOS **microkernel**: the small, privileged core that everything else trusts. It
provides scheduling, memory isolation, IPC, capability enforcement, and interrupt handling —
and nothing else.

- **Layer:** TCB (highest assurance).
- **Language:** Rust, `no_std`, isolated/audited `unsafe` ([ADR-0001](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0001-rust-as-primary-language.md)).
- **Decision of record:** [RFC-0002 — Microkernel architecture](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0002-microkernel-architecture.md).
- **System context:** [wiki/Kernel](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Kernel.md), [wiki/Architecture](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Architecture.md).

> **Phase 4** ([RFC-0036](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0036-phase-3-to-phase-4-transition.md)): hardware and assurance. The kernel runs on QEMU `virt` (riscv64): capabilities and untyped retyping, IPC, preemptive
> scheduling, interrupts, deadlines, and process reclamation, with every service confined above it. Formal verification
> of its capability and IPC paths is Phase 4's first work. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the kernel's internal design.
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — threats to the most trusted component.
- [`STATUS.md`](./STATUS.md) — current state and next steps.
- `docs/` — deeper design notes as they are written.
- `src/` — kernel source (empty until Phase 1).

## The whole job, in one list
1. Scheduling (mechanism; policy lives in user space).
2. Memory isolation (address spaces; untyped-memory retyping; no post-boot heap).
3. IPC (synchronous endpoints + asynchronous notifications).
4. Capability enforcement (per-process CSpace; rights checked every syscall).
5. Interrupt handling (delivered to user-space drivers as notifications).

Everything else — drivers, fs, net, crypto, runtimes — is unprivileged user space.
