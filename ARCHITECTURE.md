# lantern-kernel — Architecture

This document is the component-level companion to [wiki/Kernel](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Kernel.md)
and is bound by [RFC-0002](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0002-microkernel-architecture.md) and
[ADR-0004](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0004-kernel-responsibilities-and-tcb-boundary.md). Where this
file and the wiki disagree, that is a bug — file an issue.

## Design goals (in priority order)

1. **Minimal TCB** — small enough to audit and eventually verify.
2. **No ambient authority** — every operation gates on a capability.
3. **Deterministic resource use** — no dynamic kernel allocation after boot.
4. **Fast IPC** — the whole system's performance rests on it.
5. **Portability** — ISA specifics confined to the HAL seam.

## Object model (initial)

Modelled closely on seL4 because that design is *proven* implementable and verifiable:

- **Untyped memory** — raw physical memory, retyped by user space into typed objects. The
  sole source of allocation; the kernel never grows its own heap.
- **CNode** — stores capabilities; CNodes compose into a per-process **CSpace**.
- **Thread control block (seL4 sense of "TCB")** — a thread; bound to a VSpace and a
  scheduling context. Not to be confused with *Trusted Computing Base*, the other "TCB"
  used throughout this document and the rest of the project.
- **Endpoint** — synchronous call/reply rendezvous; supports **badges**.
- **Notification** — asynchronous signal; bindable to IRQs.
- **VSpace / page tables / Frame** — the address-space machinery.
- **IRQ handler** — capability to receive a specific interrupt.
- **Scheduling context** — time budget/period (final model is an open question).

## Memory

Physical memory becomes untyped at boot and is owned by the root task, which retypes and
delegates it downstream (the "narrowing waterfall"). Consequences:

- Memory is itself a capability → spatial isolation by construction.
- A component cannot exhaust kernel memory; it spends *its own* accounted untyped.
- The kernel's footprint is bounded and analysable.

## IPC

- **Fast-path:** small synchronous messages passed in registers; no memory traffic.
- **Bulk:** zero-copy via shared frames granted by capability.
- **Async:** notifications for signalling and interrupt delivery.
- **Discipline:** core-local data structures; IPC latency is benchmarked and a regression
  blocks merge.

## HAL seam

Per-ISA code lives only in [`lantern-hal`](https://github.com/lantern-os/lantern-hal): context switch, page-table
format, trap entry, timer, interrupt controller, IOMMU. The portable core carries no
`target_arch` logic beyond calling the HAL.

## Concurrency & assurance

The kernel concurrency model (big-lock vs. fine-grained vs. event-based) is an **open
question** with large verification consequences, tracked under RFC-0002 follow-ups. The IPC
and capability paths are long-term **formal-verification targets**; tininess + safe Rust make
that realistic.

## Non-responsibilities

No file/network/crypto/AI concepts; no policy; no drivers. If a proposed feature is not in
the five-item job list, it belongs in user space — and adding to this list requires an RFC.

## Open questions
- Scheduling-context model (MCS vs. simpler).
- Concurrency model and verification cost.
- Syscall/IPC ABI and message-register layout.
- IOMMU/interrupt split between HAL and portable core.
