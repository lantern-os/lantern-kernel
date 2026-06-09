# lantern-kernel — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). The kernel is the
**core of the TCB**: any flaw here is, by definition, maximum severity, because every other
guarantee in LanternOS rests on the kernel being correct.

## Assets (kernel-specific)
- Integrity of kernel objects (CNodes, endpoints, untyped, page tables, TCBs).
- Integrity of the capability check on every syscall.
- Isolation between address spaces.
- Correctness of IPC (no message confusion, no leakage across endpoints).

## Adversaries
- Any confined user-space component (service, app, or agent) issuing crafted syscalls.
- A compromised driver attempting privilege escalation into the kernel.
- (Hardware/physical adversaries are handled at the [system level](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md).)

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| K1 | Capability forgery / amplification | Caps live only in kernel-managed CSpaces; rights checked every op; `mint` is monotone (attenuation only). |
| K2 | Confused-deputy via syscall | Designation = authority; the kernel acts only on caps the caller holds. |
| K3 | Memory corruption in the kernel | Safe Rust; `unsafe` isolated, justified, reviewed; eventual formal verification. |
| K4 | Kernel memory exhaustion | No post-boot kernel heap; all object memory from accounted user untyped. |
| K5 | IPC message confusion / leakage | Typed message transfer; badged endpoints; no shared mutable state. |
| K6 | DMA bypass of isolation by a driver | IOMMU confinement (HAL/hardware dependency — see open questions). |
| K7 | Interrupt-path escalation | IRQs delivered only to holders of the IRQ capability, as notifications. |
| K8 | Timing/covert channels between components | Acknowledged; partial mitigation via scheduling isolation; not fully solved (see non-goals). |

## TCB posture
The kernel commits to staying minimal: each addition is an RFC-level decision carrying a
verification cost. `unsafe` density is a tracked metric.

## Non-goals (kernel level)
- Microarchitectural side channels (Spectre-class) are tracked, not claimed defeated.
- Hardware below the kernel (firmware/silicon implants) — see the system threat model.

## Verification intent
The capability-check and IPC fast-path are the highest-priority candidates for machine-checked
proof (Roadmap Phase 3+).
