//! Fixed capacities. The kernel does no dynamic heap allocation after boot
//! ([ADR-0004](../../lantern-rfcs/adr/0004-kernel-responsibilities-and-tcb-boundary.md)),
//! so every object pool is a fixed-size array and every slot is permanent `.bss`.
//!
//! The values were placeholders from the first prototype until
//! [RFC-0020](../../lantern-rfcs/rfcs/0020-launch-binder.md). `MAX_CNODES`, `MAX_VSPACES`,
//! `MAX_FRAMES` and `CNODE_SLOTS` are now sized from `lantern-boot-runtime-fs-demo`, the
//! largest topology, plus room for one more small service. Measured there: 5 CNodes, 4
//! VSpaces, 20 Frames, 42 root CNode slots, at most 16 kernel page tables. Raising them
//! from 4/4/16/32 cost about 4 KiB of `.bss`. [RFC-0021](../../lantern-rfcs/rfcs/0021-grant-ledger-and-revocation.md)'s
//! `grant-control` and [RFC-0022](../../lantern-rfcs/rfcs/0022-persistent-revocation-store.md)'s
//! `policy-store` have since grown it, so they were raised again. It now takes 7 CNodes, 6 VSpaces, 27
//! Frames and 64 root slots of 7, 6, 28 and 72, so another program needs these raised too. The other pools are still the original
//! placeholders: nothing has come close to them. None of this is tuned for a real workload.

pub const MAX_CNODES: usize = 7;
pub const MAX_TCBS: usize = 8;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_NOTIFICATIONS: usize = 8;
pub const MAX_UNTYPEDS: usize = 4;
pub const MAX_SCHED_CONTEXTS: usize = 8;
pub const MAX_VSPACES: usize = 6;
/// System-wide, at megapage granularity (`lantern-boot/STATUS.md`): dozens of 2 MiB
/// Frames, not hundreds. See the module doc for how this was sized.
pub const MAX_FRAMES: usize = 28;
/// Kernel-owned page tables (`crate::object::KernelPageTables`) — `VSpace`
/// roots (bounded by [`MAX_VSPACES`]) plus the L1/L0 branch pages
/// `FrameInvoke::Map` creates on demand, one 4 KiB page each. Generous for a
/// handful of loaded programs each touching a handful of distinct 1 GiB
/// (Sv39 L2) regions, not tuned. This memory is embedded directly in
/// `KernelState` (kernel `.bss`) — keep it well clear of the 2 MiB the
/// kernel image's own linker script (`lantern-boot/linker.ld`) asserts the
/// whole image must fit within.
pub const MAX_KERNEL_PAGE_TABLES: usize = 32;

/// Capacity of a single (flat, single-level) CNode, per RFC-0005's CSpace simplification.
/// Every CNode pays for this, though only the launcher's root needs this many.
pub const CNODE_SLOTS: usize = 72;
/// Interrupt lines bound to a driver at once ([RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md)).
/// The console needs one; storage and network will each need one more.
pub const MAX_IRQ_HANDLERS: usize = 4;
/// Controller actions waiting for the trap glue to apply them, between two traps. Each `IrqHandlerInvoke` queues at
/// most two, and each delivery two.
pub const MAX_IRQ_ACTIONS: usize = 16;
/// Every thread's time slice: ADR-0009's `budget == period`, replenished each period (RFC-0027).
pub const QUANTUM_NS: u64 = 10_000_000;
/// Armed-or-not `Deadline`s at once ([RFC-0028](../../lantern-rfcs/rfcs/0028-deadlines-and-a-capability-clock.md)).
/// Finding the earliest is a scan of these, on every trap.
pub const MAX_DEADLINES: usize = 8;
