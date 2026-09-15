//! Phase 1 fixed capacities. The kernel does no dynamic heap allocation after boot
//! ([ADR-0004](../../lantern-rfcs/adr/0004-kernel-responsibilities-and-tcb-boundary.md)),
//! so every object pool is a fixed-size array sized generously for a Phase 1
//! prototype (RFC-0004's "one confined hello service" exit criterion) — not tuned
//! for a real workload. Revisit when Phase 1 exits.

pub const MAX_CNODES: usize = 4;
pub const MAX_TCBS: usize = 8;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_NOTIFICATIONS: usize = 8;
pub const MAX_UNTYPEDS: usize = 4;
pub const MAX_SCHED_CONTEXTS: usize = 8;
pub const MAX_VSPACES: usize = 4;
/// Generous for a Phase 1 ELF loader: enough Frames for a small statically
/// linked binary's segments plus a stack, at megapage granularity
/// (`lantern-boot/STATUS.md`) — a handful of 2 MiB Frames, not hundreds.
pub const MAX_FRAMES: usize = 16;
/// Kernel-owned page tables (`crate::object::KernelPageTables`) — `VSpace`
/// roots (bounded by [`MAX_VSPACES`]) plus the L1/L0 branch pages
/// `FrameInvoke::Map` creates on demand, one 4 KiB page each. Generous for a
/// handful of loaded programs each touching a handful of distinct 1 GiB
/// (Sv39 L2) regions, not tuned. This memory is embedded directly in
/// `KernelState` (kernel `.bss`) — keep it well clear of the 2 MiB the
/// kernel image's own linker script (`lantern-boot/linker.ld`) asserts the
/// whole image must fit within.
pub const MAX_KERNEL_PAGE_TABLES: usize = 32;

/// Capacity of a single (Phase 1: flat, single-level) CNode, per RFC-0005's CSpace
/// simplification.
pub const CNODE_SLOTS: usize = 32;
