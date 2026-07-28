//! The kernel object model ([RFC-0002](../../lantern-rfcs/rfcs/0002-microkernel-architecture.md)/
//! [ADR-0006](../../lantern-rfcs/adr/0006-three-layer-capability-structure.md)'s kernel
//! layer): the objects a [`Capability`](crate::cap::Capability) can designate, minus
//! `CNode` (see [`crate::cap`]).

use lantern_hal::{Hal, Hardware, MessageTag, TrapFrame, MR_COUNT};

use crate::cap::{CNodeId, NotificationId, SchedContextId, TcbId, UntypedId, VSpaceId};
use crate::queue::ArrayQueue;

/// Must match [`lantern_hal`]'s `TrapFrame::raw` word count. Not exported as a
/// constant by `lantern-hal` today; if that array's size ever changes, this needs
/// updating alongside it (tracked as a follow-up: export the constant instead).
const RAW_WORDS: usize = 32;

/// A snapshot of a thread's register state — everything a [`TrapFrame`] carries,
/// copied out of it. Needed because a blocked/ready thread's registers must live
/// somewhere while a *different* thread's [`TrapFrame`] occupies the one hardware
/// trap frame (Phase 1 is single-hart, single-stack — [ADR-0010](../../lantern-rfcs/adr/0010-kernel-concurrency-model.md)).
#[derive(Clone, Copy, Debug)]
pub struct SavedContext {
    syscall_num: usize,
    tag: MessageTag,
    mrs: [usize; MR_COUNT],
    raw: [usize; RAW_WORDS],
}

impl SavedContext {
    pub const fn zeroed() -> Self {
        Self {
            syscall_num: 0,
            tag: MessageTag { label: 0, length: 0, extra_caps: 0, flags: 0 },
            mrs: [0; MR_COUNT],
            raw: [0; RAW_WORDS],
        }
    }

    /// Builds the initial saved state for a thread that has never run: `pc` where
    /// it starts, `sp` its initial stack, `arg0` its first argument. Delegates the
    /// actual register-layout knowledge to `lantern-hal`
    /// ([`Hal::initial_trap_frame`]) — this stays portable, no `target_arch` logic
    /// here, matching the HAL-seam discipline in `lantern-kernel/ARCHITECTURE.md`.
    pub fn initial(pc: usize, sp: usize, arg0: usize) -> Self {
        Self::save_from(&Hardware::initial_trap_frame(pc, sp, arg0))
    }

    /// Copies the interrupted thread's full state out of `frame`.
    pub fn save_from(frame: &TrapFrame) -> Self {
        let mut mrs = [0usize; MR_COUNT];
        for (i, mr) in mrs.iter_mut().enumerate() {
            *mr = frame.mr(i);
        }
        let mut raw = [0usize; RAW_WORDS];
        for (i, word) in raw.iter_mut().enumerate() {
            *word = frame.raw_word(i);
        }
        Self { syscall_num: frame.syscall_number(), tag: frame.tag(), mrs, raw }
    }

    /// Writes this state into `frame`, so `lantern-hal`'s trap-exit path resumes
    /// whichever thread this snapshot belongs to instead of whoever trapped in —
    /// this *is* the context switch (see `lantern-kernel/ARCHITECTURE.md`'s
    /// concurrency notes): no separate HAL primitive is needed.
    pub fn restore_into(&self, frame: &mut TrapFrame) {
        frame.set_syscall_number(self.syscall_num);
        frame.set_tag(self.tag);
        for (i, mr) in self.mrs.iter().enumerate() {
            frame.set_mr(i, *mr);
        }
        for (i, word) in self.raw.iter().enumerate() {
            frame.set_raw_word(i, *word);
        }
    }

    pub fn mr(&self, index: usize) -> usize {
        self.mrs[index]
    }

    pub fn set_mr(&mut self, index: usize, value: usize) {
        self.mrs[index] = value;
    }

    pub fn tag(&self) -> MessageTag {
        self.tag
    }

    pub fn set_tag(&mut self, tag: MessageTag) {
        self.tag = tag;
    }
}

/// A thread's run state. `Inactive` is a pool slot's initial state before
/// `TCBConfigure` sets it up — distinct from `Ready`/`Running` so an unconfigured
/// TCB can never be scheduled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadState {
    Inactive,
    Ready,
    Running,
    BlockedSend {
        endpoint: crate::cap::EndpointId,
        /// The badge of the endpoint capability this thread invoked — captured
        /// here because, once blocked, the thread's own registers no longer hold
        /// it; a later `Recv` reads it back out to deliver to the receiver.
        badge: u64,
        /// Distinguishes a blocked `Send` (receiver `make_ready`s the sender once
        /// delivered) from a blocked `Call` (receiver instead gets a `reply_to`
        /// link back to the sender, who moves to `BlockedReply`).
        is_call: bool,
    },
    BlockedRecv(crate::cap::EndpointId),
    /// Blocked in `Call`, waiting for the callee's `Reply`.
    BlockedReply,
    BlockedWait(NotificationId),
}

/// A thread control block ("TCB" in the seL4/object-model sense — see
/// `lantern-kernel/ARCHITECTURE.md`'s note on the other "TCB", Trusted Computing
/// Base, used elsewhere in this project's docs).
#[derive(Clone, Copy, Debug)]
pub struct Tcb {
    pub state: ThreadState,
    pub cspace: Option<CNodeId>,
    pub sched_context: Option<SchedContextId>,
    pub context: SavedContext,
    /// Which thread (if any) this TCB owes a `Reply` to — the implicit reply
    /// capability RFC-0005 describes ("Reply | (implicit reply cap) | Replies to
    /// the most recent unanswered Call this thread received").
    pub reply_to: Option<TcbId>,
    /// The architecture-specific physical root page-table address for this
    /// thread's address space (`riscv64`: an `Riscv64PageTable` built by
    /// `lantern-hal`'s `riscv64_map_page`), or `None` for a thread that hasn't
    /// been given one — not yet capability-mediated (no VSpace object exists in
    /// `lantern-kernel` yet, see `STATUS.md`); `lantern-boot` sets this directly.
    /// `None` also keeps every existing host unit test working unmodified: with
    /// no address space, a switch never calls `Hal::activate_address_space` at
    /// all, not even the `x86-64` no-op.
    pub address_space: Option<usize>,
}

impl Tcb {
    pub const fn new() -> Self {
        Self {
            state: ThreadState::Inactive,
            cspace: None,
            sched_context: None,
            context: SavedContext::zeroed(),
            reply_to: None,
            address_space: None,
        }
    }
}

impl Default for Tcb {
    fn default() -> Self {
        Self::new()
    }
}

/// An endpoint queues threads on (at most) one side at a time: either senders
/// waiting for a receiver, or a receiver waiting for a sender — never both, since a
/// rendezvous immediately pairs one off the queue (seL4's invariant).
#[derive(Clone, Copy, Debug)]
pub enum EndpointQueue {
    Empty,
    Send(ArrayQueue<TcbId, { crate::limits::MAX_TCBS }>),
    Recv(ArrayQueue<TcbId, { crate::limits::MAX_TCBS }>),
}

#[derive(Clone, Copy, Debug)]
pub struct Endpoint {
    pub queue: EndpointQueue,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self { queue: EndpointQueue::Empty }
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::new()
    }
}

/// An asynchronous signal: `Signal` OR-accumulates bits into `signals`; `Wait`/
/// `Poll` consume them. Phase 1 simplification: any number of threads may block in
/// `waiters` (seL4 additionally supports binding a notification to a TCB outside
/// `Wait`'s blocked queue — not modelled here, tracked as a gap).
#[derive(Clone, Copy, Debug)]
pub struct Notification {
    pub signals: u64,
    pub waiters: ArrayQueue<TcbId, { crate::limits::MAX_TCBS }>,
}

impl Notification {
    pub const fn new() -> Self {
        Self { signals: 0, waiters: ArrayQueue::new() }
    }
}

impl Default for Notification {
    fn default() -> Self {
        Self::new()
    }
}

/// Untyped memory, ready to be `UntypedRetype`d into typed objects.
///
/// **Phase 1 simplification:** real (seL4/ADR-0008) Untyped is byte-granular
/// physical memory; there is no general physical memory map to carve from yet
/// (no DTB parsing — `lantern-kernel/STATUS.md`). This models Untyped as an
/// object-count *budget* first and foremost — `remaining` decrements by one per
/// object retyped, regardless of the target object's real size — which is
/// enough to exercise the retype mechanism and its capability bookkeeping end to
/// end for `CNode`/`Endpoint`/`Notification`/`Tcb`/`SchedContext`, none of which
/// need a real physical address (they live in the kernel's own pools, not
/// user-addressable memory).
///
/// **`VSpace`/`Frame` are different: they *name* real physical memory** (an Sv39
/// root page table; a page a thread can map), so retyping one needs an actual
/// address, not just a decremented count. `memory`, when `Some`, is a real
/// physical bump range `lantern-boot` seeds at boot from its own `pmm` allocator
/// (the only real physical-memory source that exists today) — see
/// [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
/// [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md).
/// This is a narrow, additive change to *specific* Untyped instances, not a
/// general physical-memory-discovery subsystem — most Untypeds (e.g. the ones
/// today's tests construct) still have `memory: None` and can retype anything
/// except `VSpace`/`Frame*`.
#[derive(Clone, Copy, Debug)]
pub struct Untyped {
    pub remaining: usize,
    memory: Option<(usize, usize)>,
}

impl Untyped {
    pub const fn new(budget: usize) -> Self {
        Self { remaining: budget, memory: None }
    }

    /// A budget additionally backed by a real physical range `[base, base + len)`
    /// — see this struct's doc. `lantern-boot` is the only expected caller.
    pub const fn with_memory(budget: usize, base: usize, len: usize) -> Self {
        Self { remaining: budget, memory: Some((base, base + len)) }
    }

    /// Bump-allocates one `size`-byte, `align`-aligned chunk of real physical
    /// memory from this Untyped's backing range, or `None` if it has no such
    /// range (a plain count-only budget) or the range is exhausted. Does *not*
    /// touch `remaining` — callers (`admin::untyped_retype`) decrement that
    /// separately, the same one-per-object accounting every other retyped type
    /// already uses.
    pub fn bump(&mut self, size: usize, align: usize) -> Option<usize> {
        let (next, end) = self.memory?;
        let aligned = (next + align - 1) & !(align - 1);
        let new_next = aligned.checked_add(size)?;
        if new_next > end {
            return None;
        }
        self.memory = Some((new_next, end));
        Some(aligned)
    }
}

/// The Sv39 leaf sizes [`Frame`] supports (RFC-0008/ADR-0012). `Mega` is what
/// `lantern-boot`'s loader actually uses, exclusively, for now — a documented
/// workaround for a QEMU-environment limitation with full 3-level Sv39 walks
/// (`lantern-hal/STATUS.md`), not a property of this object model. `Small` is
/// fully specified so switching back is a one-line change once that's resolved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameSize {
    Small,
    Mega,
}

impl FrameSize {
    pub const fn bytes(self) -> usize {
        match self {
            FrameSize::Small => lantern_hal::RISCV64_PAGE_SIZE,
            FrameSize::Mega => lantern_hal::RISCV64_MEGAPAGE_SIZE,
        }
    }
}

/// An address space: one Sv39 root page table. `root` is a real physical
/// address, from the owning Untyped's `memory` range (RFC-0008/ADR-0012).
#[derive(Clone, Copy, Debug)]
pub struct VSpace {
    pub root: usize,
    /// Which Untyped this VSpace's root table (and any L1 tables `FrameInvoke`
    /// `Map` needs to create on demand) were bump-allocated from — `Map` reuses
    /// it rather than taking a separate "which Untyped to allocate from"
    /// argument every caller would otherwise have to supply.
    pub(crate) source: UntypedId,
}

/// One physical page usable as a `FrameInvoke` mapping target — RFC-0008/
/// ADR-0012. `paddr` is real physical memory, from the owning Untyped's
/// `memory` range, sized per `size`.
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub paddr: usize,
    pub size: FrameSize,
    /// Which VSpace currently maps this Frame, and at what address — `Unmap`'s
    /// target, and what stops a Frame being mapped into two VSpaces (or twice
    /// into the same one) at once. Phase 1 has no shared-frame IPC yet, so a
    /// Frame has at most one mapping, full stop.
    pub mapped_at: Option<(VSpaceId, usize)>,
}

/// Phase 1 scheduling context ([ADR-0009](../../lantern-rfcs/adr/0009-phase1-scheduling-context-model.md)):
/// `budget == period` always, giving plain round-robin — no replenishment, no
/// admission control.
#[derive(Clone, Copy, Debug)]
pub struct SchedulingContext {
    pub budget: u64,
    pub period: u64,
}

impl SchedulingContext {
    pub const fn new(budget_eq_period: u64) -> Self {
        Self { budget: budget_eq_period, period: budget_eq_period }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_context_roundtrips_through_a_trap_frame() {
        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(4);
        frame.set_tag(MessageTag { label: 7, length: 1, extra_caps: 0, flags: 0 });
        frame.set_mr(0, 42);
        frame.set_raw_word(5, 99);

        let saved = SavedContext::save_from(&frame);

        let mut other = TrapFrame::zeroed();
        saved.restore_into(&mut other);
        assert_eq!(other.syscall_number(), 4);
        assert_eq!(other.tag(), MessageTag { label: 7, length: 1, extra_caps: 0, flags: 0 });
        assert_eq!(other.mr(0), 42);
        assert_eq!(other.raw_word(5), 99);
    }
}
