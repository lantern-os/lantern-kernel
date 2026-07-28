//! [`KernelState`]: every kernel object pool plus the scheduler, in one place.
//!
//! Per [ADR-0010](../../lantern-rfcs/adr/0010-kernel-concurrency-model.md), the
//! kernel is single-stack and non-reentrant, so kernel data needs no synchronization
//! primitive — ordinary `&mut KernelState` access, checked by the borrow checker, is
//! sufficient. The one real `unsafe` in this module ([`kernel_state`]) is exactly
//! that ADR's payoff: a single, justified unsafe cell access at the trap boundary,
//! plain safe Rust everywhere else. Handler functions take `&mut KernelState`
//! explicitly (dependency injection, not a global reach-for) so they stay unit
//! testable with an isolated, freshly constructed state.

use core::cell::UnsafeCell;

use lantern_hal::{Hal, Hardware, TrapFrame};

use crate::cap::{Capability, CNode, CPtr, TcbId};
use crate::error::SyscallError;
use crate::limits::{
    MAX_CNODES, MAX_ENDPOINTS, MAX_FRAMES, MAX_NOTIFICATIONS, MAX_SCHED_CONTEXTS, MAX_TCBS,
    MAX_UNTYPEDS, MAX_VSPACES,
};
use crate::object::{
    Endpoint, Frame, Notification, SavedContext, SchedulingContext, Tcb, ThreadState, Untyped, VSpace,
};
use crate::pool::Pool;
use crate::scheduler::Scheduler;

pub struct KernelState {
    pub cnodes: Pool<CNode, MAX_CNODES>,
    pub tcbs: Pool<Tcb, MAX_TCBS>,
    pub endpoints: Pool<Endpoint, MAX_ENDPOINTS>,
    pub notifications: Pool<Notification, MAX_NOTIFICATIONS>,
    pub untypeds: Pool<Untyped, MAX_UNTYPEDS>,
    pub sched_contexts: Pool<SchedulingContext, MAX_SCHED_CONTEXTS>,
    /// RFC-0008/ADR-0012.
    pub vspaces: Pool<VSpace, MAX_VSPACES>,
    /// RFC-0008/ADR-0012.
    pub frames: Pool<Frame, MAX_FRAMES>,
    pub scheduler: Scheduler,
}

impl KernelState {
    pub const fn new() -> Self {
        Self {
            cnodes: Pool::new(),
            tcbs: Pool::new(),
            endpoints: Pool::new(),
            notifications: Pool::new(),
            untypeds: Pool::new(),
            sched_contexts: Pool::new(),
            vspaces: Pool::new(),
            frames: Pool::new(),
            scheduler: Scheduler::new(),
        }
    }

    /// Directed handoff to a specific thread — the IPC fast path: a `Send`/`Signal`
    /// that finds a waiting receiver switches straight to it, bypassing the ready
    /// queue entirely (this is *the* latency-critical path RFC-0002's "Performance
    /// posture" names).
    ///
    /// **Precondition:** `next` must not currently be sitting in the ready queue
    /// (it should come from a wait structure this call is popping it out of — an
    /// endpoint's blocked queue, a `reply_to` link — never from
    /// [`Scheduler::has_ready`]/the ready queue itself). This method has no way to
    /// remove an arbitrary entry from the ready queue's FIFO, so calling it on a
    /// thread that's also ready would leave a dangling duplicate entry, later
    /// handed to some other still-blocked thread as if it were newly ready. Both
    /// real call sites (`ipc::call`, `ipc::reply`) satisfy this by construction.
    pub fn switch_to(&mut self, frame: &mut TrapFrame, next: TcbId) {
        self.save_current(frame);
        if let Some(tcb) = self.tcbs.get_mut(next.0 as usize) {
            tcb.context.restore_into(frame);
            tcb.state = ThreadState::Running;
            activate_if_paged(tcb);
        }
        self.scheduler.current = Some(next);
    }

    /// Blocks the current thread: the caller must already have set its `ThreadState`
    /// and enqueued it wherever it needs to wait *before* calling this. Switches to
    /// the next ready thread and returns `true`, or — if the ready queue is empty —
    /// makes no changes and returns `false`.
    ///
    /// Phase 1 has no idle thread (needs a boot-provided idle loop), so callers
    /// **must** check [`Scheduler::has_ready`] before committing to a block (setting
    /// state / pushing onto a wait queue) rather than relying on this to roll one
    /// back — this method does not undo the caller's bookkeeping on `false`.
    pub fn block_current(&mut self, frame: &mut TrapFrame) -> bool {
        if !self.scheduler.has_ready() {
            return false;
        }
        self.save_current(frame);
        self.scheduler.current = None;
        // has_ready() was just true and nothing else can run between the check and
        // this pop (single-stack, non-reentrant — ADR-0010), so this always succeeds.
        let next = self.scheduler.ready.pop_front().expect("ready queue was non-empty");
        if let Some(tcb) = self.tcbs.get_mut(next.0 as usize) {
            tcb.context.restore_into(frame);
            tcb.state = ThreadState::Running;
            activate_if_paged(tcb);
        }
        self.scheduler.current = Some(next);
        true
    }

    /// Re-enqueues `id` as ready. Used both to admit a newly configured thread and
    /// to wake a blocked one.
    pub fn make_ready(&mut self, id: TcbId) {
        if let Some(tcb) = self.tcbs.get_mut(id.0 as usize) {
            tcb.state = ThreadState::Ready;
        }
        self.scheduler.ready.push_back(id);
    }

    /// Resolves `cptr` in `thread`'s CSpace. `FailedLookup` if `cptr` is out of
    /// range or the thread has no CSpace configured yet; `InvalidCapability` if the
    /// slot is empty.
    pub fn lookup_cap(&self, thread: TcbId, cptr: CPtr) -> Result<Capability, SyscallError> {
        let tcb = self.tcbs.get(thread.0 as usize).ok_or(SyscallError::FailedLookup)?;
        let cspace_id = tcb.cspace.ok_or(SyscallError::FailedLookup)?;
        let cnode = self.cnodes.get(cspace_id.0 as usize).ok_or(SyscallError::FailedLookup)?;
        match cnode.get(cptr) {
            Some(Capability::Null) | None => Err(SyscallError::InvalidCapability),
            Some(cap) => Ok(cap),
        }
    }

    fn save_current(&mut self, frame: &TrapFrame) {
        if let Some(current) = self.scheduler.current {
            if let Some(tcb) = self.tcbs.get_mut(current.0 as usize) {
                tcb.context = SavedContext::save_from(frame);
            }
        }
    }
}

/// Activates `tcb`'s address space, if it has one. `None` (the default, and every
/// thread `KernelState`'s own unit tests construct) skips the `Hal` call entirely —
/// not even the `x86-64` no-op runs unless a thread actually has a real address
/// space, per `Tcb::address_space`'s own doc. `pub(crate)`: also used by
/// [`crate::enter_first_thread`], which needs the identical activate-before-entry
/// step for the very first thread.
pub(crate) fn activate_if_paged(tcb: &Tcb) {
    if let Some(root) = tcb.address_space {
        // SAFETY: `address_space`'s doc requires whoever set it (currently only
        // `lantern-boot`, which owns physical-memory/page-table construction) to
        // have built a valid table there.
        unsafe { Hardware::activate_address_space(root) };
    }
}

impl Default for KernelState {
    fn default() -> Self {
        Self::new()
    }
}

struct KernelStateCell(UnsafeCell<KernelState>);
// SAFETY: only ever accessed via `kernel_state`, which the kernel's single-stack,
// non-reentrant concurrency model (ADR-0010) guarantees is never called concurrently
// with itself.
unsafe impl Sync for KernelStateCell {}

static STATE: KernelStateCell = KernelStateCell(UnsafeCell::new(KernelState::new()));

/// # Safety
/// Must only be called from the real trap-time entry point
/// ([`crate::kernel_trap_handler`]), never from test code (which should construct
/// its own local `KernelState` instead) or anywhere that could run concurrently with
/// another call to this function.
pub unsafe fn kernel_state() -> &'static mut KernelState {
    // SAFETY: forwarded to the caller via this function's own safety contract.
    unsafe { &mut *STATE.0.get() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::CNodeId;

    fn spawn_ready(state: &mut KernelState) -> TcbId {
        let index = state.tcbs.alloc(Tcb::new()).unwrap();
        let id = TcbId(index as u16);
        state.make_ready(id);
        id
    }

    /// Makes `id` the running thread directly, without touching the ready queue —
    /// `switch_to`'s precondition (see its doc comment) is that its target isn't
    /// also sitting in the ready queue, so tests that just need *some* current
    /// thread established use this instead of `switch_to` itself.
    fn make_current(state: &mut KernelState, id: TcbId) {
        state.scheduler.current = Some(id);
        if let Some(tcb) = state.tcbs.get_mut(id.0 as usize) {
            tcb.state = ThreadState::Running;
        }
    }

    #[test]
    fn switch_to_saves_the_outgoing_thread_and_loads_the_incoming_one() {
        let mut state = KernelState::new();
        let a = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        let b = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        make_current(&mut state, a);

        let mut frame = TrapFrame::zeroed();
        frame.set_mr(0, 111); // simulate a running for a bit and setting mr0

        state.switch_to(&mut frame, b);
        assert_eq!(state.scheduler.current, Some(b));
        // b's own (zeroed) context was loaded, not a's leftover value.
        assert_eq!(frame.mr(0), 0);

        frame.set_mr(0, 222); // simulate b running for a bit and setting mr0

        // Switching back to a restores exactly what was saved when we left it
        // (111), not b's leftover (222).
        state.switch_to(&mut frame, a);
        assert_eq!(state.scheduler.current, Some(a));
        assert_eq!(frame.mr(0), 111);
    }

    #[test]
    fn block_current_refuses_when_nothing_else_is_ready() {
        let mut state = KernelState::new();
        let a = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        make_current(&mut state, a);

        let mut frame = TrapFrame::zeroed();
        assert!(!state.block_current(&mut frame));
        // current is left exactly as it was — no phantom switch happened.
        assert_eq!(state.scheduler.current, Some(a));
    }

    #[test]
    fn block_current_switches_to_the_next_ready_thread() {
        let mut state = KernelState::new();
        let a = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        make_current(&mut state, a);
        let b = spawn_ready(&mut state);

        let mut frame = TrapFrame::zeroed();
        assert!(state.block_current(&mut frame));
        assert_eq!(state.scheduler.current, Some(b));
    }

    #[test]
    fn cnode_pool_allocates_independently_of_tcb_pool() {
        let mut state = KernelState::new();
        let index = state.cnodes.alloc(CNode::empty()).unwrap();
        assert_eq!(CNodeId(index as u16), CNodeId(0));
    }
}
