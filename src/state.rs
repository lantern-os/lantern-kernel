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
    MAX_CNODES, MAX_ENDPOINTS, MAX_FRAMES, MAX_IRQ_ACTIONS, MAX_IRQ_HANDLERS, MAX_NOTIFICATIONS,
    MAX_SCHED_CONTEXTS, MAX_TCBS, MAX_UNTYPEDS, MAX_VSPACES,
};
use crate::irq::IrqAction;
use crate::object::{
    Endpoint, Frame, IrqHandler, KernelPageTables, Notification, SavedContext, SchedulingContext, Tcb,
    ThreadState, Untyped, VSpace,
};
use crate::queue::ArrayQueue;
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
    /// Real physical memory for `VSpace` roots and `FrameInvoke::Map`'s
    /// on-demand branch pages — see [`KernelPageTables`]'s own doc for why
    /// these can't come from the general-memory `Untyped` range `frames`
    /// above draws from.
    pub kernel_page_tables: KernelPageTables,
    pub scheduler: Scheduler,
    /// RFC-0027: the bound interrupt lines, and the controller actions waiting for the trap glue.
    pub irq_handlers: Pool<IrqHandler, MAX_IRQ_HANDLERS>,
    pub irq_actions: ArrayQueue<IrqAction, MAX_IRQ_ACTIONS>,
    /// The time slice: whose it is (`None` while idle, so the next thread to run starts a fresh one), when it ends, and
    /// what the hardware timer is armed for (`u64::MAX`: disarmed). The timer is armed lazily, at or before
    /// `slice_end`, so a switch costs a clock read and not a call into firmware (`crate::handle_trap`).
    pub timer_owner: Option<TcbId>,
    pub slice_end: u64,
    pub timer_armed: u64,
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
            kernel_page_tables: KernelPageTables::new(),
            scheduler: Scheduler::new(),
            irq_handlers: Pool::new(),
            irq_actions: ArrayQueue::new(),
            timer_owner: None,
            slice_end: 0,
            timer_armed: u64::MAX,
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
    /// and enqueued it wherever it needs to wait *before* calling this. Saves it, and
    /// switches to the next ready thread, returning `true`.
    ///
    /// With nothing ready it returns `false`, leaving **no current thread**. The trap
    /// glue then idles until an interrupt makes something ready
    /// ([RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md)).
    /// Before RFC-0027 this was refused instead, and callers had to check first.
    pub fn block_current(&mut self, frame: &mut TrapFrame) -> bool {
        self.save_current(frame);
        self.scheduler.current = None;
        self.resume_next(frame)
    }

    /// With no current thread, starts the next ready one: `true` if there was one.
    pub fn resume_next(&mut self, frame: &mut TrapFrame) -> bool {
        debug_assert!(self.scheduler.current.is_none(), "resume_next with a thread still current");
        let Some(next) = self.scheduler.ready.pop_front() else {
            return false;
        };
        if let Some(tcb) = self.tcbs.get_mut(next.0 as usize) {
            tcb.context.restore_into(frame);
            tcb.state = ThreadState::Running;
            activate_if_paged(tcb);
        }
        self.scheduler.current = Some(next);
        true
    }

    /// The timer's preemption point (RFC-0027): if another thread is ready, the current one goes to the back of the
    /// queue and the next one runs. `true` if that switched. Only ever reached from a trap taken in U-mode, so a
    /// system call is never cut short (ADR-0010).
    pub fn preempt(&mut self, frame: &mut TrapFrame) -> bool {
        let Some(current) = self.scheduler.current else {
            return false;
        };
        if !self.scheduler.has_ready() {
            return false;
        }
        self.make_ready(current);
        self.block_current(frame)
    }

    pub fn make_ready(&mut self, id: TcbId) {
        if let Some(tcb) = self.tcbs.get_mut(id.0 as usize) {
            if tcb.state == ThreadState::Ready {
                return;
            }
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
    fn make_ready_twice_enqueues_once() {
        // The configure-then-loader double `make_ready` (see `make_ready`'s doc): a
        // stale second entry must never exist to be popped after the thread blocks.
        let mut state = KernelState::new();
        let a = spawn_ready(&mut state);
        state.make_ready(a);

        assert_eq!(state.scheduler.ready.pop_front(), Some(a));
        assert!(!state.scheduler.has_ready(), "a second make_ready must not have queued a duplicate");

        // Once it has left `Ready` (popped to run, here), waking it again enqueues it
        // normally — idempotence is only for an already-queued thread.
        state.tcbs.get_mut(a.0 as usize).unwrap().state = ThreadState::Running;
        state.make_ready(a);
        assert_eq!(state.scheduler.ready.pop_front(), Some(a));
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
    fn blocking_with_nothing_ready_leaves_no_current_thread_and_resumes_on_wake() {
        let mut state = KernelState::new();
        let a = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        make_current(&mut state, a);

        let mut frame = TrapFrame::zeroed();
        frame.set_mr(0, 111);
        assert!(!state.block_current(&mut frame));
        assert_eq!(state.scheduler.current, None, "the trap glue idles now");
        assert!(!state.resume_next(&mut frame), "still nothing to run");

        // An interrupt wakes it: it resumes exactly as it was saved.
        state.make_ready(a);
        frame.set_mr(0, 999);
        assert!(state.resume_next(&mut frame));
        assert_eq!(state.scheduler.current, Some(a));
        assert_eq!(frame.mr(0), 111);
    }

    #[test]
    fn preemption_switches_only_when_another_thread_is_ready_and_requeues_the_current_one() {
        let mut state = KernelState::new();
        let a = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        make_current(&mut state, a);
        let mut frame = TrapFrame::zeroed();
        frame.set_mr(0, 111);
        assert!(!state.preempt(&mut frame), "alone, it keeps running");
        assert_eq!((state.scheduler.current, frame.mr(0)), (Some(a), 111));

        let b = spawn_ready(&mut state);
        assert!(state.preempt(&mut frame));
        assert_eq!(state.scheduler.current, Some(b));
        // And the slice after that goes back to `a`, with its registers intact.
        assert!(state.preempt(&mut frame));
        assert_eq!((state.scheduler.current, frame.mr(0)), (Some(a), 111));
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
