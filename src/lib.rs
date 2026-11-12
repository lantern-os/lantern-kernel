//! LanternOS microkernel — Phase 1 prototype ([RFC-0004](../../lantern-rfcs/rfcs/0004-phase-0-to-phase-1-transition.md)).
//!
//! This is the kernel's first real code, written against the design RFC-0005/
//! RFC-0006 and their ADRs (0008 syscall/IPC ABI, 0009 scheduling-context model,
//! 0010 concurrency model) fixed. It implements, for real:
//!
//! - The capability/rights model and (Phase 1: flat, single-level) CSpace
//!   ([`cap`]), per RFC-0003/ADR-0005/ADR-0006.
//! - The kernel object model — Untyped, CNode, TCB, Endpoint, Notification,
//!   SchedulingContext ([`object`]).
//! - A fixed-size TCB pool and minimal round-robin scheduler ([`state`],
//!   [`scheduler`]), with context switching implemented as swapping which
//!   thread's saved registers occupy `lantern_hal`'s single [`lantern_hal::TrapFrame`]
//!   before returning — no new HAL primitive needed, a direct consequence of
//!   ADR-0010's single-stack, run-to-completion model.
//! - The full IPC fast path ([`ipc`]): `Send`/`NBSend`/`Recv`/`Call`/`Reply` on
//!   endpoints, `Signal`/`Wait`/`Poll` on notifications — real synchronous
//!   rendezvous logic, since RFC-0005 names this the path "the whole system's
//!   latency budget depends on."
//! - `CNodeInvoke`'s `Mint`/`Copy`/`Move`/`Delete` ([`cnode`]), with monotone
//!   attenuation enforced on `Mint`. `Revoke` is cleanly refused (needs a
//!   capability-derivation tree this crate doesn't build yet).
//! - `UntypedRetype`/`TCBConfigure` ([`admin`]), each with a documented Phase 1 gap:
//!   `UntypedRetype` carves from a count-based budget, not real physical memory (no
//!   `lantern-boot` yet); `TCBConfigure` cannot set a VSpace root (no HAL paging
//!   support yet).
//!
//! **Interrupts, preemption and idle** ([RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md)):
//! [`irq`] delivers a line to a driver's notification, a 10 ms slice preempts a thread only from U-mode, and with
//! nothing ready the trap glue ([`handle_trap`]) waits for an interrupt with interrupts still masked.
//!
//! **Not yet implemented:** the capability-derivation tree `Revoke` needs, user-space timeouts, and priorities.
//! See `lantern-kernel/STATUS.md`.
//!
//! **Validated under real QEMU**, not just the host unit tests: `lantern-boot`'s
//! two-thread demo drives a full `Call`→`Recv`→`Reply` round trip through
//! [`kernel_trap_handler`]/[`enter_first_thread`] via real `riscv64` traps under
//! `qemu-system-riscv64`. That exercise caught a real bug in `lantern-hal`'s trap
//! trampoline (it only ever wrote back `mr0..mr3`/the tag, silently discarding
//! every context switch) that no unit test here could have found, since these
//! tests only ever construct a bare [`lantern_hal::TrapFrame`] directly — they
//! never go through `lantern-hal`'s actual trap-entry assembly at all.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod admin;
pub mod cap;
pub mod cnode;
pub mod error;
pub mod frame;
pub mod ipc;
pub mod irq;
pub mod limits;
pub mod object;
pub mod pool;
pub mod queue;
pub mod scheduler;
pub mod state;
pub mod syscall;

pub use error::SyscallError;
pub use syscall::{dispatch, SyscallNumber};

/// The real trap-time entry point: matches [`lantern_hal::TrapHandler`]'s exact
/// signature, so `lantern-boot`/whatever performs early kernel init can pass this
/// directly to `Hal::install_trap_handler`. The logic is [`handle_trap`], which the
/// tests run against a fake controller.
pub fn kernel_trap_handler(frame: &mut lantern_hal::TrapFrame) {
    // SAFETY: this function *is* the kernel's trap entry point — by construction,
    // it is only ever invoked from `lantern-hal`'s trap context, which ADR-0010's
    // single-stack, non-reentrant model guarantees cannot call it concurrently
    // with itself.
    let state = unsafe { state::kernel_state() };
    handle_trap::<lantern_hal::Hardware>(state, frame);
}

/// Most lines claimed in one trap, so a stuck controller can't hold the kernel.
const MAX_CLAIMS_PER_TRAP: usize = 8;

/// One trap, from U-mode ([RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md)): a system
/// call, a line to claim, or the timer. Then: apply what the kernel queued for the interrupt controller, idle if
/// nothing is left to run, and give a thread that has just started running, or whose slice ended, a full quantum.
///
/// **The timer is armed lazily.** A switch only records the new slice's end, which is always later than whatever the
/// hardware is still armed for. When the timer fires, the thread is preempted only if its own slice has really ended;
/// otherwise the timer is re-armed for that end. Re-arming on every switch instead cost an SBI call into firmware
/// each time, which nearly doubled an IPC round trip.
pub fn handle_trap<H: lantern_hal::Hal>(state: &mut state::KernelState, frame: &mut lantern_hal::TrapFrame) {
    use lantern_hal::TrapCause;

    let cause = frame.cause();
    match cause {
        TrapCause::Syscall => syscall::dispatch(state, frame),
        TrapCause::ExternalInterrupt => claim_pending::<H>(state),
        TrapCause::TimerInterrupt => {
            state.timer_armed = u64::MAX;
            if H::monotonic_time_ns() >= state.slice_end {
                state.preempt(frame);
                // Whoever runs next, even the same thread when nothing else is ready, starts a fresh slice.
                state.timer_owner = None;
            }
        }
    }
    apply_irq_actions::<H>(state);
    if state.scheduler.current.is_none() {
        idle::<H>(state, frame);
    }
    if state.timer_owner != state.scheduler.current {
        state.slice_end = H::monotonic_time_ns().saturating_add(limits::QUANTUM_NS);
        state.timer_owner = state.scheduler.current;
    }
    if state.timer_armed > state.slice_end {
        arm_timer::<H>(state);
    }
}

fn claim_pending<H: lantern_hal::Hal>(state: &mut state::KernelState) {
    for _ in 0..MAX_CLAIMS_PER_TRAP {
        let line = H::interrupt_claim();
        if line == 0 {
            return;
        }
        irq::deliver(state, line);
        apply_irq_actions::<H>(state);
    }
}

fn apply_irq_actions<H: lantern_hal::Hal>(state: &mut state::KernelState) {
    while let Some(action) = state.irq_actions.pop_front() {
        match action {
            irq::IrqAction::Enable(line) => H::interrupt_line_enable(line, true),
            irq::IrqAction::Disable(line) => H::interrupt_line_enable(line, false),
            irq::IrqAction::Complete(line) => H::interrupt_complete(line),
        }
    }
}

fn arm_timer<H: lantern_hal::Hal>(state: &mut state::KernelState) {
    H::set_timer(state.slice_end);
    state.timer_armed = state.slice_end;
}

/// Nothing is ready: wait for an interrupt with interrupts still masked, deliver it, and start whatever it made ready.
/// The timer is disarmed while idle, since there's nothing to preempt, so it can't keep waking the hart.
fn idle<H: lantern_hal::Hal>(state: &mut state::KernelState, frame: &mut lantern_hal::TrapFrame) {
    H::set_timer(u64::MAX);
    state.timer_armed = u64::MAX;
    state.timer_owner = None;
    while !state.resume_next(frame) {
        H::wait_for_interrupt();
        claim_pending::<H>(state);
        if H::timer_pending() {
            H::set_timer(u64::MAX);
        }
    }
}

/// Cold-starts `id` as the very first thread this hart ever runs. Boot code (never
/// `dispatch` itself — there's no trap in progress at this point) calls this
/// exactly once, after populating `id`'s capabilities/context via
/// [`state::kernel_state`] directly. Every thread started *after* this one needs
/// no special handling: as long as something is already inside a real trap when a
/// switch happens (as any second thread necessarily is, since the first thread had
/// to trap for anything else to run), the normal trap-return path resumes it —
/// only the very first thread has no trap in progress to piggyback on.
///
/// # Safety
/// Same contract as [`lantern_hal::Hal::enter_thread`]: `id` must name a thread
/// with a validly populated `context` (a real entry point, a real, mapped stack),
/// and this must be the first and only call to this function on this hart.
pub unsafe fn enter_first_thread(id: cap::TcbId) -> ! {
    use lantern_hal::Hal;

    // SAFETY: forwarded from this function's own contract — called once, before
    // any trap, by boot code that owns exclusive access at this point.
    let state = unsafe { state::kernel_state() };
    // A thread this function is about to run directly may already be sitting
    // in the ready queue — `admin::configure` (`TCBConfigure`) auto-enqueues
    // any thread that just left `Inactive`, and this function doesn't go
    // through `make_ready`/`block_current`'s own bookkeeping to undo that.
    // Left alone, the thread would be both `current` *and* ready — the exact
    // hazard `KernelState::switch_to`'s doc warns against: the first time it
    // later blocks, `block_current` can pop this same stale entry right back
    // off the queue and treat that as a completed switch, silently dropping
    // whatever real switch should have happened instead. See
    // `lantern-kernel/STATUS.md`'s "IPC round-trip loss" entry.
    state.scheduler.remove_ready(id);
    state.scheduler.current = Some(id);
    // RFC-0027: from here on, the PLIC's lines and the timer interrupt U-mode. Lines a loader bound before this are
    // enabled now, and the first thread gets a full quantum.
    // SAFETY: the trap handler is installed (boot does that before loading anything), and no thread has run yet.
    unsafe { lantern_hal::Hardware::init_interrupts() };
    apply_irq_actions::<lantern_hal::Hardware>(state);
    state.slice_end = lantern_hal::Hardware::monotonic_time_ns().saturating_add(limits::QUANTUM_NS);
    state.timer_owner = Some(id);
    arm_timer::<lantern_hal::Hardware>(state);
    let mut frame = lantern_hal::TrapFrame::zeroed();
    if let Some(tcb) = state.tcbs.get_mut(id.0 as usize) {
        tcb.state = object::ThreadState::Running;
        tcb.context.restore_into(&mut frame);
        state::activate_if_paged(tcb);
    }
    // SAFETY: `frame` was just populated from `id`'s own saved context; the rest
    // of this function's contract is this function's own, forwarded from the
    // caller.
    unsafe { lantern_hal::Hardware::enter_thread(&frame) }
}

#[cfg(test)]
mod tests {
    //! [`handle_trap`] against a fake interrupt controller and timer, which records every call the kernel makes.

    use std::cell::RefCell;
    use std::vec::Vec;

    use lantern_hal::{Hal, MessageTag, TrapCause, TrapFrame, TrapHandler};

    use super::*;
    use crate::cap::{CNode, CNodeId, Capability, NotificationId, Rights, TcbId};
    use crate::object::{Notification, Tcb, ThreadState};

    #[derive(Default)]
    struct Fake {
        claims: Vec<u32>,
        calls: Vec<String>,
        now: u64,
        timer_pending: bool,
        /// What `wait_for_interrupt` makes pending: one line per wait.
        on_wait: Vec<u32>,
    }

    thread_local! {
        static FAKE: RefCell<Fake> = RefCell::new(Fake::default());
    }

    fn fake<R>(f: impl FnOnce(&mut Fake) -> R) -> R {
        FAKE.with(|cell| f(&mut cell.borrow_mut()))
    }

    struct FakeHal;

    impl Hal for FakeHal {
        unsafe fn install_trap_handler(_: TrapHandler) {}
        fn initial_trap_frame(_: usize, _: usize, _: usize) -> TrapFrame {
            TrapFrame::zeroed()
        }
        unsafe fn enter_thread(_: &TrapFrame) -> ! {
            unreachable!()
        }
        unsafe fn activate_address_space(_: usize) {}
        fn monotonic_time_ns() -> u64 {
            fake(|f| f.now)
        }
        unsafe fn init_interrupts() {}
        fn interrupt_line_enable(line: u32, enabled: bool) {
            fake(|f| f.calls.push(format!("enable {line} {enabled}")));
        }
        fn interrupt_claim() -> u32 {
            fake(|f| if f.claims.is_empty() { 0 } else { f.claims.remove(0) })
        }
        fn interrupt_complete(line: u32) {
            fake(|f| f.calls.push(format!("complete {line}")));
        }
        fn set_timer(deadline: u64) {
            fake(|f| {
                f.timer_pending = false;
                f.calls.push(if deadline == u64::MAX { "disarm".into() } else { format!("arm {deadline}") })
            });
        }
        fn timer_pending() -> bool {
            fake(|f| f.timer_pending)
        }
        fn wait_for_interrupt() {
            fake(|f| {
                assert!(f.calls.iter().filter(|c| *c == "wait").count() < 10, "idle never woke");
                f.calls.push("wait".into());
                if !f.on_wait.is_empty() {
                    let line = f.on_wait.remove(0);
                    f.claims.push(line);
                }
            });
        }
    }

    fn calls() -> Vec<String> {
        fake(|f| std::mem::take(&mut f.calls))
    }

    const NOTIFICATION_CPTR: usize = 1;

    /// A driver thread holding a notification, and the handler for line 10 bound to it with badge 1.
    fn driver(state: &mut state::KernelState) -> (TcbId, NotificationId) {
        let cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(CNodeId(cnode as u16));
        let notification = NotificationId(state.notifications.alloc(Notification::new()).unwrap() as u16);
        *state.cnodes.get_mut(cnode).unwrap().slot_mut(NOTIFICATION_CPTR).unwrap() =
            Capability::Notification { id: notification, badge: 1, rights: Rights::ALL };
        let Some(Capability::IrqHandler { id, .. }) = irq::create(state, 10) else { panic!() };
        state.irq_handlers.get_mut(id.0 as usize).unwrap().notification = Some((notification, 1));
        (tcb, notification)
    }

    /// `tcb` is running, in a slice ending at `slice_end`, with the timer armed for it.
    fn running(state: &mut state::KernelState, tcb: TcbId, slice_end: u64) {
        state.scheduler.current = Some(tcb);
        state.timer_owner = Some(tcb);
        state.slice_end = slice_end;
        state.timer_armed = slice_end;
    }

    fn syscall(number: SyscallNumber, cptr: usize) -> TrapFrame {
        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(number as usize);
        frame.set_mr(0, cptr);
        frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 0, flags: 0 });
        frame
    }

    #[test]
    fn a_driver_waiting_alone_idles_until_its_line_fires_then_runs_with_a_fresh_quantum() {
        fake(|f| *f = Fake { now: 1000, on_wait: vec![0, 10], ..Fake::default() });
        let mut state = state::KernelState::new();
        let (tcb, _) = driver(&mut state);
        running(&mut state, tcb, 2000);

        let mut frame = syscall(SyscallNumber::Wait, NOTIFICATION_CPTR);
        handle_trap::<FakeHal>(&mut state, &mut frame);

        // Disarmed while idle; woke once for nothing, then for line 10, which stays claimed (no `complete`).
        assert_eq!(calls(), ["disarm", "wait", "wait", "arm 10001000"]);
        assert_eq!(state.scheduler.current, Some(tcb));
        assert_eq!(frame.mr(0), 1, "woke with its badge");
        assert_eq!(state.timer_owner, Some(tcb));
    }

    #[test]
    fn a_line_nobody_handles_is_disabled_and_completed() {
        fake(|f| *f = Fake { claims: vec![33], ..Fake::default() });
        let mut state = state::KernelState::new();
        let (tcb, _) = driver(&mut state);
        running(&mut state, tcb, 2000);
        let mut frame = TrapFrame::zeroed();
        frame.set_cause(TrapCause::ExternalInterrupt);
        handle_trap::<FakeHal>(&mut state, &mut frame);
        assert_eq!(calls(), ["enable 33 false", "complete 33"], "and the running thread keeps its slice");
    }

    #[test]
    fn the_timer_preempts_only_at_the_end_of_the_slice_and_only_if_another_thread_is_ready() {
        const Q: u64 = limits::QUANTUM_NS;
        fake(|f| *f = Fake { now: 100, ..Fake::default() });
        let mut state = state::KernelState::new();
        let a = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(a.0 as usize).unwrap().state = ThreadState::Running;
        running(&mut state, a, 100);
        let b = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.make_ready(b);
        let mut frame = TrapFrame::zeroed();
        frame.set_cause(TrapCause::TimerInterrupt);

        // Early, as after a switch that kept a previous slice's deadline: no preemption, re-armed for the real end.
        state.slice_end = 500;
        handle_trap::<FakeHal>(&mut state, &mut frame);
        assert_eq!((state.scheduler.current, calls()), (Some(a), vec!["arm 500".to_string()]));

        // At the end: `b` runs, with a fresh slice, and `a` goes to the back.
        fake(|f| f.now = 500);
        handle_trap::<FakeHal>(&mut state, &mut frame);
        assert_eq!((state.scheduler.current, calls()), (Some(b), vec![format!("arm {}", 500 + Q)]));
        assert_eq!(state.scheduler.ready.pop_front(), Some(a));

        // Alone at the end of its slice: it keeps running, with a fresh one.
        fake(|f| f.now = 500 + Q);
        handle_trap::<FakeHal>(&mut state, &mut frame);
        assert_eq!((state.scheduler.current, calls()), (Some(b), vec![format!("arm {}", 500 + 2 * Q)]));
    }

    #[test]
    fn a_switch_on_a_system_call_starts_a_fresh_slice_without_reprogramming_the_timer() {
        fake(|f| *f = Fake { now: 7000, ..Fake::default() });
        let mut state = state::KernelState::new();
        let (driver, _) = driver(&mut state);
        let other = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.make_ready(other);
        running(&mut state, driver, 2000);
        // The driver waits; `other` runs, with a slice ending a full quantum from now. The timer, still armed for
        // 2000, will fire early and be re-armed then: no firmware call on the switch itself.
        let mut frame = syscall(SyscallNumber::Wait, NOTIFICATION_CPTR);
        handle_trap::<FakeHal>(&mut state, &mut frame);
        assert_eq!(state.scheduler.current, Some(other));
        assert!(calls().is_empty(), "a switch must not call set_timer");
        assert_eq!((state.slice_end, state.timer_armed), (7000 + limits::QUANTUM_NS, 2000));
    }

    #[test]
    fn a_system_call_that_keeps_the_same_thread_running_keeps_its_slice() {
        fake(|f| *f = Fake::default());
        let mut state = state::KernelState::new();
        let (tcb, _) = driver(&mut state);
        running(&mut state, tcb, 2000);
        let mut frame = syscall(SyscallNumber::Poll, NOTIFICATION_CPTR);
        handle_trap::<FakeHal>(&mut state, &mut frame);
        assert!(calls().is_empty(), "no re-arm, so a thread can't extend its slice by making system calls");
    }
}
