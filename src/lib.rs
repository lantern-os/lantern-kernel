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
//! **Not yet implemented:** VSpace/Frame/IRQ-handler objects (need HAL paging/
//! interrupt-controller support that doesn't exist yet), an idle thread (needs a
//! boot-provided idle loop), and the capability-derivation tree `Revoke` needs.
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
pub mod ipc;
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
/// directly to `Hal::install_trap_handler`. Not exercised by any test in this crate
/// (doing so would need the global state genuinely live across calls the way tests
/// don't want) — see [`syscall::dispatch`] for the tested logic this just forwards
/// to.
pub fn kernel_trap_handler(frame: &mut lantern_hal::TrapFrame) {
    // SAFETY: this function *is* the kernel's trap entry point — by construction,
    // it is only ever invoked from `lantern-hal`'s trap context, which ADR-0010's
    // single-stack, non-reentrant model guarantees cannot call it concurrently
    // with itself.
    let state = unsafe { state::kernel_state() };
    syscall::dispatch(state, frame);
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
    state.scheduler.current = Some(id);
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
