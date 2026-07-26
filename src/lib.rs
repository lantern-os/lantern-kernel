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
//! See `lantern-kernel/STATUS.md`. **Not yet exercised under QEMU** — every test
//! here runs on the host against a freshly constructed [`state::KernelState`];
//! nothing has driven this through a real trap yet, since that needs
//! `lantern-boot` to exist.
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
