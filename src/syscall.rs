//! The syscall table (ADR-0008's 12 entries, plus `FrameInvoke` added by
//! [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md))
//! and [`dispatch`], the real entry point: takes a fresh [`KernelState`] (or, at
//! the real trap boundary, the global one via [`crate::kernel_trap_handler`]) and
//! a live [`TrapFrame`], and does the syscall. Kept separate from
//! [`crate::kernel_state`]'s one `unsafe` cell access precisely so this — the
//! actual logic — stays unit testable with an isolated state.

use lantern_hal::TrapFrame;

use crate::abi;
use crate::error::SyscallError;
use crate::state::KernelState;
use crate::{admin, cnode, ipc};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum SyscallNumber {
    Send = 1,
    NBSend = 2,
    Recv = 3,
    Call = 4,
    Reply = 5,
    Signal = 6,
    Wait = 7,
    Poll = 8,
    CNodeInvoke = 9,
    UntypedRetype = 10,
    TCBConfigure = 11,
    Yield = 12,
    /// `Map`/`Unmap` — [RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
    /// [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md).
    FrameInvoke = 13,
}

impl SyscallNumber {
    pub const fn from_usize(n: usize) -> Option<Self> {
        Some(match n {
            1 => Self::Send,
            2 => Self::NBSend,
            3 => Self::Recv,
            4 => Self::Call,
            5 => Self::Reply,
            6 => Self::Signal,
            7 => Self::Wait,
            8 => Self::Poll,
            9 => Self::CNodeInvoke,
            10 => Self::UntypedRetype,
            11 => Self::TCBConfigure,
            12 => Self::Yield,
            13 => Self::FrameInvoke,
            _ => return None,
        })
    }
}

/// Voluntarily surrenders the remainder of the current scheduling-context budget
/// (ADR-0008's `Yield`). Re-enqueuing the caller before picking the next ready
/// thread means a solitary thread yielding with nothing else ready harmlessly
/// resumes itself — Phase 1's stand-in for a real idle thread (see
/// `lantern-kernel/STATUS.md`).
fn yield_now(state: &mut KernelState, current: crate::cap::TcbId, frame: &mut TrapFrame) {
    state.make_ready(current);
    // Just enqueued `current`, so the ready queue is never empty here.
    let switched = state.block_current(frame);
    debug_assert!(switched, "just enqueued current, so has_ready() must be true");
    abi::reply_success(frame);
}

/// The real dispatch logic. Callers at the actual trap boundary go through
/// [`crate::kernel_trap_handler`] instead, which supplies the global
/// [`KernelState`]; tests construct their own.
pub fn dispatch(state: &mut KernelState, frame: &mut TrapFrame) {
    let Some(current) = state.scheduler.current else {
        // No thread was running — Phase 1 has nothing meaningful to do (no
        // idle-thread infrastructure yet; see `lantern-kernel/STATUS.md`).
        return;
    };

    let Some(syscall) = SyscallNumber::from_usize(frame.syscall_number()) else {
        abi::reply_error(frame, SyscallError::IllegalOperation);
        return;
    };

    // Phase 1 convention (see `crate::abi`): the invoked capability's CPtr is mr0,
    // except for `Reply`, which is implicit and never reads it.
    let cptr = frame.mr(0);

    let result = match syscall {
        SyscallNumber::Send => ipc::send(state, current, cptr, frame, false),
        SyscallNumber::NBSend => ipc::send(state, current, cptr, frame, true),
        SyscallNumber::Recv => ipc::recv(state, current, cptr, frame),
        SyscallNumber::Call => ipc::call(state, current, cptr, frame),
        SyscallNumber::Reply => ipc::reply(state, current, frame),
        SyscallNumber::Signal => ipc::signal(state, current, cptr, frame),
        SyscallNumber::Wait => ipc::wait(state, current, cptr, frame),
        SyscallNumber::Poll => ipc::poll(state, current, cptr, frame),
        SyscallNumber::CNodeInvoke => cnode::invoke(state, current, cptr, frame),
        SyscallNumber::UntypedRetype => admin::untyped_retype(state, current, cptr, frame),
        SyscallNumber::TCBConfigure => admin::configure(state, current, cptr, frame),
        // `crate::frame`, fully qualified: `dispatch`'s own `frame: &mut TrapFrame`
        // parameter would otherwise shadow the module name.
        SyscallNumber::FrameInvoke => crate::frame::invoke(state, current, cptr, frame),
        SyscallNumber::Yield => {
            yield_now(state, current, frame);
            Ok(())
        }
    };

    if let Err(e) = result {
        abi::reply_error(frame, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CNode, CNodeId, Capability, EndpointId, Rights, TcbId};
    use crate::object::Tcb;

    #[test]
    fn full_call_recv_reply_round_trip() {
        let mut state = KernelState::new();
        let ep_idx = state.endpoints.alloc(crate::object::Endpoint::new()).unwrap();
        let ep = Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 42, rights: Rights::ALL };

        let client_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        *state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;
        let client = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(client.0 as usize).unwrap().cspace = Some(client_cnode);

        let server_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        *state.cnodes.get_mut(server_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;
        let server = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(server.0 as usize).unwrap().cspace = Some(server_cnode);

        // Run the server first: it Recvs on the endpoint with nobody sending yet,
        // so it blocks — and since the client is Ready, block_current succeeds.
        state.make_ready(client);
        state.scheduler.current = Some(server);
        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(SyscallNumber::Recv as usize);
        frame.set_mr(0, 1);
        dispatch(&mut state, &mut frame);
        assert_eq!(state.scheduler.current, Some(client));

        // The client is now running (having been switched to by the server's
        // block). It Calls the endpoint.
        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(SyscallNumber::Call as usize);
        frame.set_mr(0, 1);
        frame.set_mr(1, 111);
        dispatch(&mut state, &mut frame);
        // The server was blocked waiting to receive, so Call rendezvouses
        // immediately and switches straight to it.
        assert_eq!(state.scheduler.current, Some(server));
        assert_eq!(frame.mr(0), 42, "server sees the endpoint cap's badge");
        assert_eq!(frame.mr(1), 111, "payload delivered");
        assert!(!frame.tag().is_error());

        // The server replies.
        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(SyscallNumber::Reply as usize);
        frame.set_mr(1, 222);
        dispatch(&mut state, &mut frame);
        assert_eq!(state.scheduler.current, Some(client));
        assert_eq!(frame.mr(1), 222, "client sees the reply payload");
        assert!(!frame.tag().is_error());
    }

    #[test]
    fn unknown_syscall_number_returns_a_defined_error_not_a_panic() {
        let mut state = KernelState::new();
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.make_ready(tcb);
        state.scheduler.current = Some(tcb);

        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(999);
        dispatch(&mut state, &mut frame);
        assert!(frame.tag().is_error());
        assert_eq!(frame.mr(0), SyscallError::IllegalOperation.code());
    }

    #[test]
    fn invalid_capability_returns_an_error_and_current_thread_keeps_running() {
        let mut state = KernelState::new();
        let cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(cnode);
        state.make_ready(tcb);
        state.scheduler.current = Some(tcb);

        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(SyscallNumber::Send as usize);
        frame.set_mr(0, 0); // empty slot
        dispatch(&mut state, &mut frame);

        assert_eq!(state.scheduler.current, Some(tcb));
        assert!(frame.tag().is_error());
        assert_eq!(frame.mr(0), SyscallError::InvalidCapability.code());
    }

    #[test]
    fn yield_with_nothing_else_ready_resumes_the_same_thread() {
        let mut state = KernelState::new();
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.make_ready(tcb);
        state.scheduler.current = Some(tcb);

        let mut frame = TrapFrame::zeroed();
        frame.set_syscall_number(SyscallNumber::Yield as usize);
        dispatch(&mut state, &mut frame);

        assert_eq!(state.scheduler.current, Some(tcb));
        assert!(!frame.tag().is_error());
    }
}
