//! A program's life — [RFC-0030](../../lantern-rfcs/rfcs/0030-process-lifecycle-faults-and-reclamation.md): building
//! a thread from user space, and ending it when it faults.
//!
//! **A fault ends the program, not the system.** The faulting thread is made `Inactive` and never resumed, its fault is
//! recorded for `ReadFault`, and its fault notification, if set, is signalled. A caller blocked waiting for its reply is
//! resumed with an error, so a crashed service can't hang its clients. Then the next thread runs.

use lantern_hal::{MessageTag, TrapFrame, FLAG_ERROR};

use crate::abi;
use crate::cap::{Capability, CPtr, Rights, TcbId};
use crate::error::SyscallError;
use crate::ipc::signal_notification;
use crate::object::{SavedContext, ThreadState};
use crate::state::KernelState;

/// `TcbInvoke`'s labels. `SET_ENTRY` takes `pc`, `sp` and `arg0` in `mr1` to `mr3`; `SET_FAULT_NOTIFICATION` the
/// notification's `CPtr` in `mr1`; `READ_FAULT` answers the cause and value in `mr1` and `mr2`, both 0 if it hasn't faulted.
pub const LABEL_SET_ENTRY: u32 = 1;
pub const LABEL_SET_FAULT_NOTIFICATION: u32 = 2;
pub const LABEL_READ_FAULT: u32 = 3;

/// `TcbInvoke`. `READ_FAULT` needs `READ`; the rest need `WRITE`.
pub fn invoke(state: &mut KernelState, current: TcbId, cptr: CPtr, frame: &mut TrapFrame) -> Result<(), SyscallError> {
    let (id, rights) = match state.lookup_cap(current, cptr)? {
        Capability::Tcb { id, rights } => (id, rights),
        _ => return Err(SyscallError::InvalidCapability),
    };
    let label = frame.tag().label;
    let needed = if label == LABEL_READ_FAULT { Rights::READ } else { Rights::WRITE };
    if !rights.contains(needed) {
        return Err(SyscallError::IllegalOperation);
    }
    match label {
        LABEL_SET_ENTRY => {
            let tcb = state.tcbs.get_mut(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
            // Only before it first runs: a running thread's registers are its own.
            if tcb.state != ThreadState::Inactive || tcb.fault.is_some() {
                return Err(SyscallError::IllegalOperation);
            }
            tcb.context = SavedContext::initial(frame.mr(1), frame.mr(2), frame.mr(3));
        }
        LABEL_SET_FAULT_NOTIFICATION => {
            let (notification, badge) = match state.lookup_cap(current, frame.mr(1))? {
                Capability::Notification { id, badge, rights } if rights.contains(Rights::WRITE) => (id, badge),
                Capability::Notification { .. } => return Err(SyscallError::IllegalOperation),
                _ => return Err(SyscallError::InvalidCapability),
            };
            if badge == 0 {
                return Err(SyscallError::InvalidArgument);
            }
            state.tcbs.get_mut(id.0 as usize).ok_or(SyscallError::InvalidCapability)?.fault_notification =
                Some((notification, badge));
        }
        LABEL_READ_FAULT => {
            let (cause, value) = state.tcbs.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?.fault.unwrap_or((0, 0));
            frame.set_mr(1, cause);
            frame.set_mr(2, value);
        }
        _ => return Err(SyscallError::InvalidArgument),
    }
    abi::reply_success(frame);
    Ok(())
}

/// The current thread faulted: end it, tell whoever asked to be told, and run the next thread. With nothing left to run,
/// the trap glue idles.
pub fn fault(state: &mut KernelState, frame: &mut TrapFrame, cause: usize, value: usize) {
    let Some(current) = state.scheduler.current else { return };
    let Some(tcb) = state.tcbs.get_mut(current.0 as usize) else { return };
    tcb.state = ThreadState::Inactive;
    tcb.fault = Some((cause, value));
    let notify = tcb.fault_notification;
    let owed = tcb.reply_to.take();
    if let Some(caller) = owed {
        fail_blocked(state, caller, SyscallError::InvalidCapability);
    }
    if let Some((notification, badge)) = notify {
        let _ = signal_notification(state, notification, badge);
    }
    state.block_current(frame);
}

/// Resumes a thread that was blocked on something that has gone, with `error` as its system call's result.
pub fn fail_blocked(state: &mut KernelState, id: TcbId, error: SyscallError) {
    let Some(tcb) = state.tcbs.get_mut(id.0 as usize) else { return };
    if matches!(tcb.state, ThreadState::Inactive | ThreadState::Ready | ThreadState::Running) {
        return;
    }
    tcb.context.set_mr(0, error.code());
    let tag = tcb.context.tag();
    tcb.context.set_tag(MessageTag { flags: tag.flags | FLAG_ERROR, ..tag });
    tcb.state = ThreadState::Inactive;
    state.make_ready(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CNode, CNodeId, NotificationId};
    use crate::object::{Notification, Tcb};

    const TCB_CPTR: CPtr = 1;
    const NOTIFICATION_CPTR: CPtr = 2;

    /// A parent, current, holding a capability to a child thread and a badged notification.
    fn setup(rights: Rights) -> (KernelState, TcbId, TcbId, NotificationId) {
        let mut state = KernelState::new();
        let cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let parent = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        let child = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(parent.0 as usize).unwrap().cspace = Some(CNodeId(cnode as u16));
        state.scheduler.current = Some(parent);
        let notification = NotificationId(state.notifications.alloc(Notification::new()).unwrap() as u16);
        let slots = state.cnodes.get_mut(cnode).unwrap();
        *slots.slot_mut(TCB_CPTR).unwrap() = Capability::Tcb { id: child, rights };
        *slots.slot_mut(NOTIFICATION_CPTR).unwrap() = Capability::Notification { id: notification, badge: 0b10, rights: Rights::ALL };
        (state, parent, child, notification)
    }

    fn call(state: &mut KernelState, parent: TcbId, label: u32, mrs: [usize; 3]) -> Result<[usize; 2], SyscallError> {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label, length: 0, extra_caps: 0, flags: 0 });
        for (i, &v) in mrs.iter().enumerate() {
            frame.set_mr(i + 1, v);
        }
        invoke(state, parent, TCB_CPTR, &mut frame).map(|()| [frame.mr(1), frame.mr(2)])
    }

    #[test]
    fn set_entry_is_refused_once_the_thread_has_run_or_faulted() {
        // The success path builds an architecture's initial frame, which only the `riscv64` HAL implements: it is
        // exercised under QEMU by `lantern-boot-lifecycle-demo`, which builds every child process with it.
        let (mut state, parent, child, _) = setup(Rights::ALL);
        state.tcbs.get_mut(child.0 as usize).unwrap().state = ThreadState::Ready;
        assert_eq!(call(&mut state, parent, LABEL_SET_ENTRY, [0, 0, 0]), Err(SyscallError::IllegalOperation));
        let tcb = state.tcbs.get_mut(child.0 as usize).unwrap();
        tcb.state = ThreadState::Inactive;
        tcb.fault = Some((2, 0));
        assert_eq!(call(&mut state, parent, LABEL_SET_ENTRY, [0, 0, 0]), Err(SyscallError::IllegalOperation), "a faulted thread");
    }

    #[test]
    fn a_fault_ends_the_thread_records_it_and_signals_the_parent() {
        let (mut state, parent, child, notification) = setup(Rights::ALL);
        call(&mut state, parent, LABEL_SET_FAULT_NOTIFICATION, [NOTIFICATION_CPTR, 0, 0]).unwrap();
        // The child runs, and faults; the parent is ready to run next.
        state.scheduler.current = Some(child);
        state.tcbs.get_mut(child.0 as usize).unwrap().state = ThreadState::Running;
        state.make_ready(parent);
        let mut frame = TrapFrame::zeroed();
        fault(&mut state, &mut frame, 13, 0xdead);
        assert_eq!(state.scheduler.current, Some(parent));
        assert_eq!(state.tcbs.get(child.0 as usize).unwrap().state, ThreadState::Inactive);
        assert_eq!(state.notifications.get(notification.0 as usize).unwrap().signals, 0b10);
        assert_eq!(call(&mut state, parent, LABEL_READ_FAULT, [0, 0, 0]), Ok([13, 0xdead]));
        assert_eq!(call(&mut state, parent, LABEL_SET_ENTRY, [0, 0, 0]), Err(SyscallError::IllegalOperation), "never resumed");
    }

    #[test]
    fn a_service_that_faults_mid_call_fails_its_caller_instead_of_hanging_it() {
        let (mut state, _, child, _) = setup(Rights::ALL);
        let client = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(client.0 as usize).unwrap().state = ThreadState::BlockedReply { dest_slot: None };
        let server = state.tcbs.get_mut(child.0 as usize).unwrap();
        server.state = ThreadState::Running;
        server.reply_to = Some(client);
        state.scheduler.current = Some(child);
        let mut frame = TrapFrame::zeroed();
        fault(&mut state, &mut frame, 15, 0);
        assert_eq!(state.scheduler.current, Some(client));
        assert!(frame.tag().is_error());
        assert_eq!(frame.mr(0), SyscallError::InvalidCapability.code());
    }

    #[test]
    fn rights_are_checked() {
        let (mut state, parent, _, _) = setup(Rights::READ);
        assert_eq!(call(&mut state, parent, LABEL_SET_ENTRY, [0, 0, 0]), Err(SyscallError::IllegalOperation));
        assert_eq!(call(&mut state, parent, LABEL_READ_FAULT, [0, 0, 0]), Ok([0, 0]));
    }

    // One `KernelState` per test: a debug build keeps several copies of it on the stack.
    #[test]
    fn badges_and_labels_are_checked() {
        let (mut state, parent, _, notification) = setup(Rights::ALL);
        let cnode = state.tcbs.get(parent.0 as usize).unwrap().cspace.unwrap();
        *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(NOTIFICATION_CPTR).unwrap() =
            Capability::Notification { id: notification, badge: 0, rights: Rights::ALL };
        assert_eq!(call(&mut state, parent, LABEL_SET_FAULT_NOTIFICATION, [NOTIFICATION_CPTR, 0, 0]), Err(SyscallError::InvalidArgument));
        assert_eq!(call(&mut state, parent, 9, [0, 0, 0]), Err(SyscallError::InvalidArgument));
    }
}
