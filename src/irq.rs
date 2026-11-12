//! Interrupt delivery — [RFC-0027](../../lantern-rfcs/rfcs/0027-interrupt-delivery-timer-and-idle.md), the kernel half
//! of [ADR-0004](../../lantern-rfcs/adr/0004-kernel-responsibilities-and-tcb-boundary.md)'s item 5.
//!
//! An [`IrqHandler`] binds one interrupt line to a `Notification`. On a claimed line, the kernel signals it and leaves
//! the line claimed, so it can't fire again until the driver's `Ack`. A storm then costs one delivery per
//! acknowledgement. The kernel never touches a device's own registers.
//!
//! **Nothing here touches the controller.** Invocations and deliveries queue [`IrqAction`]s on
//! [`KernelState::irq_actions`], and the trap glue (`crate::kernel_trap_handler`) applies them through the HAL. So
//! all of this is plain logic, tested on the host like the scheduler and IPC.

use lantern_hal::TrapFrame;

use crate::abi;
use crate::cap::{Capability, CPtr, IrqHandlerId, Rights, TcbId};
use crate::error::SyscallError;
use crate::ipc::signal_notification;
use crate::limits::MAX_IRQ_HANDLERS;
use crate::object::IrqHandler;
use crate::state::KernelState;

/// `IrqHandlerInvoke`'s labels. `SET_NOTIFICATION` takes the notification's `CPtr` in `mr1`.
pub const LABEL_SET_NOTIFICATION: u32 = 1;
pub const LABEL_CLEAR: u32 = 2;
pub const LABEL_ACK: u32 = 3;

/// What the trap glue does to the interrupt controller on the kernel's behalf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrqAction {
    Enable(u32),
    Disable(u32),
    /// Lets a claimed line interrupt again.
    Complete(u32),
}

/// Creates a handler for `line`: only the boot-time loader calls this (RFC-0027 has no `IrqControl` capability yet).
/// `None` for line 0, which means "no interrupt", for a line that already has one, or when the pool is full.
pub fn create(state: &mut KernelState, line: u16) -> Option<Capability> {
    if line == 0 || find(state, line as u32).is_some() {
        return None;
    }
    let index = state.irq_handlers.alloc(IrqHandler::new(line))?;
    Some(Capability::IrqHandler { id: IrqHandlerId(index as u16), rights: Rights::ALL })
}

fn find(state: &KernelState, line: u32) -> Option<usize> {
    (0..MAX_IRQ_HANDLERS).find(|&index| state.irq_handlers.get(index).is_some_and(|h| h.line as u32 == line))
}

/// A line the controller just handed over. A bound, unacknowledged-free handler signals its notification and keeps
/// the line claimed until `Ack`. Anything else is completed and disabled, so a line nobody handles goes quiet.
pub fn deliver(state: &mut KernelState, line: u32) {
    if let Some(index) = find(state, line) {
        let handler = *state.irq_handlers.get(index).expect("found above");
        match handler.notification {
            Some((notification, badge)) if !handler.pending && signal_notification(state, notification, badge).is_ok() => {
                state.irq_handlers.get_mut(index).expect("found above").pending = true;
                return;
            }
            // Delivered and not yet acknowledged: the controller shouldn't have offered it again. Keep it claimed.
            Some(_) if handler.pending => return,
            // Unbound, or its notification is gone.
            _ => {}
        }
    }
    queue(state, &[IrqAction::Disable(line), IrqAction::Complete(line)]);
}

/// `IrqHandlerInvoke`: `SET_NOTIFICATION`, `CLEAR` or `ACK`, by the tag's label. Every one needs `WRITE`.
pub fn invoke(state: &mut KernelState, current: TcbId, cptr: CPtr, frame: &mut TrapFrame) -> Result<(), SyscallError> {
    let id = match state.lookup_cap(current, cptr)? {
        Capability::IrqHandler { id, rights } if rights.contains(Rights::WRITE) => id,
        Capability::IrqHandler { .. } => return Err(SyscallError::IllegalOperation),
        _ => return Err(SyscallError::InvalidCapability),
    };
    let handler = *state.irq_handlers.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let line = handler.line as u32;
    // Room is checked first, so a failed invocation changes nothing.
    if state.irq_actions.len() + 2 > state.irq_actions.capacity() {
        return Err(SyscallError::NotEnoughMemory);
    }
    let updated = match frame.tag().label {
        LABEL_SET_NOTIFICATION => {
            let (notification, badge) = match state.lookup_cap(current, frame.mr(1))? {
                Capability::Notification { id, badge, rights } if rights.contains(Rights::WRITE) => (id, badge),
                Capability::Notification { .. } => return Err(SyscallError::IllegalOperation),
                _ => return Err(SyscallError::InvalidCapability),
            };
            if badge == 0 {
                return Err(SyscallError::InvalidArgument);
            }
            queue(state, &[IrqAction::Enable(line)]);
            IrqHandler { notification: Some((notification, badge)), ..handler }
        }
        LABEL_CLEAR => {
            queue(state, &[IrqAction::Disable(line)]);
            if handler.pending {
                queue(state, &[IrqAction::Complete(line)]);
            }
            IrqHandler { notification: None, pending: false, ..handler }
        }
        LABEL_ACK => {
            if handler.pending {
                queue(state, &[IrqAction::Complete(line)]);
            }
            IrqHandler { pending: false, ..handler }
        }
        _ => return Err(SyscallError::InvalidArgument),
    };
    *state.irq_handlers.get_mut(id.0 as usize).expect("looked up above") = updated;
    abi::reply_success(frame);
    Ok(())
}

fn queue(state: &mut KernelState, actions: &[IrqAction]) {
    for &action in actions {
        // Bounded by `MAX_IRQ_ACTIONS`, and drained after every trap. Losing one would leave a line claimed or
        // enabled, so overflowing is a kernel bug, not a runtime condition.
        let queued = state.irq_actions.push_back(action);
        debug_assert!(queued, "irq_actions overflowed: the trap glue must drain it after every trap");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CNode, CNodeId, NotificationId};
    use crate::object::{Notification, Tcb, ThreadState};
    use lantern_hal::MessageTag;

    const LINE: u16 = 10;
    const HANDLER_CPTR: CPtr = 1;
    const NOTIFICATION_CPTR: CPtr = 2;

    /// One thread, current, holding a handler for `LINE` and a badged notification.
    fn setup(badge: u64, irq_rights: Rights, ntfn_rights: Rights) -> (KernelState, TcbId, NotificationId) {
        let mut state = KernelState::new();
        let cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(CNodeId(cnode as u16));
        state.scheduler.current = Some(tcb);
        let Some(Capability::IrqHandler { id, .. }) = create(&mut state, LINE) else { panic!("created") };
        let notification = NotificationId(state.notifications.alloc(Notification::new()).unwrap() as u16);
        let slots = state.cnodes.get_mut(cnode).unwrap();
        *slots.slot_mut(HANDLER_CPTR).unwrap() = Capability::IrqHandler { id, rights: irq_rights };
        *slots.slot_mut(NOTIFICATION_CPTR).unwrap() = Capability::Notification { id: notification, badge, rights: ntfn_rights };
        (state, tcb, notification)
    }

    fn call(state: &mut KernelState, tcb: TcbId, label: u32) -> Result<(), SyscallError> {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(1, NOTIFICATION_CPTR);
        invoke(state, tcb, HANDLER_CPTR, &mut frame)
    }

    fn drain(state: &mut KernelState) -> std::vec::Vec<IrqAction> {
        let mut out = std::vec::Vec::new();
        while let Some(action) = state.irq_actions.pop_front() {
            out.push(action);
        }
        out
    }

    #[test]
    fn only_one_handler_per_line_and_never_for_line_zero() {
        let mut state = KernelState::new();
        assert!(create(&mut state, 0).is_none());
        assert!(create(&mut state, LINE).is_some());
        assert!(create(&mut state, LINE).is_none());
        for line in 1..MAX_IRQ_HANDLERS as u16 {
            assert!(create(&mut state, LINE + line).is_some());
        }
        assert!(create(&mut state, 99).is_none(), "pool full");
    }

    #[test]
    fn an_unbound_line_is_disabled_and_completed() {
        let (mut state, _, _) = setup(1, Rights::ALL, Rights::ALL);
        deliver(&mut state, LINE as u32);
        assert_eq!(drain(&mut state), [IrqAction::Disable(10), IrqAction::Complete(10)]);
        deliver(&mut state, 77);
        assert_eq!(drain(&mut state), [IrqAction::Disable(77), IrqAction::Complete(77)], "a line with no handler");
    }

    #[test]
    fn a_bound_line_signals_stays_claimed_until_ack_and_then_can_fire_again() {
        let (mut state, tcb, notification) = setup(0b100, Rights::ALL, Rights::ALL);
        call(&mut state, tcb, LABEL_SET_NOTIFICATION).unwrap();
        assert_eq!(drain(&mut state), [IrqAction::Enable(10)]);

        // A driver blocked in `Wait` wakes with the badge.
        let driver = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(driver.0 as usize).unwrap().state = ThreadState::BlockedWait(notification);
        state.notifications.get_mut(notification.0 as usize).unwrap().waiters.push_back(driver);
        deliver(&mut state, LINE as u32);
        assert!(drain(&mut state).is_empty(), "no Complete: the line stays claimed");
        assert_eq!(state.scheduler.ready.pop_front(), Some(driver));
        assert_eq!(state.tcbs.get(driver.0 as usize).unwrap().context.mr(0), 0b100);

        // A second delivery before `Ack` changes nothing.
        deliver(&mut state, LINE as u32);
        assert!(drain(&mut state).is_empty());
        assert_eq!(state.notifications.get(notification.0 as usize).unwrap().signals, 0);

        call(&mut state, tcb, LABEL_ACK).unwrap();
        assert_eq!(drain(&mut state), [IrqAction::Complete(10)]);
        call(&mut state, tcb, LABEL_ACK).unwrap();
        assert!(drain(&mut state).is_empty(), "nothing to complete twice");

        // With no waiter, the badge waits in the notification.
        deliver(&mut state, LINE as u32);
        assert_eq!(state.notifications.get(notification.0 as usize).unwrap().signals, 0b100);
    }

    #[test]
    fn clearing_a_pending_line_disables_and_completes_it() {
        let (mut state, tcb, _) = setup(1, Rights::ALL, Rights::ALL);
        call(&mut state, tcb, LABEL_SET_NOTIFICATION).unwrap();
        deliver(&mut state, LINE as u32);
        drain(&mut state);
        call(&mut state, tcb, LABEL_CLEAR).unwrap();
        assert_eq!(drain(&mut state), [IrqAction::Disable(10), IrqAction::Complete(10)]);
        deliver(&mut state, LINE as u32);
        assert_eq!(drain(&mut state), [IrqAction::Disable(10), IrqAction::Complete(10)], "unbound again");
    }

    #[test]
    fn binding_needs_write_on_both_and_a_nonzero_badge_and_a_refusal_changes_nothing() {
        for (badge, irq_rights, ntfn_rights, label, want) in [
            (0, Rights::ALL, Rights::ALL, LABEL_SET_NOTIFICATION, SyscallError::InvalidArgument),
            (1, Rights::ALL, Rights::READ, LABEL_SET_NOTIFICATION, SyscallError::IllegalOperation),
            (1, Rights::READ, Rights::ALL, LABEL_ACK, SyscallError::IllegalOperation),
            (1, Rights::ALL, Rights::ALL, 9, SyscallError::InvalidArgument),
        ] {
            let (mut state, tcb, _) = setup(badge, irq_rights, ntfn_rights);
            let before = *state.irq_handlers.get(0).unwrap();
            assert_eq!(call(&mut state, tcb, label), Err(want));
            assert!(drain(&mut state).is_empty(), "a refused invocation queues nothing");
            assert_eq!(*state.irq_handlers.get(0).unwrap(), before, "and leaves the handler as it was");
        }
    }
}
