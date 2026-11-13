//! Deadlines and the clock — [RFC-0028](../../lantern-rfcs/rfcs/0028-deadlines-and-a-capability-clock.md).
//!
//! A [`Deadline`] signals a bound notification once, when the monotonic clock reaches an absolute time, and is the only way
//! a program can read that clock (`Now`): **time is a capability**. The kernel arms RFC-0027's timer for the earliest of
//! every armed deadline and the current slice's end ([`earliest`], `crate::handle_trap`), idle included.
//!
//! All of this is plain logic. The trap glue reads the clock once per trap into [`KernelState::now`], and calls
//! [`fire_expired`] after every trap, so an `Arm` for a time already past fires on the way out of that same call.

use lantern_hal::TrapFrame;

use crate::abi;
use crate::cap::{Capability, CPtr, DeadlineId, Rights, TcbId};
use crate::error::SyscallError;
use crate::ipc::signal_notification;
use crate::limits::MAX_DEADLINES;
use crate::object::Deadline;
use crate::state::KernelState;

/// `DeadlineInvoke`'s labels. `SET_NOTIFICATION` takes the notification's `CPtr` in `mr1`, `ARM` the time in `mr1`, and
/// `NOW` answers the time in `mr1`.
pub const LABEL_SET_NOTIFICATION: u32 = 1;
pub const LABEL_ARM: u32 = 2;
pub const LABEL_CANCEL: u32 = 3;
pub const LABEL_NOW: u32 = 4;

/// Creates a deadline: only the boot-time loader calls this (RFC-0028 has no other way to make one). `None` when the
/// pool is full.
pub fn create(state: &mut KernelState) -> Option<Capability> {
    let index = state.deadlines.alloc(Deadline::default())?;
    Some(Capability::Deadline { id: DeadlineId(index as u16), rights: Rights::ALL })
}

/// `DeadlineInvoke`. `NOW` needs `READ`; everything else needs `WRITE`.
pub fn invoke(state: &mut KernelState, current: TcbId, cptr: CPtr, frame: &mut TrapFrame) -> Result<(), SyscallError> {
    let (id, rights) = match state.lookup_cap(current, cptr)? {
        Capability::Deadline { id, rights } => (id, rights),
        _ => return Err(SyscallError::InvalidCapability),
    };
    let label = frame.tag().label;
    let needed = if label == LABEL_NOW { Rights::READ } else { Rights::WRITE };
    if !rights.contains(needed) {
        return Err(SyscallError::IllegalOperation);
    }
    let deadline = *state.deadlines.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let updated = match label {
        LABEL_SET_NOTIFICATION => {
            let (notification, badge) = match state.lookup_cap(current, frame.mr(1))? {
                Capability::Notification { id, badge, rights } if rights.contains(Rights::WRITE) => (id, badge),
                Capability::Notification { .. } => return Err(SyscallError::IllegalOperation),
                _ => return Err(SyscallError::InvalidCapability),
            };
            if badge == 0 {
                return Err(SyscallError::InvalidArgument);
            }
            Deadline { notification: Some((notification, badge)), ..deadline }
        }
        LABEL_ARM => {
            if deadline.notification.is_none() {
                return Err(SyscallError::IllegalOperation);
            }
            Deadline { at: Some(frame.mr(1) as u64), ..deadline }
        }
        LABEL_CANCEL => Deadline { at: None, ..deadline },
        LABEL_NOW => {
            frame.set_mr(1, state.now as usize);
            deadline
        }
        _ => return Err(SyscallError::InvalidArgument),
    };
    *state.deadlines.get_mut(id.0 as usize).expect("looked up above") = updated;
    abi::reply_success(frame);
    Ok(())
}

/// Signals every armed deadline whose time has come by `now`, earliest first, and disarms each. A deadline whose
/// notification has gone is simply disarmed.
pub fn fire_expired(state: &mut KernelState, now: u64) {
    while let Some((index, _)) = next_due(state, now) {
        let deadline = state.deadlines.get_mut(index).expect("found by next_due");
        deadline.at = None;
        if let Some((notification, badge)) = deadline.notification {
            let _ = signal_notification(state, notification, badge);
        }
    }
}

fn next_due(state: &KernelState, now: u64) -> Option<(usize, u64)> {
    (0..MAX_DEADLINES)
        .filter_map(|i| Some((i, state.deadlines.get(i)?.at?)))
        .filter(|&(_, at)| at <= now)
        .min_by_key(|&(_, at)| at)
}

/// The earliest armed deadline, if any.
pub fn earliest(state: &KernelState) -> Option<u64> {
    (0..MAX_DEADLINES).filter_map(|i| state.deadlines.get(i)?.at).min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CNode, CNodeId, NotificationId};
    use crate::object::{Notification, Tcb, ThreadState};
    use lantern_hal::MessageTag;

    const DEADLINE_CPTR: CPtr = 1;
    const NOTIFICATION_CPTR: CPtr = 2;

    fn setup(badge: u64, rights: Rights) -> (KernelState, TcbId, NotificationId) {
        let mut state = KernelState::new();
        let cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(CNodeId(cnode as u16));
        state.scheduler.current = Some(tcb);
        let Some(Capability::Deadline { id, .. }) = create(&mut state) else { panic!() };
        let notification = NotificationId(state.notifications.alloc(Notification::new()).unwrap() as u16);
        let slots = state.cnodes.get_mut(cnode).unwrap();
        *slots.slot_mut(DEADLINE_CPTR).unwrap() = Capability::Deadline { id, rights };
        *slots.slot_mut(NOTIFICATION_CPTR).unwrap() = Capability::Notification { id: notification, badge, rights: Rights::ALL };
        (state, tcb, notification)
    }

    fn call(state: &mut KernelState, tcb: TcbId, label: u32, mr1: usize) -> Result<usize, SyscallError> {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(1, mr1);
        invoke(state, tcb, DEADLINE_CPTR, &mut frame).map(|()| frame.mr(1))
    }

    fn signals(state: &KernelState, n: NotificationId) -> u64 {
        state.notifications.get(n.0 as usize).unwrap().signals
    }

    #[test]
    fn now_reads_the_clock_and_needs_only_read() {
        let (mut state, tcb, _) = setup(1, Rights::READ);
        state.now = 12345;
        assert_eq!(call(&mut state, tcb, LABEL_NOW, 0), Ok(12345));
        assert_eq!(call(&mut state, tcb, LABEL_ARM, 1), Err(SyscallError::IllegalOperation), "arming needs WRITE");
    }

    #[test]
    fn arming_needs_a_binding_with_a_nonzero_badge() {
        let (mut state, tcb, _) = setup(0, Rights::ALL);
        assert_eq!(call(&mut state, tcb, LABEL_ARM, 100), Err(SyscallError::IllegalOperation));
        assert_eq!(call(&mut state, tcb, LABEL_SET_NOTIFICATION, NOTIFICATION_CPTR), Err(SyscallError::InvalidArgument));
        assert_eq!(call(&mut state, tcb, 9, 0), Err(SyscallError::InvalidArgument));
    }

    #[test]
    fn a_deadline_fires_once_at_its_time_and_never_early() {
        let (mut state, tcb, n) = setup(0b10, Rights::ALL);
        call(&mut state, tcb, LABEL_SET_NOTIFICATION, NOTIFICATION_CPTR).unwrap();
        call(&mut state, tcb, LABEL_ARM, 500).unwrap();
        assert_eq!(earliest(&state), Some(500));
        fire_expired(&mut state, 499);
        assert_eq!(signals(&state, n), 0, "not early");
        fire_expired(&mut state, 500);
        assert_eq!(signals(&state, n), 0b10);
        assert_eq!(earliest(&state), None, "one-shot");
        state.notifications.get_mut(n.0 as usize).unwrap().signals = 0;
        fire_expired(&mut state, 10_000);
        assert_eq!(signals(&state, n), 0, "and only once");
    }

    #[test]
    fn rearming_replaces_and_cancel_disarms() {
        let (mut state, tcb, n) = setup(1, Rights::ALL);
        call(&mut state, tcb, LABEL_SET_NOTIFICATION, NOTIFICATION_CPTR).unwrap();
        call(&mut state, tcb, LABEL_ARM, 100).unwrap();
        call(&mut state, tcb, LABEL_ARM, 900).unwrap();
        fire_expired(&mut state, 500);
        assert_eq!(signals(&state, n), 0, "the earlier arming was replaced");
        call(&mut state, tcb, LABEL_CANCEL, 0).unwrap();
        fire_expired(&mut state, 1000);
        assert_eq!((signals(&state, n), earliest(&state)), (0, None));
        call(&mut state, tcb, LABEL_CANCEL, 0).unwrap();
    }

    #[test]
    fn a_waiter_wakes_with_the_badge_and_several_fire_in_order() {
        let (mut state, tcb, n) = setup(4, Rights::ALL);
        call(&mut state, tcb, LABEL_SET_NOTIFICATION, NOTIFICATION_CPTR).unwrap();
        let waiter = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(waiter.0 as usize).unwrap().state = ThreadState::BlockedWait(n);
        state.notifications.get_mut(n.0 as usize).unwrap().waiters.push_back(waiter);
        // A second deadline, earlier, on the same notification with the same badge.
        let Some(Capability::Deadline { id, .. }) = create(&mut state) else { panic!() };
        state.deadlines.get_mut(id.0 as usize).unwrap().notification = Some((n, 8));
        state.deadlines.get_mut(id.0 as usize).unwrap().at = Some(200);
        call(&mut state, tcb, LABEL_ARM, 300).unwrap();
        assert_eq!(earliest(&state), Some(200));
        fire_expired(&mut state, 1000);
        // The earlier one woke the waiter; the later one's bit waits in the notification.
        assert_eq!(state.tcbs.get(waiter.0 as usize).unwrap().context.mr(0), 8);
        assert_eq!(signals(&state, n), 4);
    }

    #[test]
    fn the_pool_bounds_how_many_exist() {
        let mut state = KernelState::new();
        for _ in 0..MAX_DEADLINES {
            assert!(create(&mut state).is_some());
        }
        assert!(create(&mut state).is_none());
    }
}
