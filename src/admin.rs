//! `UntypedRetype` and `TCBConfigure` — the "slow path" administrative operations.
//!
//! Both are real, working implementations, but each has a deliberate Phase 1 gap
//! documented on the relevant function: `UntypedRetype` carves objects from a
//! count-based budget rather than real physical memory (no `lantern-boot` yet), and
//! `TCBConfigure` cannot set a VSpace root (no HAL paging support yet).

use lantern_hal::TrapFrame;

use crate::abi;
use crate::cap::{Capability, CNode, CPtr, EndpointId, NotificationId, ObjectType, Rights, SchedContextId, TcbId};
use crate::error::SyscallError;
use crate::object::{Endpoint, Notification, SchedulingContext, Tcb, ThreadState};
use crate::state::KernelState;

/// Carves one new typed object out of an Untyped capability's budget and places a
/// full-rights capability to it in the caller's own CSpace.
///
/// **Phase 1 simplification:** real Untyped memory is byte-granular physical
/// memory; there is no physical memory map to carve from without `lantern-boot`
/// (see `lantern-kernel/STATUS.md`). [`crate::object::Untyped`] instead models a
/// plain object-count budget — this exercises the retype mechanism and its
/// capability bookkeeping for real, just not real memory accounting yet.
pub fn untyped_retype(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let untyped_id = match state.lookup_cap(current, cptr)? {
        Capability::Untyped { id, rights } if rights.contains(Rights::WRITE) => id,
        Capability::Untyped { .. } => return Err(SyscallError::IllegalOperation),
        _ => return Err(SyscallError::InvalidCapability),
    };
    let object_type = ObjectType::from_usize(frame.mr(1)).ok_or(SyscallError::InvalidArgument)?;
    let dest = frame.mr(2);

    // Validate everything before allocating anything, so a failure never leaves an
    // allocated pool slot with no capability pointing at it.
    let untyped = state.untypeds.get(untyped_id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    if untyped.remaining == 0 {
        return Err(SyscallError::NotEnoughMemory);
    }
    let cspace_id = state
        .tcbs
        .get(current.0 as usize)
        .and_then(|t| t.cspace)
        .ok_or(SyscallError::FailedLookup)?;
    {
        let cnode = state.cnodes.get(cspace_id.0 as usize).ok_or(SyscallError::FailedLookup)?;
        let dest_cap = cnode.get(dest).ok_or(SyscallError::RangeError)?;
        if dest_cap != Capability::Null {
            return Err(SyscallError::IllegalOperation);
        }
    }

    let new_cap = match object_type {
        ObjectType::CNode => {
            let idx = state.cnodes.alloc(CNode::empty()).ok_or(SyscallError::NotEnoughMemory)?;
            Capability::CNode(crate::cap::CNodeId(idx as u16))
        }
        ObjectType::Endpoint => {
            let idx = state.endpoints.alloc(Endpoint::new()).ok_or(SyscallError::NotEnoughMemory)?;
            Capability::Endpoint { id: EndpointId(idx as u16), badge: 0, rights: Rights::ALL }
        }
        ObjectType::Notification => {
            let idx = state.notifications.alloc(Notification::new()).ok_or(SyscallError::NotEnoughMemory)?;
            Capability::Notification { id: NotificationId(idx as u16), badge: 0, rights: Rights::ALL }
        }
        ObjectType::Tcb => {
            let idx = state.tcbs.alloc(Tcb::new()).ok_or(SyscallError::NotEnoughMemory)?;
            Capability::Tcb { id: TcbId(idx as u16), rights: Rights::ALL }
        }
        ObjectType::SchedContext => {
            let idx = state
                .sched_contexts
                .alloc(SchedulingContext::new(1))
                .ok_or(SyscallError::NotEnoughMemory)?;
            Capability::SchedContext { id: SchedContextId(idx as u16), rights: Rights::ALL }
        }
        // Untyped isn't a valid retype *target* (there's nothing to split a
        // count-based budget into) — matches seL4, where Untyped is always the
        // retype source, never the requested output type.
        ObjectType::Untyped => return Err(SyscallError::InvalidArgument),
    };

    // Neither of these can fail now: the destination slot was checked empty above
    // and nothing else could have touched it since (single-stack, non-reentrant —
    // ADR-0010).
    let cnode = state.cnodes.get_mut(cspace_id.0 as usize).expect("checked above");
    *cnode.slot_mut(dest).expect("checked above") = new_cap;
    state.untypeds.get_mut(untyped_id.0 as usize).expect("checked above").remaining -= 1;

    abi::reply_success(frame);
    Ok(())
}

/// Sets a thread's CSpace root and scheduling context, and admits it to the
/// scheduler the first time it's configured.
///
/// **Phase 1 gap:** does not (cannot yet) set a VSpace root — that needs HAL paging
/// support `lantern-hal/STATUS.md` doesn't have yet. A thread configured this way
/// has no address space; running actual user-mode code against it is future work.
pub fn configure(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let target = match state.lookup_cap(current, cptr)? {
        Capability::Tcb { id, rights } if rights.contains(Rights::WRITE) => id,
        Capability::Tcb { .. } => return Err(SyscallError::IllegalOperation),
        _ => return Err(SyscallError::InvalidCapability),
    };
    let cspace_id = match state.lookup_cap(current, frame.mr(1))? {
        Capability::CNode(id) => id,
        _ => return Err(SyscallError::InvalidCapability),
    };
    let sched_id = match state.lookup_cap(current, frame.mr(2))? {
        Capability::SchedContext { id, .. } => id,
        _ => return Err(SyscallError::InvalidCapability),
    };

    let was_inactive = {
        let tcb = state.tcbs.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
        let was_inactive = tcb.state == ThreadState::Inactive;
        tcb.cspace = Some(cspace_id);
        tcb.sched_context = Some(sched_id);
        was_inactive
    };
    if was_inactive {
        state.make_ready(target);
    }

    abi::reply_success(frame);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::CNodeId;
    use lantern_hal::MessageTag;

    fn frame_for(mr0: usize, mr1: usize, mr2: usize) -> TrapFrame {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(0, mr0);
        frame.set_mr(1, mr1);
        frame.set_mr(2, mr2);
        frame
    }

    fn setup_with_untyped(budget: usize) -> (KernelState, TcbId, CPtr, CPtr) {
        let mut state = KernelState::new();
        let cnode_idx = state.cnodes.alloc(CNode::empty()).unwrap();
        let cnode_id = CNodeId(cnode_idx as u16);
        let tcb_idx = state.tcbs.alloc(Tcb::new()).unwrap();
        let tcb_id = TcbId(tcb_idx as u16);
        state.tcbs.get_mut(tcb_idx).unwrap().cspace = Some(cnode_id);

        let untyped_idx = state.untypeds.alloc(crate::object::Untyped::new(budget)).unwrap();
        let untyped_cptr: CPtr = 1;
        *state.cnodes.get_mut(cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
            Capability::Untyped { id: crate::cap::UntypedId(untyped_idx as u16), rights: Rights::ALL };

        (state, tcb_id, untyped_cptr, 2 /* dest slot */)
    }

    #[test]
    fn retype_endpoint_places_a_full_rights_capability() {
        let (mut state, tcb, untyped_cptr, dest) = setup_with_untyped(2);
        let mut frame = frame_for(untyped_cptr, ObjectType::Endpoint as usize, dest);
        untyped_retype(&mut state, tcb, untyped_cptr, &mut frame).unwrap();

        let cnode = state.cnodes.get(0).unwrap();
        assert_eq!(
            cnode.get(dest),
            Some(Capability::Endpoint { id: EndpointId(0), badge: 0, rights: Rights::ALL })
        );
        assert_eq!(state.untypeds.get(0).unwrap().remaining, 1);
    }

    #[test]
    fn retype_exhausts_budget() {
        let (mut state, tcb, untyped_cptr, dest) = setup_with_untyped(1);
        let mut frame = frame_for(untyped_cptr, ObjectType::Endpoint as usize, dest);
        untyped_retype(&mut state, tcb, untyped_cptr, &mut frame).unwrap();

        let mut frame2 = frame_for(untyped_cptr, ObjectType::Endpoint as usize, dest + 1);
        assert_eq!(
            untyped_retype(&mut state, tcb, untyped_cptr, &mut frame2),
            Err(SyscallError::NotEnoughMemory)
        );
    }

    #[test]
    fn retype_into_occupied_slot_does_not_leak_a_pool_entry() {
        let (mut state, tcb, untyped_cptr, dest) = setup_with_untyped(2);
        // Occupy the destination first.
        *state.cnodes.get_mut(0).unwrap().slot_mut(dest).unwrap() =
            Capability::Endpoint { id: EndpointId(99), badge: 0, rights: Rights::ALL };

        let mut frame = frame_for(untyped_cptr, ObjectType::Endpoint as usize, dest);
        assert_eq!(
            untyped_retype(&mut state, tcb, untyped_cptr, &mut frame),
            Err(SyscallError::IllegalOperation)
        );
        // Budget untouched and nothing was allocated into the endpoint pool.
        assert_eq!(state.untypeds.get(0).unwrap().remaining, 2);
        assert_eq!(state.endpoints.len(), 0);
    }

    #[test]
    fn configure_admits_an_inactive_thread_to_the_ready_queue() {
        let mut state = KernelState::new();
        let admin_cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let admin_id = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(admin_id.0 as usize).unwrap().cspace = Some(CNodeId(admin_cnode as u16));

        let target_idx = state.tcbs.alloc(Tcb::new()).unwrap();
        let target = TcbId(target_idx as u16);
        let target_cspace = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let sched = state.sched_contexts.alloc(SchedulingContext::new(1)).unwrap();

        let cnode = state.cnodes.get_mut(admin_cnode).unwrap();
        *cnode.slot_mut(0).unwrap() = Capability::Tcb { id: target, rights: Rights::ALL };
        *cnode.slot_mut(1).unwrap() = Capability::CNode(target_cspace);
        *cnode.slot_mut(2).unwrap() =
            Capability::SchedContext { id: SchedContextId(sched as u16), rights: Rights::ALL };

        let mut frame = frame_for(0, 1, 2);
        configure(&mut state, admin_id, 0, &mut frame).unwrap();

        assert_eq!(state.tcbs.get(target_idx).unwrap().state, ThreadState::Ready);
        assert_eq!(state.tcbs.get(target_idx).unwrap().cspace, Some(target_cspace));
    }
}
