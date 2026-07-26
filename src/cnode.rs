//! `CNodeInvoke`: `Mint`/`Copy`/`Move`/`Delete`/`Revoke`, dispatched on the message
//! tag's `label` — a Phase 1 kernel-internal convention (ADR-0008 leaves exact
//! `label` tables to implementation).
//!
//! All operations target slots *within a single CNode* named by `mr0`'s capability
//! (which must resolve to a `Capability::CNode`, per [`crate::abi`]'s `mr0`-is-CPtr
//! convention) — including administering a thread's own CSpace, which therefore
//! requires that thread to actually hold a capability to its own CNode, not an
//! ambient "you can always edit your own CSpace" exception. This keeps
//! self-administration inside the same "designation = authority" discipline as
//! everything else (RFC-0003).

use lantern_hal::TrapFrame;

use crate::abi;
use crate::cap::{Capability, CNodeId, CPtr, Rights, TcbId};
use crate::error::SyscallError;
use crate::state::KernelState;

pub const LABEL_MINT: u32 = 1;
pub const LABEL_COPY: u32 = 2;
pub const LABEL_MOVE: u32 = 3;
pub const LABEL_DELETE: u32 = 4;
pub const LABEL_REVOKE: u32 = 5;

pub fn invoke(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let target = match state.lookup_cap(current, cptr)? {
        Capability::CNode(id) => id,
        _ => return Err(SyscallError::InvalidCapability),
    };

    let label = frame.tag().label;
    let src = frame.mr(1);
    let dest = frame.mr(2);
    let arg3 = frame.mr(3);

    match label {
        LABEL_MINT => mint(state, target, src, dest, arg3)?,
        LABEL_COPY => copy(state, target, src, dest)?,
        LABEL_MOVE => move_cap(state, target, src, dest)?,
        LABEL_DELETE => delete(state, target, src)?,
        LABEL_REVOKE => {
            // Recursive revocation needs a capability-derivation tree Phase 1
            // doesn't track yet (RFC-0005 already named "revocation cost model" as
            // an open question) — refuse cleanly rather than silently no-op or
            // panic.
            return Err(SyscallError::IllegalOperation);
        }
        _ => return Err(SyscallError::InvalidArgument),
    }
    abi::reply_success(frame);
    Ok(())
}

/// `packed = (badge << 8) | rights_bits` — Mint needs two arguments (new rights,
/// new badge) but only has one payload word (`mr3`) free, so this convention packs
/// both into it. `rights`-only capability types (CNode/Tcb/Untyped/SchedContext)
/// simply ignore the badge bits.
fn mint(
    state: &mut KernelState,
    target: CNodeId,
    src: usize,
    dest: usize,
    packed: usize,
) -> Result<(), SyscallError> {
    let new_rights = Rights::from_bits_truncate((packed & 0xFF) as u8);
    let badge = (packed >> 8) as u64;

    let cnode = state.cnodes.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let source_cap = cnode.get(src).ok_or(SyscallError::RangeError)?;
    if source_cap == Capability::Null {
        return Err(SyscallError::InvalidCapability);
    }
    // Monotone attenuation (ADR-0005): mint may only narrow rights, never widen.
    if !new_rights.is_subset_of(source_cap.rights()) {
        return Err(SyscallError::IllegalOperation);
    }
    let minted = attenuate(source_cap, new_rights, badge)?;

    let dest_slot = cnode.slot_mut(dest).ok_or(SyscallError::RangeError)?;
    if *dest_slot != Capability::Null {
        return Err(SyscallError::IllegalOperation);
    }
    *dest_slot = minted;
    Ok(())
}

fn attenuate(source: Capability, rights: Rights, badge: u64) -> Result<Capability, SyscallError> {
    Ok(match source {
        Capability::Untyped { id, .. } => Capability::Untyped { id, rights },
        Capability::Endpoint { id, .. } => Capability::Endpoint { id, badge, rights },
        Capability::Notification { id, .. } => Capability::Notification { id, badge, rights },
        Capability::Tcb { id, .. } => Capability::Tcb { id, rights },
        Capability::SchedContext { id, .. } => Capability::SchedContext { id, rights },
        Capability::CNode(_) | Capability::Null | Capability::Reply { .. } => {
            return Err(SyscallError::IllegalOperation);
        }
    })
}

fn copy(state: &mut KernelState, target: CNodeId, src: usize, dest: usize) -> Result<(), SyscallError> {
    let cnode = state.cnodes.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let source_cap = cnode.get(src).ok_or(SyscallError::RangeError)?;
    if source_cap == Capability::Null {
        return Err(SyscallError::InvalidCapability);
    }
    let dest_slot = cnode.slot_mut(dest).ok_or(SyscallError::RangeError)?;
    if *dest_slot != Capability::Null {
        return Err(SyscallError::IllegalOperation);
    }
    *dest_slot = source_cap;
    Ok(())
}

fn move_cap(state: &mut KernelState, target: CNodeId, src: usize, dest: usize) -> Result<(), SyscallError> {
    let cnode = state.cnodes.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let source_cap = cnode.get(src).ok_or(SyscallError::RangeError)?;
    if source_cap == Capability::Null {
        return Err(SyscallError::InvalidCapability);
    }
    {
        let dest_slot = cnode.slot_mut(dest).ok_or(SyscallError::RangeError)?;
        if *dest_slot != Capability::Null {
            return Err(SyscallError::IllegalOperation);
        }
        *dest_slot = source_cap;
    }
    *cnode.slot_mut(src).expect("src was already validated above") = Capability::Null;
    Ok(())
}

/// Clears the slot. Does **not** reclaim the underlying pooled object even if this
/// was the capability's last reference — no reference counting yet (the same gap
/// that leaves `Revoke` stubbed). A Phase 1 prototype demo doesn't churn objects
/// enough for pool exhaustion to matter; tracked in `lantern-kernel/STATUS.md`.
fn delete(state: &mut KernelState, target: CNodeId, src: usize) -> Result<(), SyscallError> {
    let cnode = state.cnodes.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let slot = cnode.slot_mut(src).ok_or(SyscallError::RangeError)?;
    if *slot == Capability::Null {
        return Err(SyscallError::InvalidCapability);
    }
    *slot = Capability::Null;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CNode, EndpointId};

    fn setup() -> (KernelState, TcbId, CPtr) {
        let mut state = KernelState::new();
        let cnode_idx = state.cnodes.alloc(CNode::empty()).unwrap();
        let cnode_id = CNodeId(cnode_idx as u16);

        let tcb_idx = state.tcbs.alloc(crate::object::Tcb::new()).unwrap();
        let tcb_id = TcbId(tcb_idx as u16);
        state.tcbs.get_mut(tcb_idx).unwrap().cspace = Some(cnode_id);

        // Slot 0 of the thread's own CSpace holds a capability to that same CNode,
        // so it can administer itself (see the module doc).
        let self_cptr: CPtr = 0;
        *state.cnodes.get_mut(cnode_idx).unwrap().slot_mut(self_cptr).unwrap() = Capability::CNode(cnode_id);

        (state, tcb_id, self_cptr)
    }

    fn frame_for(label: u32, mr0: usize, mr1: usize, mr2: usize, mr3: usize) -> TrapFrame {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(lantern_hal::MessageTag { label, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(0, mr0);
        frame.set_mr(1, mr1);
        frame.set_mr(2, mr2);
        frame.set_mr(3, mr3);
        frame
    }

    #[test]
    fn copy_duplicates_a_capability() {
        let (mut state, tcb, self_cptr) = setup();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;

        let mut frame = frame_for(LABEL_COPY, self_cptr, 5, 6, 0);
        invoke(&mut state, tcb, self_cptr, &mut frame).unwrap();

        assert_eq!(state.cnodes.get(0).unwrap().get(5), Some(ep));
        assert_eq!(state.cnodes.get(0).unwrap().get(6), Some(ep));
    }

    #[test]
    fn move_relocates_and_clears_the_source() {
        let (mut state, tcb, self_cptr) = setup();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;

        let mut frame = frame_for(LABEL_MOVE, self_cptr, 5, 6, 0);
        invoke(&mut state, tcb, self_cptr, &mut frame).unwrap();

        assert_eq!(state.cnodes.get(0).unwrap().get(5), Some(Capability::Null));
        assert_eq!(state.cnodes.get(0).unwrap().get(6), Some(ep));
    }

    #[test]
    fn mint_narrows_rights_and_rejects_amplification() {
        let (mut state, tcb, self_cptr) = setup();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::READ.union(Rights::WRITE) };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;

        // Attempting to mint GRANT (which the source doesn't have) must fail.
        let mut frame = frame_for(LABEL_MINT, self_cptr, 5, 6, Rights::ALL.bits() as usize);
        assert_eq!(invoke(&mut state, tcb, self_cptr, &mut frame), Err(SyscallError::IllegalOperation));
        assert_eq!(state.cnodes.get(0).unwrap().get(6), Some(Capability::Null));

        // A strict subset succeeds.
        let mut frame = frame_for(LABEL_MINT, self_cptr, 5, 6, Rights::READ.bits() as usize);
        invoke(&mut state, tcb, self_cptr, &mut frame).unwrap();
        assert_eq!(
            state.cnodes.get(0).unwrap().get(6),
            Some(Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::READ })
        );
    }

    #[test]
    fn delete_clears_the_slot() {
        let (mut state, tcb, self_cptr) = setup();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;

        let mut frame = frame_for(LABEL_DELETE, self_cptr, 5, 0, 0);
        invoke(&mut state, tcb, self_cptr, &mut frame).unwrap();
        assert_eq!(state.cnodes.get(0).unwrap().get(5), Some(Capability::Null));
    }

    #[test]
    fn copy_into_occupied_slot_is_rejected() {
        let (mut state, tcb, self_cptr) = setup();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;
        *state.cnodes.get_mut(0).unwrap().slot_mut(6).unwrap() = ep;

        let mut frame = frame_for(LABEL_COPY, self_cptr, 5, 6, 0);
        assert_eq!(invoke(&mut state, tcb, self_cptr, &mut frame), Err(SyscallError::IllegalOperation));
    }

    #[test]
    fn revoke_is_cleanly_refused() {
        let (mut state, tcb, self_cptr) = setup();
        let mut frame = frame_for(LABEL_REVOKE, self_cptr, 5, 0, 0);
        assert_eq!(invoke(&mut state, tcb, self_cptr, &mut frame), Err(SyscallError::IllegalOperation));
    }
}
