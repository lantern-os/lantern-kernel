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
/// Like `Copy`, but the source capability lives in a *different* CNode than the
/// invoked (destination) one — [RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)'s
/// administrative counterpart to `crate::ipc`'s live `extra_caps == 1` transfer.
/// See [`copy_cross`]'s doc for why these are two genuinely different
/// mechanisms, not one built on the other.
pub const LABEL_COPY_CROSS: u32 = 6;

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
        LABEL_COPY_CROSS => copy_cross(state, current, target, src, dest, arg3)?,
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
/// both into it. `rights`-only capability types (CNode/Tcb/Untyped/SchedContext/
/// VSpace/Frame) simply ignore the badge bits.
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
        Capability::VSpace { id, .. } => Capability::VSpace { id, rights },
        Capability::Frame { id, .. } => Capability::Frame { id, rights },
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

/// `CNodeInvoke::CopyCross` — copies a capability from `source_slot` in a
/// *different* CNode (`source_cnode`, a CPtr resolved in the **caller's own**
/// CSpace, distinct from `target`, the invoked/destination CNode from `mr0`)
/// into `target`'s `dest` slot.
///
/// **Why this exists alongside `crate::ipc`'s live `extra_caps == 1` transfer,
/// rather than loader code just using that instead:** live transfer needs an
/// already-running receiver to `Recv` with a registered destination slot — but
/// a receiver needs *some* capability (an endpoint, at minimum) to `Recv` on in
/// the first place. It cannot bootstrap a program's very first capability
/// (chicken-and-egg). `CopyCross` is the administrative operation that seeds
/// that first capability instead — the same role seL4's root-task CNode
/// manipulation plays. It's gated the same way ordinary same-CNode `Copy`
/// already is: holding a `Capability::CNode` is unrestricted read/write access
/// to everything in it (Phase 1's flat-CSpace model), for *both* CNodes named
/// here, not just one. This is real capability-checked administration, not a
/// pool poke — but it is not RFC-0010's `Rights::GRANT`-gated authority
/// transfer between mutually distrusting, already-running parties; conflating
/// the two would either weaken the live-transfer trust model or make bootstrap
/// impossible, so they stay two distinct mechanisms.
fn copy_cross(
    state: &mut KernelState,
    current: TcbId,
    target: CNodeId,
    source_cnode: CPtr,
    source_slot: usize,
    dest: usize,
) -> Result<(), SyscallError> {
    let source_id = match state.lookup_cap(current, source_cnode)? {
        Capability::CNode(id) => id,
        _ => return Err(SyscallError::InvalidCapability),
    };
    let source_cap = state
        .cnodes
        .get(source_id.0 as usize)
        .ok_or(SyscallError::InvalidCapability)?
        .get(source_slot)
        .ok_or(SyscallError::RangeError)?;
    if source_cap == Capability::Null {
        return Err(SyscallError::InvalidCapability);
    }

    let target_cnode = state.cnodes.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let dest_slot = target_cnode.slot_mut(dest).ok_or(SyscallError::RangeError)?;
    if *dest_slot != Capability::Null {
        return Err(SyscallError::IllegalOperation);
    }
    *dest_slot = source_cap;
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

    /// One thread, one CSpace (`cnode_a`, pool index 0), holding capabilities to
    /// *two* CNodes: a self-reference at slot 0 (`cnode_a` itself — `CopyCross`'s
    /// `source_cnode` argument) and a second, genuinely different CNode
    /// (`cnode_b`, pool index 1) at slot 1 (`CopyCross`'s invoked/destination
    /// argument, `mr0`). Returns `(state, tcb, dest_cptr, source_cnode_cptr)`.
    fn setup_cross() -> (KernelState, TcbId, CPtr, CPtr) {
        let mut state = KernelState::new();
        let cnode_a = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let cnode_b = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);

        let tcb_idx = state.tcbs.alloc(crate::object::Tcb::new()).unwrap();
        let tcb_id = TcbId(tcb_idx as u16);
        state.tcbs.get_mut(tcb_idx).unwrap().cspace = Some(cnode_a);

        *state.cnodes.get_mut(cnode_a.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(cnode_a);
        *state.cnodes.get_mut(cnode_a.0 as usize).unwrap().slot_mut(1).unwrap() = Capability::CNode(cnode_b);

        (state, tcb_id, 1, 0)
    }

    #[test]
    fn copy_cross_places_a_capability_from_a_different_cnode() {
        let (mut state, tcb, dest_cptr, source_cnode_cptr) = setup_cross();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 42, rights: Rights::ALL };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep; // cnode_a, slot 5

        let mut frame = frame_for(LABEL_COPY_CROSS, dest_cptr, source_cnode_cptr, 5, 9);
        invoke(&mut state, tcb, dest_cptr, &mut frame).unwrap();

        // Landed in cnode_b (pool index 1), slot 9.
        assert_eq!(state.cnodes.get(1).unwrap().get(9), Some(ep));
        // Source untouched -- this is a copy, not a move.
        assert_eq!(state.cnodes.get(0).unwrap().get(5), Some(ep));
    }

    #[test]
    fn copy_cross_into_an_occupied_destination_slot_is_rejected() {
        let (mut state, tcb, dest_cptr, source_cnode_cptr) = setup_cross();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;
        // cnode_b's slot 9 is already occupied by something.
        *state.cnodes.get_mut(1).unwrap().slot_mut(9).unwrap() = ep;

        let mut frame = frame_for(LABEL_COPY_CROSS, dest_cptr, source_cnode_cptr, 5, 9);
        assert_eq!(invoke(&mut state, tcb, dest_cptr, &mut frame), Err(SyscallError::IllegalOperation));
    }

    #[test]
    fn copy_cross_rejects_a_source_argument_that_is_not_a_cnode_capability() {
        let (mut state, tcb, dest_cptr, _source_cnode_cptr) = setup_cross();
        let ep = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        // Slot 1 in the caller's own CSpace names cnode_b, a real CNode -- but
        // not one holding a plain-capability source at slot 5, and slot 1's
        // target is what CopyCross's own `mr0` already claims as the
        // destination. Point `source_cnode` (mr1) at a slot that isn't a CNode
        // capability at all instead (slot 5, an Endpoint).
        *state.cnodes.get_mut(0).unwrap().slot_mut(5).unwrap() = ep;

        let mut frame = frame_for(LABEL_COPY_CROSS, dest_cptr, 5, 0, 9);
        assert_eq!(invoke(&mut state, tcb, dest_cptr, &mut frame), Err(SyscallError::InvalidCapability));
    }
}
