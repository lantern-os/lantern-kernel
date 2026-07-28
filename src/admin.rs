//! `UntypedRetype` and `TCBConfigure` — the "slow path" administrative operations.
//!
//! Both are real, working implementations. `UntypedRetype` carves
//! `CNode`/`Endpoint`/`Notification`/`Tcb`/`SchedContext` from a plain count-based
//! budget (still no general physical memory map — `lantern-kernel/STATUS.md`), but
//! `VSpace`/`FrameSmall`/`FrameMega` from a *real* physical bump range a source
//! Untyped may additionally carry (RFC-0008/ADR-0012, `crate::object::Untyped`'s
//! own doc). `TCBConfigure` can now set a VSpace root, via a real capability
//! (same RFC) — the "no HAL paging support yet" gap this comment used to describe
//! is what that RFC closed.

use lantern_hal::TrapFrame;

use crate::abi;
use crate::cap::{
    Capability, CNode, CPtr, EndpointId, FrameId, NotificationId, ObjectType, Rights, SchedContextId,
    TcbId, VSpaceId,
};
use crate::error::SyscallError;
use crate::object::{Endpoint, Frame, FrameSize, Notification, SchedulingContext, Tcb, ThreadState, VSpace};
use crate::state::KernelState;

/// Carves one new typed object out of an Untyped capability's budget and places a
/// full-rights capability to it in the caller's own CSpace.
///
/// **Phase 1 simplification:** most object types carve from a plain object-count
/// budget, not real physical memory (see `crate::object::Untyped`'s doc) — this
/// exercises the retype mechanism and its capability bookkeeping for real, just
/// not real memory accounting for those types. `VSpace`/`Frame*` are the
/// exception: they always carve from a real physical range, since they *name*
/// physical memory rather than just occupying a kernel pool slot.
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
        ObjectType::VSpace => {
            let untyped = state.untypeds.get_mut(untyped_id.0 as usize).expect("checked above");
            let root = untyped
                .bump(lantern_hal::RISCV64_PAGE_SIZE, lantern_hal::RISCV64_PAGE_SIZE)
                .ok_or(SyscallError::NotEnoughMemory)?;
            let idx = state.vspaces.alloc(VSpace { root, source: untyped_id }).ok_or(SyscallError::NotEnoughMemory)?;
            Capability::VSpace { id: VSpaceId(idx as u16), rights: Rights::ALL }
        }
        ObjectType::FrameSmall | ObjectType::FrameMega => {
            let size = if object_type == ObjectType::FrameSmall { FrameSize::Small } else { FrameSize::Mega };
            let untyped = state.untypeds.get_mut(untyped_id.0 as usize).expect("checked above");
            let paddr = untyped.bump(size.bytes(), size.bytes()).ok_or(SyscallError::NotEnoughMemory)?;
            let idx =
                state.frames.alloc(Frame { paddr, size, mapped_at: None }).ok_or(SyscallError::NotEnoughMemory)?;
            Capability::Frame { id: FrameId(idx as u16), rights: Rights::ALL }
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

/// Sets a thread's CSpace root, scheduling context, and (optionally) VSpace root,
/// and admits it to the scheduler the first time it's configured.
///
/// `mr3` is `0` for a thread that stays kernel-resident with no address space of
/// its own (unchanged `Tcb::address_space: None` meaning — RFC-0008/ADR-0012),
/// or a VSpace capability (WRITE required) otherwise. `0` is a real sentinel, not
/// "whatever's in slot 0": CNode slot 0 is left free by convention project-wide
/// (see `lantern-boot/demo.rs`), so a caller that actually wants no VSpace passes
/// the literal argument `0` rather than relying on slot 0 happening to be empty
/// — a mistyped nonzero cptr still fails loudly instead of silently becoming
/// "no VSpace."
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
    let vspace_arg = frame.mr(3);
    let address_space = if vspace_arg == 0 {
        None
    } else {
        match state.lookup_cap(current, vspace_arg)? {
            Capability::VSpace { id, rights } if rights.contains(Rights::WRITE) => {
                let vspace = state.vspaces.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
                Some(vspace.root)
            }
            Capability::VSpace { .. } => return Err(SyscallError::IllegalOperation),
            _ => return Err(SyscallError::InvalidCapability),
        }
    };

    let was_inactive = {
        let tcb = state.tcbs.get_mut(target.0 as usize).ok_or(SyscallError::InvalidCapability)?;
        let was_inactive = tcb.state == ThreadState::Inactive;
        tcb.cspace = Some(cspace_id);
        tcb.sched_context = Some(sched_id);
        tcb.address_space = address_space;
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

    /// A real, page-aligned, host-addressable "physical" buffer for
    /// memory-backed-Untyped tests (RFC-0008/ADR-0012) — the same trick
    /// `lantern-hal/riscv64_paging.rs`'s own host tests use for fake page tables:
    /// `VSpace`/`Frame` retype hands back real addresses that a later `Map` call
    /// genuinely dereferences (`lantern_hal::riscv64_translate`/`map_page`), so a
    /// bogus placeholder address would be unsound to test against, not just
    /// semantically wrong.
    #[repr(C, align(4096))]
    struct TestArena([u8; 64 * 1024]);

    /// Like [`setup_with_untyped`], but the Untyped is backed by `arena` — real,
    /// dereferenceable "physical" memory — so `VSpace`/`FrameSmall`/`FrameMega`
    /// retype (and, downstream, `FrameInvoke::Map`) can be exercised for real.
    /// `arena` is an out-param (not returned) so its address never moves after
    /// this call — a moved buffer would invalidate every address already handed
    /// out.
    fn setup_with_memory_backed_untyped(
        budget: usize,
        arena: &mut TestArena,
    ) -> (KernelState, TcbId, CPtr, CPtr) {
        let mut state = KernelState::new();
        let cnode_idx = state.cnodes.alloc(CNode::empty()).unwrap();
        let cnode_id = CNodeId(cnode_idx as u16);
        let tcb_idx = state.tcbs.alloc(Tcb::new()).unwrap();
        let tcb_id = TcbId(tcb_idx as u16);
        state.tcbs.get_mut(tcb_idx).unwrap().cspace = Some(cnode_id);

        let base = arena as *mut TestArena as usize;
        let untyped =
            crate::object::Untyped::with_memory(budget, base, core::mem::size_of::<TestArena>());
        let untyped_idx = state.untypeds.alloc(untyped).unwrap();
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

    #[test]
    fn retype_vspace_from_a_memory_backed_untyped() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, untyped_cptr, dest) = setup_with_memory_backed_untyped(2, &mut arena);
        let mut frame = frame_for(untyped_cptr, ObjectType::VSpace as usize, dest);
        untyped_retype(&mut state, tcb, untyped_cptr, &mut frame).unwrap();

        let Some(Capability::VSpace { id, rights }) = state.cnodes.get(0).unwrap().get(dest) else {
            panic!("expected a VSpace capability");
        };
        assert_eq!(rights, Rights::ALL);
        let vspace = state.vspaces.get(id.0 as usize).unwrap();
        let base = &arena as *const TestArena as usize;
        assert!(vspace.root >= base && vspace.root < base + core::mem::size_of::<TestArena>());
        assert_eq!(vspace.root % lantern_hal::RISCV64_PAGE_SIZE, 0);
        assert_eq!(state.untypeds.get(0).unwrap().remaining, 1);
    }

    #[test]
    fn retype_frame_small_gets_a_correctly_sized_page() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, untyped_cptr, dest) = setup_with_memory_backed_untyped(2, &mut arena);

        let mut frame1 = frame_for(untyped_cptr, ObjectType::FrameSmall as usize, dest);
        untyped_retype(&mut state, tcb, untyped_cptr, &mut frame1).unwrap();
        let mut frame2 = frame_for(untyped_cptr, ObjectType::FrameSmall as usize, dest + 1);
        untyped_retype(&mut state, tcb, untyped_cptr, &mut frame2).unwrap();

        let Some(Capability::Frame { id: first_id, .. }) = state.cnodes.get(0).unwrap().get(dest) else {
            panic!("expected a Frame capability");
        };
        let Some(Capability::Frame { id: second_id, .. }) = state.cnodes.get(0).unwrap().get(dest + 1) else {
            panic!("expected a Frame capability");
        };
        let first = state.frames.get(first_id.0 as usize).unwrap();
        let second = state.frames.get(second_id.0 as usize).unwrap();
        assert_eq!(first.size, FrameSize::Small);
        assert_eq!(first.paddr % lantern_hal::RISCV64_PAGE_SIZE, 0);
        assert_ne!(first.paddr, second.paddr, "two retypes must never alias the same page");
        assert!(first.mapped_at.is_none());
    }

    #[test]
    fn retype_frame_mega_gets_a_correctly_sized_page() {
        // FrameMega needs a real 2 MiB-scale backing range — a heap allocation,
        // not a stack-local `TestArena`, to avoid depending on how large a
        // stack the test harness happens to give this thread.
        let mut backing = vec![0u8; 3 * lantern_hal::RISCV64_MEGAPAGE_SIZE];
        let base = backing.as_mut_ptr() as usize;
        let mut state = KernelState::new();
        let cnode_idx = state.cnodes.alloc(CNode::empty()).unwrap();
        let tcb_id = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb_id.0 as usize).unwrap().cspace = Some(CNodeId(cnode_idx as u16));
        let untyped = crate::object::Untyped::with_memory(2, base, backing.len());
        let untyped_idx = state.untypeds.alloc(untyped).unwrap();
        let untyped_cptr: CPtr = 1;
        *state.cnodes.get_mut(cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
            Capability::Untyped { id: crate::cap::UntypedId(untyped_idx as u16), rights: Rights::ALL };

        let mut frame = frame_for(untyped_cptr, ObjectType::FrameMega as usize, 2);
        untyped_retype(&mut state, tcb_id, untyped_cptr, &mut frame).unwrap();

        let Some(Capability::Frame { id, .. }) = state.cnodes.get(0).unwrap().get(2) else {
            panic!("expected a Frame capability");
        };
        let mega = state.frames.get(id.0 as usize).unwrap();
        assert_eq!(mega.size, FrameSize::Mega);
        assert_eq!(mega.paddr % lantern_hal::RISCV64_MEGAPAGE_SIZE, 0);
        assert!(mega.mapped_at.is_none());
    }

    #[test]
    fn retype_vspace_without_real_memory_backing_fails() {
        // `setup_with_untyped` (not the `_memory_backed` variant) has no `memory`
        // range at all — VSpace/Frame retype can't hand back a real address.
        let (mut state, tcb, untyped_cptr, dest) = setup_with_untyped(2);
        let mut frame = frame_for(untyped_cptr, ObjectType::VSpace as usize, dest);
        assert_eq!(
            untyped_retype(&mut state, tcb, untyped_cptr, &mut frame),
            Err(SyscallError::NotEnoughMemory)
        );
    }

    #[test]
    fn configure_sets_address_space_from_a_vspace_capability() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, admin_id, untyped_cptr, dest) = setup_with_memory_backed_untyped(3, &mut arena);
        let target_idx = state.tcbs.alloc(Tcb::new()).unwrap();
        let target = TcbId(target_idx as u16);
        let target_cspace = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let sched = state.sched_contexts.alloc(SchedulingContext::new(1)).unwrap();

        let mut retype_frame = frame_for(untyped_cptr, ObjectType::VSpace as usize, dest);
        untyped_retype(&mut state, admin_id, untyped_cptr, &mut retype_frame).unwrap();
        let Some(Capability::VSpace { id: vspace_id, .. }) = state.cnodes.get(0).unwrap().get(dest) else {
            panic!("expected a VSpace capability");
        };
        let expected_root = state.vspaces.get(vspace_id.0 as usize).unwrap().root;

        let cnode = state.cnodes.get_mut(0).unwrap();
        *cnode.slot_mut(3).unwrap() = Capability::Tcb { id: target, rights: Rights::ALL };
        *cnode.slot_mut(4).unwrap() = Capability::CNode(target_cspace);
        *cnode.slot_mut(5).unwrap() =
            Capability::SchedContext { id: SchedContextId(sched as u16), rights: Rights::ALL };

        let mut frame = TrapFrame::zeroed();
        frame.set_mr(1, 4);
        frame.set_mr(2, 5);
        frame.set_mr(3, dest); // the VSpace cptr retyped above
        configure(&mut state, admin_id, 3, &mut frame).unwrap();

        assert_eq!(state.tcbs.get(target_idx).unwrap().address_space, Some(expected_root));
    }

    #[test]
    fn configure_with_mr3_zero_leaves_no_address_space() {
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

        let mut frame = frame_for(0, 1, 2); // mr3 defaults to 0
        configure(&mut state, admin_id, 0, &mut frame).unwrap();

        assert_eq!(state.tcbs.get(target_idx).unwrap().address_space, None);
    }

    #[test]
    fn configure_rejects_a_non_vspace_mr3() {
        let mut state = KernelState::new();
        let admin_cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let admin_id = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(admin_id.0 as usize).unwrap().cspace = Some(CNodeId(admin_cnode as u16));
        let target_idx = state.tcbs.alloc(Tcb::new()).unwrap();
        let target = TcbId(target_idx as u16);
        let target_cspace = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let sched = state.sched_contexts.alloc(SchedulingContext::new(1)).unwrap();
        let ep = state.endpoints.alloc(Endpoint::new()).unwrap();

        let cnode = state.cnodes.get_mut(admin_cnode).unwrap();
        *cnode.slot_mut(0).unwrap() = Capability::Tcb { id: target, rights: Rights::ALL };
        *cnode.slot_mut(1).unwrap() = Capability::CNode(target_cspace);
        *cnode.slot_mut(2).unwrap() =
            Capability::SchedContext { id: SchedContextId(sched as u16), rights: Rights::ALL };
        *cnode.slot_mut(3).unwrap() =
            Capability::Endpoint { id: EndpointId(ep as u16), badge: 0, rights: Rights::ALL };

        let mut frame = TrapFrame::zeroed();
        frame.set_mr(1, 1);
        frame.set_mr(2, 2);
        frame.set_mr(3, 3); // names an Endpoint, not a VSpace
        assert_eq!(
            configure(&mut state, admin_id, 0, &mut frame),
            Err(SyscallError::InvalidCapability)
        );
    }
}
