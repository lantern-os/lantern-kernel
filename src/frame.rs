//! `FrameInvoke`: `Map`/`Unmap` ([RFC-0008](../../lantern-rfcs/rfcs/0008-vspace-frame-capabilities-and-elf-loader.md)/
//! [ADR-0012](../../lantern-rfcs/adr/0012-vspace-frame-capabilities-and-elf-loader.md)),
//! dispatched on the message tag's `label` — mirrors `crate::cnode`'s `CNodeInvoke`
//! shape exactly (invoke on the *Frame* capability, matching seL4's
//! `Frame_Map`/`Frame_Unmap` convention rather than an "invoke on the VSpace"
//! shape — see RFC-0008's "Alternatives considered").
//!
//! `Map`'s permission bits (`mr3`) are a Phase 1 kernel-internal convention
//! `crate::abi`'s general mr0-is-CPtr note doesn't cover, so it's fixed here:
//! bit 0 = readable, bit 1 = writable, bit 2 = executable, bit 3 = user-accessible
//! ([`PermFlags`]). This is a mapping *permission*, independent of the Frame
//! capability's own [`Rights`] (which gate whether this thread may invoke `Map`
//! at all, not what the resulting page allows).

use lantern_hal::TrapFrame;

use crate::abi;
use crate::cap::{Capability, CPtr, FrameId, Rights, TcbId};
use crate::error::SyscallError;
use crate::object::FrameSize;
use crate::state::KernelState;

pub const LABEL_MAP: u32 = 1;
pub const LABEL_UNMAP: u32 = 2;

/// `mr3`'s bit layout for `Map` — see the module doc.
#[derive(Clone, Copy)]
struct PermFlags(usize);

impl PermFlags {
    const READ: usize = 1 << 0;
    const WRITE: usize = 1 << 1;
    const EXECUTE: usize = 1 << 2;
    const USER: usize = 1 << 3;

    fn to_pte_flags(self) -> lantern_hal::Riscv64PteFlags {
        let mut flags = lantern_hal::Riscv64PteFlags::VALID;
        // VALID is folded in unconditionally by `leaf()` on the `lantern-hal`
        // side too; harmless to union it here again for clarity.
        if self.0 & Self::READ != 0 {
            flags = flags.union(lantern_hal::Riscv64PteFlags::READ);
        }
        if self.0 & Self::WRITE != 0 {
            flags = flags.union(lantern_hal::Riscv64PteFlags::WRITE);
        }
        if self.0 & Self::EXECUTE != 0 {
            flags = flags.union(lantern_hal::Riscv64PteFlags::EXECUTE);
        }
        if self.0 & Self::USER != 0 {
            flags = flags.union(lantern_hal::Riscv64PteFlags::USER);
        }
        flags
    }
}

pub fn invoke(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let frame_id = match state.lookup_cap(current, cptr)? {
        Capability::Frame { id, rights } if rights.contains(Rights::WRITE) => id,
        Capability::Frame { .. } => return Err(SyscallError::IllegalOperation),
        _ => return Err(SyscallError::InvalidCapability),
    };

    match frame.tag().label {
        LABEL_MAP => map(state, current, frame_id, frame)?,
        LABEL_UNMAP => unmap(state, frame_id)?,
        _ => return Err(SyscallError::InvalidArgument),
    }
    abi::reply_success(frame);
    Ok(())
}

fn map(
    state: &mut KernelState,
    current: TcbId,
    frame_id: FrameId,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let vspace_id = match state.lookup_cap(current, frame.mr(1))? {
        Capability::VSpace { id, rights } if rights.contains(Rights::WRITE) => id,
        Capability::VSpace { .. } => return Err(SyscallError::IllegalOperation),
        _ => return Err(SyscallError::InvalidCapability),
    };
    let vaddr = frame.mr(2);
    let perms = PermFlags(frame.mr(3));

    let f = state.frames.get(frame_id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    if f.mapped_at.is_some() {
        return Err(SyscallError::IllegalOperation);
    }
    let (paddr, size) = (f.paddr, f.size);
    if !vaddr.is_multiple_of(size.bytes()) {
        return Err(SyscallError::AlignmentError);
    }

    let vspace = state.vspaces.get(vspace_id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let root = vspace.root as *mut lantern_hal::Riscv64PageTable;
    let source = vspace.source;

    // SAFETY: `root` is a valid Sv39 root page table — every VSpace was built by
    // `admin::untyped_retype`'s `ObjectType::VSpace` arm, which always produces
    // one (a zeroed, page-aligned physical page from a real memory-backed
    // Untyped). `translate` only reads.
    if unsafe { lantern_hal::riscv64_translate(root, vaddr) }.is_some() {
        return Err(SyscallError::IllegalOperation);
    }

    // `map`/`map_megapage`'s allocator closures are infallible by contract (they
    // always return a page, never `None`) — but the Untyped they'd allocate an
    // intermediate branch table from *can* be exhausted, which must fail
    // gracefully (ADR-0008: "no syscall panics on caller-supplied input"), not
    // panic inside the closure. Pre-allocating every page either walk could
    // *possibly* need — up to two (L1 and L0) for `map`'s full 3-level walk, up
    // to one (L1 only) for `map_megapage` — before ever calling either, turns
    // that failure into an ordinary `NotEnoughMemory` return, at the cost of
    // sometimes bumping a page the walk turns out not to need (a target branch
    // was already valid from an earlier `Map` sharing the same region). Wasted,
    // never reused (no reclaim, same as every other Untyped bump —
    // `crate::object::Untyped`'s doc) — acceptable for a handful of Phase 1
    // loader mappings, not a real memory budget concern yet.
    let max_new_tables = match size {
        FrameSize::Small => 2,
        FrameSize::Mega => 1,
    };
    let mut spares = [0usize; 2];
    {
        let untyped = state.untypeds.get_mut(source.0 as usize).ok_or(SyscallError::InvalidCapability)?;
        for slot in spares.iter_mut().take(max_new_tables) {
            *slot = untyped
                .bump(lantern_hal::RISCV64_PAGE_SIZE, lantern_hal::RISCV64_PAGE_SIZE)
                .ok_or(SyscallError::NotEnoughMemory)?;
        }
    }
    let mut next_spare = 0usize;
    let mut alloc = move || {
        let p = spares[next_spare];
        next_spare += 1;
        p
    };

    // SAFETY: `root` as above; `alloc` returns a distinct fresh page per call (up
    // to `max_new_tables` calls, exactly what each walk can possibly make) — this
    // Untyped's bump pointer never repeats, per `Untyped::bump`'s own contract.
    match size {
        FrameSize::Small => unsafe {
            lantern_hal::riscv64_map_page(root, vaddr, paddr, perms.to_pte_flags(), &mut alloc)
        },
        FrameSize::Mega => unsafe {
            lantern_hal::riscv64_map_megapage(root, vaddr, paddr, perms.to_pte_flags(), &mut alloc)
        },
    }

    let f = state.frames.get_mut(frame_id.0 as usize).expect("checked above");
    f.mapped_at = Some((vspace_id, vaddr));
    Ok(())
}

fn unmap(state: &mut KernelState, frame_id: FrameId) -> Result<(), SyscallError> {
    let f = state.frames.get(frame_id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let Some((vspace_id, vaddr)) = f.mapped_at else {
        return Ok(()); // Not currently mapped anywhere — a harmless no-op.
    };

    let vspace = state.vspaces.get(vspace_id.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let root = vspace.root as *mut lantern_hal::Riscv64PageTable;
    // SAFETY: as `map`'s — `root` is a valid Sv39 root page table.
    unsafe { lantern_hal::riscv64_unmap(root, vaddr) };

    let f = state.frames.get_mut(frame_id.0 as usize).expect("checked above");
    f.mapped_at = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin;
    use crate::cap::{CNode, CNodeId, ObjectType, UntypedId};
    use crate::object::{Tcb, Untyped};
    use crate::state::KernelState;
    use lantern_hal::MessageTag;

    /// Real, page-aligned, host-addressable "physical" memory — `Map`/`Unmap`
    /// genuinely dereference `VSpace`/`Frame` addresses (`lantern_hal::riscv64_*`),
    /// so a placeholder address would be unsound to test against here, the same
    /// reasoning `admin.rs`'s own `TestArena` doc gives.
    #[repr(C, align(4096))]
    struct TestArena([u8; 64 * 1024]);

    /// Builds a thread with a memory-backed Untyped already retyped into one
    /// VSpace (cptr 2) and one `FrameSmall` (cptr 3), ready for `Map`/`Unmap`.
    fn setup(arena: &mut TestArena) -> (KernelState, TcbId, CPtr, CPtr) {
        let mut state = KernelState::new();
        let cnode_idx = state.cnodes.alloc(CNode::empty()).unwrap();
        let tcb_id = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb_id.0 as usize).unwrap().cspace = Some(CNodeId(cnode_idx as u16));

        let base = arena as *mut TestArena as usize;
        let untyped = Untyped::with_memory(4, base, core::mem::size_of::<TestArena>());
        let untyped_idx = state.untypeds.alloc(untyped).unwrap();
        let untyped_cptr: CPtr = 1;
        *state.cnodes.get_mut(cnode_idx).unwrap().slot_mut(untyped_cptr).unwrap() =
            Capability::Untyped { id: UntypedId(untyped_idx as u16), rights: Rights::ALL };

        let vspace_cptr: CPtr = 2;
        let mut retype_vspace = TrapFrame::zeroed();
        retype_vspace.set_mr(1, ObjectType::VSpace as usize);
        retype_vspace.set_mr(2, vspace_cptr);
        admin::untyped_retype(&mut state, tcb_id, untyped_cptr, &mut retype_vspace).unwrap();

        let frame_cptr: CPtr = 3;
        let mut retype_frame = TrapFrame::zeroed();
        retype_frame.set_mr(1, ObjectType::FrameSmall as usize);
        retype_frame.set_mr(2, frame_cptr);
        admin::untyped_retype(&mut state, tcb_id, untyped_cptr, &mut retype_frame).unwrap();

        (state, tcb_id, frame_cptr, vspace_cptr)
    }

    fn map_frame(mr3: usize) -> TrapFrame {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: LABEL_MAP, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(3, mr3);
        frame
    }

    #[test]
    fn map_then_translate_succeeds_and_marks_the_frame_mapped() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, frame_cptr, vspace_cptr) = setup(&mut arena);
        let Capability::VSpace { id: vspace_id, .. } = state.lookup_cap(tcb, vspace_cptr).unwrap() else {
            panic!("expected a VSpace capability");
        };
        let Capability::Frame { id: frame_id, .. } = state.lookup_cap(tcb, frame_cptr).unwrap() else {
            panic!("expected a Frame capability");
        };
        let paddr = state.frames.get(frame_id.0 as usize).unwrap().paddr;
        let root = state.vspaces.get(vspace_id.0 as usize).unwrap().root;

        let vaddr = 0x1000_0000usize; // arbitrary, 4 KiB-aligned
        let mut frame = map_frame(PermFlags::READ | PermFlags::WRITE);
        frame.set_mr(1, vspace_cptr);
        frame.set_mr(2, vaddr);
        invoke(&mut state, tcb, frame_cptr, &mut frame).unwrap();

        // SAFETY: `root` is this test's own retyped VSpace's real backing page.
        let translated = unsafe { lantern_hal::riscv64_translate(root as *const _, vaddr) };
        assert_eq!(translated, Some(paddr));
        assert_eq!(state.frames.get(frame_id.0 as usize).unwrap().mapped_at, Some((vspace_id, vaddr)));
    }

    #[test]
    fn map_rejects_a_frame_without_write_rights() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, frame_cptr, vspace_cptr) = setup(&mut arena);
        // Mint a read-only copy of the Frame cap into a fresh slot.
        let Capability::Frame { id, .. } = state.lookup_cap(tcb, frame_cptr).unwrap() else {
            panic!("expected a Frame capability");
        };
        *state.cnodes.get_mut(0).unwrap().slot_mut(4).unwrap() =
            Capability::Frame { id, rights: Rights::READ };

        let mut frame = map_frame(PermFlags::READ);
        frame.set_mr(1, vspace_cptr);
        frame.set_mr(2, 0x1000_0000);
        assert_eq!(invoke(&mut state, tcb, 4, &mut frame), Err(SyscallError::IllegalOperation));
    }

    #[test]
    fn map_rejects_an_already_mapped_frame() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, frame_cptr, vspace_cptr) = setup(&mut arena);

        let mut frame1 = map_frame(PermFlags::READ);
        frame1.set_mr(1, vspace_cptr);
        frame1.set_mr(2, 0x1000_0000);
        invoke(&mut state, tcb, frame_cptr, &mut frame1).unwrap();

        let mut frame2 = map_frame(PermFlags::READ);
        frame2.set_mr(1, vspace_cptr);
        frame2.set_mr(2, 0x2000_0000);
        assert_eq!(invoke(&mut state, tcb, frame_cptr, &mut frame2), Err(SyscallError::IllegalOperation));
    }

    #[test]
    fn map_rejects_a_misaligned_vaddr() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, frame_cptr, vspace_cptr) = setup(&mut arena);

        let mut frame = map_frame(PermFlags::READ);
        frame.set_mr(1, vspace_cptr);
        frame.set_mr(2, 0x1000_0123); // not page-aligned
        assert_eq!(invoke(&mut state, tcb, frame_cptr, &mut frame), Err(SyscallError::AlignmentError));
    }

    #[test]
    fn unmap_clears_the_mapping() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, frame_cptr, vspace_cptr) = setup(&mut arena);
        let Capability::VSpace { id: vspace_id, .. } = state.lookup_cap(tcb, vspace_cptr).unwrap() else {
            panic!("expected a VSpace capability");
        };
        let root = state.vspaces.get(vspace_id.0 as usize).unwrap().root;

        let vaddr = 0x1000_0000usize;
        let mut map = map_frame(PermFlags::READ);
        map.set_mr(1, vspace_cptr);
        map.set_mr(2, vaddr);
        invoke(&mut state, tcb, frame_cptr, &mut map).unwrap();

        let mut unmap = TrapFrame::zeroed();
        unmap.set_tag(MessageTag { label: LABEL_UNMAP, length: 0, extra_caps: 0, flags: 0 });
        invoke(&mut state, tcb, frame_cptr, &mut unmap).unwrap();

        let Capability::Frame { id: frame_id, .. } = state.lookup_cap(tcb, frame_cptr).unwrap() else {
            panic!("expected a Frame capability");
        };
        assert_eq!(state.frames.get(frame_id.0 as usize).unwrap().mapped_at, None);
        // SAFETY: `root` is this test's own retyped VSpace's real backing page.
        assert_eq!(unsafe { lantern_hal::riscv64_translate(root as *const _, vaddr) }, None);
    }

    #[test]
    fn unmapping_an_unmapped_frame_is_a_harmless_no_op() {
        let mut arena = TestArena([0; 64 * 1024]);
        let (mut state, tcb, frame_cptr, _vspace_cptr) = setup(&mut arena);
        let mut unmap = TrapFrame::zeroed();
        unmap.set_tag(MessageTag { label: LABEL_UNMAP, length: 0, extra_caps: 0, flags: 0 });
        assert_eq!(invoke(&mut state, tcb, frame_cptr, &mut unmap), Ok(()));
    }
}
