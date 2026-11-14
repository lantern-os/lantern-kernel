//! `Reset`: reclaiming everything made from an `Untyped` —
//! [RFC-0030](../../lantern-rfcs/rfcs/0030-process-lifecycle-faults-and-reclamation.md).
//!
//! **Objects die with the memory they were made from.** [`reset`] destroys every object whose origin is the `Untyped` or a
//! descendant of it, unwinds every kernel reference to them, clears every capability to them in every surviving CNode, frees
//! their pool slots and page tables, and rewinds the `Untyped` to empty. It's a bounded scan of fixed-size pools, not a
//! derivation tree, so the kernel stays non-preemptible (ADR-0010).
//!
//! Objects boot code made directly have no origin, and nothing here can reach them: `IrqHandler`s, `Deadline`s, and every
//! boot-time program's objects.

use crate::cap::{Capability, NotificationId, TcbId, UntypedId};
use crate::error::SyscallError;
use crate::lifecycle::fail_blocked;
use crate::limits::{MAX_CNODES, MAX_DEADLINES, MAX_ENDPOINTS, MAX_FRAMES, MAX_NOTIFICATIONS, MAX_SCHED_CONTEXTS, MAX_TCBS, MAX_UNTYPEDS, MAX_VSPACES};
use crate::object::{EndpointQueue, ThreadState};
use crate::state::{KernelState, ACTIVE_ROOT};

/// What a `Reset` destroys, by pool index.
struct Doomed {
    untypeds: [bool; MAX_UNTYPEDS],
    cnodes: [bool; MAX_CNODES],
    tcbs: [bool; MAX_TCBS],
    endpoints: [bool; MAX_ENDPOINTS],
    notifications: [bool; MAX_NOTIFICATIONS],
    sched_contexts: [bool; MAX_SCHED_CONTEXTS],
    vspaces: [bool; MAX_VSPACES],
    frames: [bool; MAX_FRAMES],
}

impl Doomed {
    fn cap(&self, cap: &Capability) -> bool {
        match *cap {
            Capability::Untyped { id, .. } => self.untypeds[id.0 as usize],
            Capability::CNode(id) => self.cnodes[id.0 as usize],
            Capability::Tcb { id, .. } => self.tcbs[id.0 as usize],
            Capability::Endpoint { id, .. } => self.endpoints[id.0 as usize],
            Capability::Notification { id, .. } => self.notifications[id.0 as usize],
            Capability::SchedContext { id, .. } => self.sched_contexts[id.0 as usize],
            Capability::VSpace { id, .. } => self.vspaces[id.0 as usize],
            Capability::Frame { id, .. } => self.frames[id.0 as usize],
            _ => false,
        }
    }
}

/// Destroys everything made from `untyped` and its descendants, and empties it. The `Untyped` itself survives, ready to
/// be retyped from again.
pub fn reset(state: &mut KernelState, untyped: UntypedId) -> Result<(), SyscallError> {
    state.untypeds.get(untyped.0 as usize).ok_or(SyscallError::InvalidCapability)?;
    let doomed = mark(state, untyped);

    // Never free the tables the hart is running on: switch to the kernel-only root first.
    let active = ACTIVE_ROOT.load(core::sync::atomic::Ordering::Relaxed);
    let active_doomed = (0..MAX_VSPACES).any(|i| doomed.vspaces[i] && state.vspaces.get(i).is_some_and(|v| v.root == active));
    if active_doomed {
        if let Some(idle) = state.kernel_template.idle_root {
            activate(idle);
        }
    }

    for i in (0..MAX_TCBS).filter(|&i| doomed.tcbs[i]) {
        unlink(state, TcbId(i as u16));
    }
    // A surviving thread that relied on something going away can't run: suspend it.
    for i in (0..MAX_TCBS).filter(|&i| !doomed.tcbs[i]) {
        let Some(tcb) = state.tcbs.get(i) else { continue };
        let lost_cspace = tcb.cspace.is_some_and(|c| doomed.cnodes[c.0 as usize]);
        let lost_sched = tcb.sched_context.is_some_and(|s| doomed.sched_contexts[s.0 as usize]);
        let lost_vspace = tcb.address_space.is_some_and(|root| {
            (0..MAX_VSPACES).any(|v| doomed.vspaces[v] && state.vspaces.get(v).is_some_and(|vs| vs.root == root))
        });
        if lost_cspace || lost_sched || lost_vspace {
            unlink(state, TcbId(i as u16));
            state.tcbs.get_mut(i).expect("present").state = ThreadState::Inactive;
        }
    }
    for i in (0..MAX_ENDPOINTS).filter(|&i| doomed.endpoints[i]) {
        let Some(endpoint) = state.endpoints.get(i).copied() else { continue };
        if let EndpointQueue::Send(mut q) | EndpointQueue::Recv(mut q) = endpoint.queue {
            while let Some(blocked) = q.pop_front() {
                fail_blocked(state, blocked, SyscallError::InvalidCapability);
            }
        }
    }
    for i in (0..MAX_NOTIFICATIONS).filter(|&i| doomed.notifications[i]) {
        let gone = NotificationId(i as u16);
        let Some(mut waiters) = state.notifications.get(i).map(|n| n.waiters) else { continue };
        while let Some(blocked) = waiters.pop_front() {
            fail_blocked(state, blocked, SyscallError::InvalidCapability);
        }
        unbind(state, gone);
    }
    for i in 0..MAX_FRAMES {
        let Some(frame) = state.frames.get(i).copied() else { continue };
        for (slot, mapping) in frame.mapped_at.iter().enumerate() {
            let Some((vspace, vaddr)) = *mapping else { continue };
            let vspace_doomed = doomed.vspaces[vspace.0 as usize];
            if doomed.frames[i] && !vspace_doomed {
                if let Some(v) = state.vspaces.get(vspace.0 as usize) {
                    // SAFETY: a live VSpace root from the kernel's pool, and a mapping this Frame recorded.
                    unsafe { lantern_hal::riscv64_unmap(v.root as *mut lantern_hal::Riscv64PageTable, vaddr) };
                }
            }
            if vspace_doomed && !doomed.frames[i] {
                // A surviving Frame loses a mapping in a VSpace that's going.
                state.frames.get_mut(i).expect("present").mapped_at[slot] = None;
            }
        }
    }
    for i in (0..MAX_VSPACES).filter(|&i| doomed.vspaces[i]) {
        if let Some(root) = state.vspaces.get(i).map(|v| v.root) {
            crate::vspace::free_tables(state, root);
        }
    }

    // Every capability to anything destroyed, in every CNode that survives.
    for c in (0..MAX_CNODES).filter(|&c| !doomed.cnodes[c]) {
        let Some(cnode) = state.cnodes.get_mut(c) else { continue };
        for slot in 0..crate::limits::CNODE_SLOTS {
            let cap = cnode.get(slot).expect("in range");
            if doomed.cap(&cap) {
                *cnode.slot_mut(slot).expect("in range") = Capability::Null;
            }
        }
    }

    free(state, &doomed);
    state.untypeds.get_mut(untyped.0 as usize).expect("checked above").rewind();

    // The current thread may be one of the dead; if not, it may have lost a mapping it was using.
    if state.scheduler.current.is_some_and(|t| doomed.tcbs[t.0 as usize]) {
        state.scheduler.current = None;
    } else if let Some(tcb) = state.scheduler.current.and_then(|t| state.tcbs.get(t.0 as usize)) {
        // Re-activating flushes any stale translation for a page unmapped above.
        crate::state::activate_if_paged(tcb);
    }
    Ok(())
}

fn mark(state: &KernelState, root: UntypedId) -> Doomed {
    let mut set = [false; MAX_UNTYPEDS];
    set[root.0 as usize] = true;
    // The descendants: a fixed point, since a child's origin is on the child.
    loop {
        let mut changed = false;
        for i in 0..MAX_UNTYPEDS {
            let Some(u) = state.untypeds.get(i) else { continue };
            if !set[i] && u.origin.is_some_and(|o| set[o.0 as usize]) {
                set[i] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let from = |origin: Option<UntypedId>| origin.is_some_and(|o| set[o.0 as usize]);
    let o = &state.origins;
    let mut untypeds = set;
    untypeds[root.0 as usize] = false;
    Doomed {
        untypeds,
        cnodes: core::array::from_fn(|i| state.cnodes.get(i).is_some() && from(o.cnodes[i])),
        tcbs: core::array::from_fn(|i| state.tcbs.get(i).is_some() && from(o.tcbs[i])),
        endpoints: core::array::from_fn(|i| state.endpoints.get(i).is_some() && from(o.endpoints[i])),
        notifications: core::array::from_fn(|i| state.notifications.get(i).is_some() && from(o.notifications[i])),
        sched_contexts: core::array::from_fn(|i| state.sched_contexts.get(i).is_some() && from(o.sched_contexts[i])),
        vspaces: core::array::from_fn(|i| state.vspaces.get(i).is_some() && from(o.vspaces[i])),
        frames: core::array::from_fn(|i| state.frames.get(i).is_some() && from(o.frames[i])),
    }
}

/// Takes a thread out of everything that could resume it or name it.
fn unlink(state: &mut KernelState, id: TcbId) {
    state.scheduler.remove_ready(id);
    for i in 0..MAX_ENDPOINTS {
        let Some(endpoint) = state.endpoints.get_mut(i) else { continue };
        endpoint.queue = match endpoint.queue {
            EndpointQueue::Send(mut q) => {
                q.remove(id);
                if q.is_empty() { EndpointQueue::Empty } else { EndpointQueue::Send(q) }
            }
            EndpointQueue::Recv(mut q) => {
                q.remove(id);
                if q.is_empty() { EndpointQueue::Empty } else { EndpointQueue::Recv(q) }
            }
            EndpointQueue::Empty => EndpointQueue::Empty,
        };
    }
    for i in 0..MAX_NOTIFICATIONS {
        if let Some(n) = state.notifications.get_mut(i) {
            n.waiters.remove(id);
        }
    }
    // Nobody can reply to it any more, and a caller it owed a reply to is told.
    for i in 0..MAX_TCBS {
        if let Some(t) = state.tcbs.get_mut(i) {
            if t.reply_to == Some(id) {
                t.reply_to = None;
            }
        }
    }
    let owed = state.tcbs.get_mut(id.0 as usize).and_then(|t| t.reply_to.take());
    if let Some(caller) = owed {
        fail_blocked(state, caller, SyscallError::InvalidCapability);
    }
}

/// Clears every binding to a notification that's going: interrupt lines, deadlines, and fault notifications.
fn unbind(state: &mut KernelState, gone: NotificationId) {
    crate::irq::unbind_notification(state, gone);
    for i in 0..MAX_DEADLINES {
        if let Some(d) = state.deadlines.get_mut(i) {
            if d.notification.is_some_and(|(n, _)| n == gone) {
                *d = crate::object::Deadline::default();
            }
        }
    }
    for i in 0..MAX_TCBS {
        if let Some(t) = state.tcbs.get_mut(i) {
            if t.fault_notification.is_some_and(|(n, _)| n == gone) {
                t.fault_notification = None;
            }
        }
    }
}

fn free(state: &mut KernelState, doomed: &Doomed) {
    let o = &mut state.origins;
    for i in (0..MAX_CNODES).filter(|&i| doomed.cnodes[i]) {
        state.cnodes.free(i);
        o.cnodes[i] = None;
    }
    for i in (0..MAX_TCBS).filter(|&i| doomed.tcbs[i]) {
        state.tcbs.free(i);
        o.tcbs[i] = None;
    }
    for i in (0..MAX_ENDPOINTS).filter(|&i| doomed.endpoints[i]) {
        state.endpoints.free(i);
        o.endpoints[i] = None;
    }
    for i in (0..MAX_NOTIFICATIONS).filter(|&i| doomed.notifications[i]) {
        state.notifications.free(i);
        o.notifications[i] = None;
    }
    for i in (0..MAX_SCHED_CONTEXTS).filter(|&i| doomed.sched_contexts[i]) {
        state.sched_contexts.free(i);
        o.sched_contexts[i] = None;
    }
    for i in (0..MAX_VSPACES).filter(|&i| doomed.vspaces[i]) {
        state.vspaces.free(i);
        o.vspaces[i] = None;
    }
    for i in (0..MAX_FRAMES).filter(|&i| doomed.frames[i]) {
        state.frames.free(i);
        o.frames[i] = None;
    }
    for i in (0..MAX_UNTYPEDS).filter(|&i| doomed.untypeds[i]) {
        state.untypeds.free(i);
    }
}

fn activate(root: usize) {
    #[cfg(target_arch = "riscv64")]
    {
        use lantern_hal::Hal;
        // SAFETY: the kernel-only root from `crate::vspace`, which maps the kernel itself and the direct map.
        unsafe { lantern_hal::Hardware::activate_address_space(root) };
        ACTIVE_ROOT.store(root, core::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(not(target_arch = "riscv64"))]
    let _ = root;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{CNode, CNodeId, CPtr, Rights};
    use crate::object::{Tcb, Untyped};
    use lantern_hal::{MessageTag, TrapFrame};

    const MEGA: usize = lantern_hal::RISCV64_MEGAPAGE_SIZE;
    const ROOT_CPTR: CPtr = 1;
    const CHILD_CPTR: CPtr = 2;

    /// Host memory standing in for RAM: 4 MiB, megapage-aligned, inside a larger allocation.
    struct Ram(Vec<u8>);

    impl Ram {
        fn new() -> Self {
            Self(vec![0; 6 * MEGA])
        }
        fn base(&self) -> usize {
            (self.0.as_ptr() as usize + MEGA - 1) & !(MEGA - 1)
        }
    }

    /// A current "launcher" thread holding an `Untyped` over `ram` at slot 1, and a 2 MiB child of it at slot 2.
    fn setup(ram: &Ram) -> (KernelState, TcbId) {
        let mut state = KernelState::new();
        let cnode = state.cnodes.alloc(CNode::empty()).unwrap();
        let launcher = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(launcher.0 as usize).unwrap().cspace = Some(CNodeId(cnode as u16));
        state.scheduler.current = Some(launcher);
        let root = state.untypeds.alloc(Untyped::with_memory(64, ram.base(), 4 * MEGA)).unwrap();
        *state.cnodes.get_mut(cnode).unwrap().slot_mut(ROOT_CPTR).unwrap() =
            Capability::Untyped { id: UntypedId(root as u16), rights: Rights::ALL };
        retype_sized(&mut state, launcher, ROOT_CPTR, 1, CHILD_CPTR, 2 * MEGA).unwrap();
        (state, launcher)
    }

    fn retype_sized(state: &mut KernelState, tcb: TcbId, from: CPtr, ty: usize, dest: CPtr, size: usize) -> Result<(), SyscallError> {
        let mut frame = TrapFrame::zeroed();
        frame.set_mr(1, ty);
        frame.set_mr(2, dest);
        frame.set_mr(3, size);
        crate::admin::untyped_retype(state, tcb, from, &mut frame)
    }

    fn retype(state: &mut KernelState, tcb: TcbId, from: CPtr, ty: usize, dest: CPtr) {
        retype_sized(state, tcb, from, ty, dest, 0).unwrap();
    }

    fn cap(state: &KernelState, tcb: TcbId, cptr: CPtr) -> Capability {
        let cnode = state.tcbs.get(tcb.0 as usize).unwrap().cspace.unwrap();
        state.cnodes.get(cnode.0 as usize).unwrap().get(cptr).unwrap()
    }

    fn reset_cap(state: &mut KernelState, tcb: TcbId, cptr: CPtr) -> Result<(), SyscallError> {
        let Capability::Untyped { id, .. } = cap(state, tcb, cptr) else { panic!("not an Untyped") };
        reset(state, id)
    }

    const ENDPOINT: usize = 2;
    const NOTIFICATION: usize = 3;
    const TCB: usize = 4;
    const CNODE: usize = 0;
    const SCHED: usize = 5;
    const VSPACE: usize = 6;
    const FRAME_SMALL: usize = 7;

    #[test]
    fn reset_destroys_everything_made_from_it_and_nothing_else_and_it_can_be_used_again() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        retype(&mut state, launcher, ROOT_CPTR, ENDPOINT, 20); // From the parent: survives.
        let survivors = (state.endpoints.len(), state.tcbs.len(), state.cnodes.len(), state.kernel_page_tables.in_use());
        for (ty, dest) in [(ENDPOINT, 10), (NOTIFICATION, 11), (TCB, 12), (CNODE, 13), (SCHED, 14), (VSPACE, 15), (FRAME_SMALL, 16)] {
            retype(&mut state, launcher, CHILD_CPTR, ty, dest);
        }
        let Capability::Frame { id, .. } = cap(&state, launcher, 16) else { panic!() };
        let paddr = state.frames.get(id.0 as usize).unwrap().paddr;
        // Its last owner leaves something behind.
        unsafe { core::ptr::write_bytes(paddr as *mut u8, 0xa5, 4096) };

        reset_cap(&mut state, launcher, CHILD_CPTR).unwrap();
        for dest in 10..=16 {
            assert_eq!(cap(&state, launcher, dest), Capability::Null, "slot {dest}");
        }
        assert!(matches!(cap(&state, launcher, 20), Capability::Endpoint { .. }), "made from the parent: kept");
        assert!(matches!(cap(&state, launcher, CHILD_CPTR), Capability::Untyped { .. }), "the Untyped itself stays");
        assert_eq!(
            (state.endpoints.len(), state.tcbs.len(), state.cnodes.len(), state.kernel_page_tables.in_use()),
            survivors,
            "every pool slot and page table came back"
        );
        assert_eq!(state.frames.len(), 0);

        // Empty again: the same memory comes back, zeroed by the kernel on retype.
        retype(&mut state, launcher, CHILD_CPTR, FRAME_SMALL, 16);
        let Capability::Frame { id, .. } = cap(&state, launcher, 16) else { panic!() };
        assert_eq!(state.frames.get(id.0 as usize).unwrap().paddr, paddr);
        assert!(unsafe { core::slice::from_raw_parts(paddr as *const u8, 4096) }.iter().all(|&b| b == 0));
    }

    #[test]
    fn more_launches_than_any_pool_holds_all_fit_when_each_is_reset() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        for round in 0..crate::limits::MAX_TCBS * 3 {
            for (ty, dest) in [(TCB, 10), (CNODE, 11), (VSPACE, 12), (FRAME_SMALL, 13)] {
                assert!(retype_sized(&mut state, launcher, CHILD_CPTR, ty, dest, 0).is_ok(), "round {round}");
            }
            reset_cap(&mut state, launcher, CHILD_CPTR).unwrap();
        }
    }

    #[test]
    fn a_survivor_blocked_on_a_doomed_endpoint_is_failed_not_left_hanging() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        retype(&mut state, launcher, CHILD_CPTR, ENDPOINT, 10);
        let Capability::Endpoint { id, .. } = cap(&state, launcher, 10) else { panic!() };
        let waiter = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(waiter.0 as usize).unwrap().state = ThreadState::BlockedRecv { endpoint: id, dest_slot: None };
        let mut q = crate::queue::ArrayQueue::new();
        q.push_back(waiter);
        state.endpoints.get_mut(id.0 as usize).unwrap().queue = EndpointQueue::Recv(q);

        reset_cap(&mut state, launcher, CHILD_CPTR).unwrap();
        assert_eq!(state.scheduler.ready.pop_front(), Some(waiter));
        let context = state.tcbs.get(waiter.0 as usize).unwrap().context;
        assert!(context.tag().is_error());
        assert_eq!(context.mr(0), SyscallError::InvalidCapability.code());
    }

    #[test]
    fn a_doomed_frame_is_unmapped_from_a_surviving_vspace() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        retype(&mut state, launcher, ROOT_CPTR, VSPACE, 20); // A survivor's address space.
        retype(&mut state, launcher, CHILD_CPTR, FRAME_SMALL, 10);
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: crate::frame::LABEL_MAP, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(1, 20);
        frame.set_mr(2, 0x9000_0000);
        frame.set_mr(3, 0b1011); // R, W, U
        crate::frame::invoke(&mut state, launcher, 10, &mut frame).unwrap();
        let Capability::VSpace { id, .. } = cap(&state, launcher, 20) else { panic!() };
        let root = state.vspaces.get(id.0 as usize).unwrap().root as *const lantern_hal::Riscv64PageTable;
        assert!(unsafe { lantern_hal::riscv64_translate(root, 0x9000_0000) }.is_some());

        reset_cap(&mut state, launcher, CHILD_CPTR).unwrap();
        assert_eq!(unsafe { lantern_hal::riscv64_translate(root, 0x9000_0000) }, None);
    }

    #[test]
    fn resetting_a_parent_takes_its_children_and_theirs_too() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        retype_sized(&mut state, launcher, CHILD_CPTR, 1, 3, MEGA).unwrap(); // A grandchild.
        retype(&mut state, launcher, 3, ENDPOINT, 10);
        let untypeds = state.untypeds.len();
        reset_cap(&mut state, launcher, ROOT_CPTR).unwrap();
        assert_eq!(cap(&state, launcher, CHILD_CPTR), Capability::Null);
        assert_eq!(cap(&state, launcher, 3), Capability::Null);
        assert_eq!(cap(&state, launcher, 10), Capability::Null);
        assert_eq!(state.untypeds.len(), untypeds - 2);
        assert_eq!(state.endpoints.len(), 0);
    }

    #[test]
    fn bindings_to_a_doomed_notification_are_cleared() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        retype(&mut state, launcher, CHILD_CPTR, NOTIFICATION, 10);
        let Capability::Notification { id, .. } = cap(&state, launcher, 10) else { panic!() };
        let Some(Capability::Deadline { id: d, .. }) = crate::deadline::create(&mut state) else { panic!() };
        *state.deadlines.get_mut(d.0 as usize).unwrap() = crate::object::Deadline { notification: Some((id, 1)), at: Some(5) };
        let Some(Capability::IrqHandler { id: h, .. }) = crate::irq::create(&mut state, 10) else { panic!() };
        state.irq_handlers.get_mut(h.0 as usize).unwrap().notification = Some((id, 1));
        state.irq_handlers.get_mut(h.0 as usize).unwrap().pending = true;
        state.tcbs.get_mut(launcher.0 as usize).unwrap().fault_notification = Some((id, 1));

        reset_cap(&mut state, launcher, CHILD_CPTR).unwrap();
        assert_eq!(*state.deadlines.get(d.0 as usize).unwrap(), crate::object::Deadline::default());
        assert_eq!(state.irq_handlers.get(h.0 as usize).unwrap().notification, None);
        assert_eq!(state.tcbs.get(launcher.0 as usize).unwrap().fault_notification, None);
        let mut actions = Vec::new();
        while let Some(a) = state.irq_actions.pop_front() {
            actions.push(a);
        }
        assert_eq!(actions, [crate::irq::IrqAction::Disable(10), crate::irq::IrqAction::Complete(10)]);
    }

    #[test]
    fn a_doomed_current_thread_leaves_no_current_thread() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        retype(&mut state, launcher, CHILD_CPTR, TCB, 10);
        let Capability::Tcb { id, .. } = cap(&state, launcher, 10) else { panic!() };
        // The doomed thread is somehow current (a thread resetting its own memory).
        state.scheduler.current = Some(id);
        reset(&mut state, UntypedId(1)).unwrap();
        assert_eq!(state.scheduler.current, None);
    }

    #[test]
    fn boot_made_objects_have_no_origin_and_are_never_reached() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        let boot_endpoint = state.endpoints.alloc(crate::object::Endpoint::new()).unwrap();
        reset_cap(&mut state, launcher, ROOT_CPTR).unwrap();
        assert!(state.endpoints.get(boot_endpoint).is_some());
        assert!(state.tcbs.get(launcher.0 as usize).is_some());
    }

    #[test]
    fn only_a_writable_untyped_can_be_reset_through_revoke() {
        let ram = Ram::new();
        let (mut state, launcher) = setup(&ram);
        let cnode = state.tcbs.get(launcher.0 as usize).unwrap().cspace.unwrap();
        *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(5).unwrap() = Capability::CNode(cnode);
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: crate::cnode::LABEL_REVOKE, length: 0, extra_caps: 0, flags: 0 });
        frame.set_mr(1, CHILD_CPTR);
        assert!(crate::cnode::invoke(&mut state, launcher, 5, &mut frame).is_ok());
        frame.set_mr(1, 5); // A CNode capability: still refused.
        assert_eq!(crate::cnode::invoke(&mut state, launcher, 5, &mut frame), Err(SyscallError::IllegalOperation));
        let Capability::Untyped { id, .. } = cap(&state, launcher, CHILD_CPTR) else { panic!() };
        *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(CHILD_CPTR).unwrap() =
            Capability::Untyped { id, rights: Rights::READ };
        frame.set_mr(1, CHILD_CPTR);
        assert_eq!(crate::cnode::invoke(&mut state, launcher, 5, &mut frame), Err(SyscallError::IllegalOperation));
    }
}
