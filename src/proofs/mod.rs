//! Kani proofs ([RFC-0037](../../../lantern-rfcs/rfcs/0037-formal-verification-first-properties.md)). Compiled only
//! under `cfg(kani)`, where [`crate::limits`] makes every pool small; run with `scripts/prove.sh`.
//!
//! **How a harness is built.** Each starts from [`skeleton`]: a small, fixed kernel state, with a running caller and two
//! other threads. It then makes arbitrary exactly the parts its operation can touch: every CNode slot ([`any_cnodes`]),
//! the other threads' states and queues ([`any_threads`]), and every register and argument. Then it assumes W
//! ([`crate::wf`]), makes one system call, and checks what RFC-0037 promises of the result. Kani explores every
//! combination of those, not a sample, and its own checks add property 9: no panic, overflow or out-of-bounds index on
//! the way.
//!
//! The fixed parts are the price of tractability: a harness doesn't cover states where they differ. Each harness says
//! which parts it leaves arbitrary.
//!
//! The hardware is replaced by [`stubs`]: page-table writes and RAM zeroing go through raw addresses, which these proofs
//! don't cover (RFC-0037, "What these proofs do not establish").

mod stubs;

use lantern_hal::{MessageTag, TrapFrame, RAW_WORDS};

use crate::cap::*;
use crate::limits::*;
use crate::object::*;
use crate::state::KernelState;
use crate::syscall::{dispatch, SyscallNumber};

// ---------------------------------------------------------------------------------------------------------------------
// Arbitrary values
// ---------------------------------------------------------------------------------------------------------------------

fn id(limit: usize) -> u16 {
    let v: u16 = kani::any();
    kani::assume((v as usize) < limit);
    v
}

fn rights() -> Rights {
    Rights::from_bits_truncate(kani::any())
}

fn maybe<T>(f: impl FnOnce() -> T) -> Option<T> {
    if kani::any() {
        Some(f())
    } else {
        None
    }
}

/// A slot number: in range, or one past it.
fn slot() -> usize {
    let v: usize = kani::any();
    kani::assume(v <= CNODE_SLOTS);
    v
}

/// A register argument: usually a slot, sometimes anything, so both cases are explored.
fn argument() -> usize {
    if kani::any() {
        slot()
    } else {
        kani::any()
    }
}

/// Any capability a CNode could hold, `Null` included. W rules out the ones naming nothing live.
fn capability() -> Capability {
    match kani::any::<u8>() {
        1 => Capability::CNode(CNodeId(id(MAX_CNODES))),
        2 => Capability::Untyped { id: UntypedId(id(MAX_UNTYPEDS)), rights: rights() },
        3 => Capability::Endpoint { id: EndpointId(id(MAX_ENDPOINTS)), badge: kani::any(), rights: rights() },
        4 => Capability::Notification { id: NotificationId(id(MAX_NOTIFICATIONS)), badge: kani::any(), rights: rights() },
        5 => Capability::Tcb { id: TcbId(id(MAX_TCBS)), rights: rights() },
        6 => Capability::SchedContext { id: SchedContextId(id(MAX_SCHED_CONTEXTS)), rights: rights() },
        _ => Capability::Null,
    }
}

fn registers() -> SavedContext {
    let mut frame = TrapFrame::zeroed();
    frame.set_syscall_number(kani::any());
    frame.set_tag(MessageTag { label: kani::any(), length: kani::any(), extra_caps: kani::any(), flags: kani::any() });
    for i in 0..lantern_hal::MR_COUNT {
        frame.set_mr(i, kani::any());
    }
    for i in 0..RAW_WORDS {
        frame.set_raw_word(i, kani::any());
    }
    SavedContext::save_from(&frame)
}

// ---------------------------------------------------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------------------------------------------------

/// The caller, and the two other threads.
const CALLER: TcbId = TcbId(0);
const OTHERS: [TcbId; 2] = [TcbId(1), TcbId(2)];

/// A small, fixed, well-formed state:
/// - two CNodes, both empty: the caller's CSpace (0) and one more (1);
/// - one each of `Untyped` (no physical memory), endpoint, notification and scheduling context;
/// - the caller (thread 0), running in CNode 0; thread 1 inactive, in CNode 1; thread 2 ready. Every thread's registers
///   are arbitrary.
fn skeleton() -> KernelState {
    let mut s = KernelState::new();
    s.now = kani::any();
    let c0 = CNodeId(s.cnodes.alloc(CNode::empty()).unwrap() as u16);
    let c1 = CNodeId(s.cnodes.alloc(CNode::empty()).unwrap() as u16);
    s.untypeds.alloc(Untyped::new(kani::any())).unwrap();
    s.endpoints.alloc(Endpoint::new()).unwrap();
    s.notifications.alloc(Notification { signals: kani::any(), ..Notification::new() }).unwrap();
    let sc = SchedContextId(s.sched_contexts.alloc(SchedulingContext::new(kani::any())).unwrap() as u16);
    for (t, cspace) in [(CALLER, c0), (OTHERS[0], c1), (OTHERS[1], c1)] {
        let i = s.tcbs.alloc(Tcb { cspace: Some(cspace), sched_context: Some(sc), context: registers(), ..Tcb::new() });
        assert_eq!(i, Some(t.0 as usize));
    }
    s.tcbs.with_mut(0, |t| t.state = ThreadState::Running);
    s.scheduler.current = Some(CALLER);
    s.make_ready(OTHERS[1]);
    s
}

/// Every slot of every CNode: any capability.
fn any_cnodes(s: &mut KernelState) {
    for c in 0..MAX_CNODES {
        s.cnodes.with_mut(c, |cnode| {
            for i in 0..CNODE_SLOTS {
                cnode.set(i, capability());
            }
        });
    }
}

/// The two other threads: any state, with the queue it names, in either order.
fn any_threads(s: &mut KernelState) {
    let order = if kani::any() { OTHERS } else { [OTHERS[1], OTHERS[0]] };
    any_threads_of(s, &order);
}

/// `threads`, in that order: any state, with the queue it names. The others keep the skeleton's.
fn any_threads_of(s: &mut KernelState, threads: &[TcbId]) {
    for &t in threads {
        s.scheduler.ready.remove(t);
    }
    for &t in threads {
        place(s, t, kani::any());
    }
    // The caller owes a reply to a thread blocked in `Call`, or to nobody.
    let owed = maybe(|| OTHERS[kani::any::<bool>() as usize]);
    s.tcbs.with_mut(CALLER.0 as usize, |t| t.reply_to = owed);
}

/// Thread `t` in a state of kind `kind` (0 inactive, 1 ready, 2 sending a capability, 6 sending without one, 7 calling
/// with a capability, 8 calling with neither, 9 calling with a slot for the reply's capability, 3 receiving, 4 waiting
/// for a reply, 5 waiting on a notification; anything else inactive), with everything else about that state arbitrary,
/// in the queue it names.
fn place(s: &mut KernelState, t: TcbId, kind: u8) {
    s.scheduler.ready.remove(t);
    let state = match kind {
        1 => ThreadState::Ready,
        2 | 6..=9 => ThreadState::BlockedSend {
            endpoint: EndpointId(0),
            badge: kani::any(),
            // 2 and 6 are `Send`s, 7 to 9 `Call`s; 2 and 7 carry a capability; 9 names a slot for the reply's. A `Call`
            // never does both (`extra_caps` is 1 or 2, `crate::abi`).
            is_call: kind >= 7,
            extra_cap: if kind == 2 || kind == 7 { Some(capability()) } else { None },
            reply_dest_slot: if kind == 9 { Some(CNODE_SLOTS - 1) } else { None },
        },
        3 => ThreadState::BlockedRecv { endpoint: EndpointId(0), dest_slot: maybe(slot) },
        4 => ThreadState::BlockedReply { dest_slot: maybe(slot) },
        5 => ThreadState::BlockedWait(NotificationId(0)),
        _ => ThreadState::Inactive,
    };
    s.tcbs.with_mut(t.0 as usize, |tcb| tcb.state = state);
    match state {
        ThreadState::Ready => {
            s.scheduler.ready.push_back(t);
        }
        ThreadState::BlockedSend { .. } | ThreadState::BlockedRecv { .. } => {
            let sending = matches!(state, ThreadState::BlockedSend { .. });
            s.endpoints.with_mut(0, |e| match &mut e.queue {
                EndpointQueue::Send(q) if sending => {
                    q.push_back(t);
                }
                EndpointQueue::Recv(q) if !sending => {
                    q.push_back(t);
                }
                EndpointQueue::Empty => {
                    let mut q = crate::queue::ArrayQueue::new();
                    q.push_back(t);
                    e.queue = if sending { EndpointQueue::Send(q) } else { EndpointQueue::Recv(q) };
                }
                // A sender and a receiver on one endpoint: W rejects it, as the kernel never makes it.
                _ => {}
            });
        }
        ThreadState::BlockedWait(_) => {
            s.notifications.with_mut(0, |n| n.waiters.push_back(t));
        }
        _ => {}
    }
}

/// The caller's trap frame for a system call `number`: its own registers, with every argument arbitrary.
fn syscall_frame(s: &KernelState, number: SyscallNumber) -> TrapFrame {
    let mut frame = TrapFrame::zeroed();
    s.tcbs.with(CALLER.0 as usize, |t| t.context.restore_into(&mut frame));
    frame.set_syscall_number(number as usize);
    frame.set_tag(MessageTag { label: kani::any(), length: kani::any(), extra_caps: kani::any(), flags: kani::any() });
    for i in 0..lantern_hal::MR_COUNT {
        frame.set_mr(i, argument());
    }
    frame
}

// ---------------------------------------------------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------------------------------------------------

/// What a capability designates: its kind and pool index, badge and rights aside.
fn designates(cap: &Capability) -> Option<(u8, u16)> {
    Some(match *cap {
        Capability::Null | Capability::Reply { .. } => return None,
        Capability::CNode(id) => (1, id.0),
        Capability::Untyped { id, .. } => (2, id.0),
        Capability::Endpoint { id, .. } => (3, id.0),
        Capability::Notification { id, .. } => (4, id.0),
        Capability::Tcb { id, .. } => (5, id.0),
        Capability::SchedContext { id, .. } => (6, id.0),
        Capability::VSpace { id, .. } => (7, id.0),
        Capability::Frame { id, .. } => (8, id.0),
        Capability::IrqHandler { id, .. } => (9, id.0),
        Capability::Deadline { id, .. } => (10, id.0),
    })
}

fn was_live(before: &KernelState, (kind, i): (u8, u16)) -> bool {
    let i = i as usize;
    match kind {
        1 => before.cnodes.contains(i),
        2 => before.untypeds.contains(i),
        3 => before.endpoints.contains(i),
        4 => before.notifications.contains(i),
        5 => before.tcbs.contains(i),
        6 => before.sched_contexts.contains(i),
        7 => before.vspaces.contains(i),
        8 => before.frames.contains(i),
        9 => before.irq_handlers.contains(i),
        _ => before.deadlines.contains(i),
    }
}

/// Whether `cap` is justified by `old`: the same object, with no right `old` lacks.
fn covers(old: &Capability, cap: &Capability, object: (u8, u16)) -> bool {
    designates(old) == Some(object) && cap.rights().is_subset_of(old.rights())
}

/// The capability a blocked sender has in flight, if any.
fn in_flight(s: &KernelState, t: usize) -> Option<Capability> {
    match s.tcbs.with(t, |tcb| tcb.state)? {
        ThreadState::BlockedSend { extra_cap, .. } => extra_cap,
        _ => None,
    }
}

/// Properties 1 and 2: after the call, every capability names a fresh object (only `UntypedRetype` may make one), or
/// an object something held before (in a CNode, or in flight with a blocked `Send`), with no right it lacked.
fn no_amplification_or_forgery(before: &KernelState, after: &KernelState, fresh_allowed: bool) {
    for c in 0..MAX_CNODES {
        let Some(cnode) = after.cnodes.with(c, |x| *x) else { continue };
        for i in 0..CNODE_SLOTS {
            let cap = cnode.get(i).expect("in range");
            let Some(object) = designates(&cap) else { continue };
            if fresh_allowed && !was_live(before, object) {
                continue;
            }
            let mut justified = false;
            for old_c in 0..MAX_CNODES {
                if let Some(old) = before.cnodes.with(old_c, |x| *x) {
                    for j in 0..CNODE_SLOTS {
                        justified |= covers(&old.get(j).expect("in range"), &cap, object);
                    }
                }
            }
            for t in 0..MAX_TCBS {
                if let Some(old) = in_flight(before, t) {
                    justified |= covers(&old, &cap, object);
                }
            }
            assert!(justified, "a capability with authority nothing held before");
        }
    }
}

fn is_ipc(number: SyscallNumber) -> bool {
    use SyscallNumber::*;
    matches!(number, Send | NBSend | Recv | Call | Reply | Signal | Wait | Poll | Yield)
}

/// Property 3, and for IPC properties 1 and 2 with it: IPC changes CNodes only by moving one capability. Every slot is as
/// it was, except at most one that was empty and now holds a capability with `GRANT` that was in the caller's CSpace, or
/// in flight with a blocked sender, exactly: same object, badge and rights.
fn transfers_exact(before: &KernelState, after: &KernelState) {
    let mut filled = 0;
    for c in 0..MAX_CNODES {
        let (old, new) = (before.cnodes.with(c, |x| *x), after.cnodes.with(c, |x| *x));
        assert!(old.is_some() == new.is_some(), "IPC made or destroyed a CNode");
        let (Some(old), Some(new)) = (old, new) else { continue };
        for i in 0..CNODE_SLOTS {
            let (was, now) = (old.get(i).expect("in range"), new.get(i).expect("in range"));
            if was == now {
                continue;
            }
            assert!(was == Capability::Null, "IPC changed or removed a capability");
            filled += 1;
            assert!(now.rights().contains(Rights::GRANT), "a capability without GRANT moved");
            let mut sent = false;
            if let Some(caller) = before.cnodes.with(0, |x| *x) {
                for j in 0..CNODE_SLOTS {
                    sent |= caller.get(j) == Some(now);
                }
            }
            for t in 0..MAX_TCBS {
                sent |= in_flight(before, t) == Some(now);
            }
            assert!(sent, "a capability arrived that wasn't sent");
        }
    }
    assert!(filled <= 1, "more than one capability arrived");
}

/// Property 8: a thread ready or inactive before the call isn't a party to it, unless the call names it by a thread
/// capability (`named`: `TcbInvoke` sets an inactive thread's first registers), so its registers are exactly as it left
/// them: in the live frame if it now runs, saved otherwise.
fn bystanders_untouched(before: &KernelState, after: &KernelState, frame: &TrapFrame, named: Option<TcbId>) {
    for t in OTHERS {
        let old = before.tcbs.with(t.0 as usize, |x| *x).unwrap();
        if !matches!(old.state, ThreadState::Ready | ThreadState::Inactive) || named == Some(t) {
            continue;
        }
        // Destroyed (by `Reset`): not a bystander, and nothing left to compare.
        let Some(saved) = after.tcbs.with(t.0 as usize, |x| x.context) else { continue };
        let registers = if after.scheduler.current == Some(t) { SavedContext::save_from(frame) } else { saved };
        assert!(registers.same_as(&old.context), "a bystander's registers changed");
    }
}

/// One system call: properties 1, 2, 7 and 8 (and 3 for IPC), and by Kani's own checks 9. With `label`, the call's
/// label is that, not arbitrary: a harness per operation keeps each one tractable.
fn check(s: KernelState, number: SyscallNumber, label: Option<u32>) {
    check_with(s, number, |frame| {
        if let Some(label) = label {
            let tag = frame.tag();
            frame.set_tag(MessageTag { label, ..tag });
        }
    });
}

/// [`check`], with `adjust` fixing part of the call's frame first: a harness per path keeps each one tractable.
fn check_with(mut s: KernelState, number: SyscallNumber, adjust: impl FnOnce(&mut TrapFrame)) {
    kani::assume(crate::wf::check(&s).is_ok());
    let before = s.clone();
    let mut frame = syscall_frame(&s, number);
    adjust(&mut frame);
    // The thread the call names by capability, if it's one that acts on a thread.
    let named = match (number, before.lookup_cap(CALLER, frame.mr(0))) {
        (SyscallNumber::TcbInvoke | SyscallNumber::TCBConfigure, Ok(Capability::Tcb { id, .. })) => Some(id),
        _ => None,
    };
    dispatch(&mut s, &mut frame);
    assert!(crate::wf::check(&s).is_ok(), "W broken");
    if is_ipc(number) {
        // For IPC the stronger statement is also the cheaper one to check, and implies properties 1 and 2.
        transfers_exact(&before, &s);
    } else {
        no_amplification_or_forgery(&before, &s, number == SyscallNumber::UntypedRetype);
    }
    bystanders_untouched(&before, &s, &frame, named);
}

// ---------------------------------------------------------------------------------------------------------------------
// The harnesses
// ---------------------------------------------------------------------------------------------------------------------

/// `CNodeInvoke`, one harness per operation: every CNode slot and every argument arbitrary.
macro_rules! cnode_proofs {
    ($($name:ident => $label:ident),* $(,)?) => {$(
        #[kani::proof]
        fn $name() {
            let mut s = skeleton();
            any_cnodes(&mut s);
            check(s, SyscallNumber::CNodeInvoke, Some(crate::cnode::$label));
        }
    )*};
}

cnode_proofs! {
    cnode_mint => LABEL_MINT,
    cnode_copy => LABEL_COPY,
    cnode_move => LABEL_MOVE,
    cnode_delete => LABEL_DELETE,
    cnode_copy_cross => LABEL_COPY_CROSS,
}

/// `CNodeInvoke` with any other label: refused, and nothing changes.
#[kani::proof]
fn cnode_unknown_label() {
    let mut s = skeleton();
    any_cnodes(&mut s);
    let label: u32 = kani::any();
    kani::assume(!(crate::cnode::LABEL_MINT..=crate::cnode::LABEL_COPY_CROSS).contains(&label));
    check(s, SyscallNumber::CNodeInvoke, Some(label));
}

/// The IPC system calls: every CNode slot, the other threads' states and queues, and every argument arbitrary.
macro_rules! ipc_proofs {
    ($($name:ident => $number:ident),* $(,)?) => {$(
        #[kani::proof]
        fn $name() {
            let mut s = skeleton();
            any_cnodes(&mut s);
            any_threads(&mut s);
            check(s, SyscallNumber::$number, None);
        }
    )*};
}

ipc_proofs! {
    ipc_nb_send => NBSend,
    ipc_reply => Reply,
    ipc_signal => Signal,
    ipc_wait => Wait,
    ipc_poll => Poll,
    ipc_yield => Yield,
}

/// `Send`, `Recv` and `Call`, which can both move a capability and meet another thread: a harness for each value of the
/// tag's `extra_caps` (0: none; 1: a capability to send, or a slot to receive one in; 2: `Call`'s slot for the reply's;
/// anything more is refused), with everything else arbitrary as for the other IPC harnesses.
macro_rules! ipc_split_proofs {
    ($($name:ident => $number:ident, $extra:expr);* $(;)?) => {$(
        #[kani::proof]
        fn $name() {
            let mut s = skeleton();
            any_cnodes(&mut s);
            any_threads(&mut s);
            check_with(s, SyscallNumber::$number, |frame| {
                let tag = frame.tag();
                let extra_caps: u8 = $extra;
                frame.set_tag(MessageTag { extra_caps, ..tag });
            });
        }
    )*};
}

fn more_than_two() -> u8 {
    let n: u8 = kani::any();
    kani::assume(n > 2);
    n
}

ipc_split_proofs! {
    ipc_send_plain => Send, 0;
    ipc_send_transfer => Send, 1;
    ipc_send_refused => Send, { let n: u8 = kani::any(); kani::assume(n > 1); n };
    ipc_recv_plain => Recv, 0;
    ipc_recv_transfer => Recv, 1;
    ipc_recv_refused => Recv, { let n: u8 = kani::any(); kani::assume(n > 1); n };
    ipc_call_plain => Call, 0;
    ipc_call_transfer => Call, 1;
    ipc_call_reply_slot => Call, 2;
    ipc_call_refused => Call, more_than_two();
}

/// The harnesses must not be vacuous: the skeleton is well-formed, and with arbitrary CNodes and threads some states
/// still are, with the caller holding a capability and another thread blocked.
#[kani::proof]
fn skeleton_is_well_formed() {
    let mut s = skeleton();
    assert!(crate::wf::check(&s).is_ok(), "the skeleton itself");
    any_cnodes(&mut s);
    any_threads(&mut s);
    let held = s.cnodes.with(0, |c| c.get(0) != Some(Capability::Null)).unwrap();
    let blocked = s.tcbs.with(1, |t| matches!(t.state, ThreadState::BlockedRecv { .. })).unwrap();
    kani::cover!(crate::wf::check(&s).is_ok() && held && blocked);
}

// ---------------------------------------------------------------------------------------------------------------------
// Reclamation, retyping, lookup
// ---------------------------------------------------------------------------------------------------------------------

/// Whether `origin` is the `Untyped` being reset, or its child.
fn doomed_origin(before: &KernelState, origin: Option<UntypedId>) -> bool {
    match origin {
        Some(UntypedId(0)) => true,
        Some(u) => before.untypeds.with(u.0 as usize, |u| u.origin == Some(UntypedId(0))).unwrap_or(false),
        None => false,
    }
}

/// Properties 5 and 6, for `Reset` of `Untyped` 0 (W after it is property 5's "nothing dangling"): an object is destroyed
/// exactly when it was made from that `Untyped` or its child, and the `Untyped` is empty again.
fn reset_exact(before: &KernelState, after: &KernelState) {
    macro_rules! exact {
        ($pool:ident, $max:ident) => {
            for i in 0..$max {
                if before.$pool.contains(i) {
                    let gone = !after.$pool.contains(i);
                    assert!(gone == doomed_origin(before, before.origins.$pool[i]), "Reset destroyed the wrong objects");
                }
            }
        };
    }
    exact!(cnodes, MAX_CNODES);
    exact!(tcbs, MAX_TCBS);
    exact!(endpoints, MAX_ENDPOINTS);
    exact!(notifications, MAX_NOTIFICATIONS);
    exact!(sched_contexts, MAX_SCHED_CONTEXTS);
    // The child `Untyped` goes; the reset one stays, empty.
    for i in 1..MAX_UNTYPEDS {
        if before.untypeds.contains(i) {
            let gone = !after.untypeds.contains(i);
            assert!(gone == doomed_origin(before, before.untypeds.with(i, |u| u.origin).unwrap()), "the wrong Untypeds went");
        }
    }
    assert!(after.untypeds.with(0, |u| u.remaining == u.budget()).unwrap(), "the Untyped wasn't emptied");
}

/// `Reset`'s effect on capabilities: it only removes them. Every slot holds what it did, or nothing. That implies
/// properties 1 and 2 for `Reset`, and is cheaper to check.
fn only_removes(before: &KernelState, after: &KernelState) {
    for c in 0..MAX_CNODES {
        let (Some(old), Some(new)) = (before.cnodes.with(c, |x| *x), after.cnodes.with(c, |x| *x)) else { continue };
        for i in 0..CNODE_SLOTS {
            let now = new.get(i).expect("in range");
            assert!(now == old.get(i).expect("in range") || now == Capability::Null, "Reset changed a capability");
        }
    }
}

/// `Revoke` on `Untyped` 0, which is `Reset`: from the skeleton, with `vary` making part of it arbitrary and `made` saying
/// which objects came from which `Untyped`. The caller holds its own CNode in slot 0 and the `Untyped`, with any rights,
/// in slot 1, so the call reaches `Reset` whenever the rights allow.
fn check_reset(made: impl FnOnce(&mut KernelState), vary: impl FnOnce(&mut KernelState)) {
    let mut s = skeleton();
    vary(&mut s);
    made(&mut s);
    let untyped_rights = rights();
    s.cnodes.with_mut(0, |c| {
        c.set(0, Capability::CNode(CNodeId(0)));
        c.set(1, Capability::Untyped { id: UntypedId(0), rights: untyped_rights });
    });
    kani::assume(crate::wf::check(&s).is_ok());
    let before = s.clone();
    let mut frame = syscall_frame(&s, SyscallNumber::CNodeInvoke);
    let tag = frame.tag();
    frame.set_tag(MessageTag { label: crate::cnode::LABEL_REVOKE, ..tag });
    frame.set_mr(0, 0);
    frame.set_mr(1, 1);
    dispatch(&mut s, &mut frame);
    assert!(crate::wf::check(&s).is_ok(), "W broken");
    only_removes(&before, &s);
    bystanders_untouched(&before, &s, &frame, None);
    if !frame.tag().is_error() {
        reset_exact(&before, &s);
    }
}

/// Thread `doomed` made from `Untyped` 0, and thread 1 in a state of kind `kind` (see [`place`]), with the caller owing
/// it a reply, or not. With `doomed` 1 that's the thread `Reset` destroys; with `doomed` 0 it's the caller, beside it.
fn destroyed_thread(s: &mut KernelState, doomed: usize, kind: u8) {
    s.origins.tcbs[doomed] = Some(UntypedId(0));
    place(s, OTHERS[0], kind);
    let owed = maybe(|| OTHERS[0]);
    s.tcbs.with_mut(CALLER.0 as usize, |t| t.reply_to = owed);
}

/// A child of `Untyped` 0, carved from it, at index 1.
fn child_untyped(s: &mut KernelState) {
    let mut child = Untyped::new(kani::any());
    child.origin = Some(UntypedId(0));
    s.untypeds.alloc(child);
}

/// `Reset`, a harness per object it destroys, each with arbitrary exactly what that object touches: the CNodes (and
/// capabilities to it), or the other threads (and threads blocked on it, or it itself), or both. Which object came from
/// the `Untyped` is fixed per harness; everything else was made at boot and survives. Page-table walks are the stubs.
macro_rules! reset_proofs {
    ($($name:ident => |$s:ident| $made:block, $cnodes:expr, $threads:expr);* $(;)?) => {$(
        // Every loop `Reset` runs is at most 5 iterations at these pool sizes (4 CNode slots, plus one to leave): the
        // tighter bound keeps the harness within 16 GB, and Kani's unwinding assertions still fail it if a loop needs more.
        #[kani::proof]
        #[kani::unwind(5)]
        #[kani::stub(lantern_hal::riscv64_unmap, stubs::unmap)]
        #[kani::stub(lantern_hal::riscv64_for_each_table, stubs::for_each_table)]
        fn $name() {
            check_reset(
                |$s: &mut KernelState| $made,
                |s| {
                    if $cnodes {
                        any_cnodes(s);
                    }
                    if $threads {
                        any_threads(s);
                    }
                },
            );
        }
    )*};
}

reset_proofs! {
    reset_cnode => |s| { s.origins.cnodes[1] = Some(UntypedId(0)); }, true, false;
    reset_own_cnode => |s| { s.origins.cnodes[0] = Some(UntypedId(0)); }, true, false;
    reset_other_thread_inactive => |s| { destroyed_thread(s, 1, 0); }, false, false;
    reset_other_thread_ready => |s| { destroyed_thread(s, 1, 1); }, false, false;
    reset_other_thread_sending_a_capability => |s| { destroyed_thread(s, 1, 2); }, false, false;
    reset_other_thread_sending_nothing => |s| { destroyed_thread(s, 1, 6); }, false, false;
    reset_other_thread_calling_with_a_capability => |s| { destroyed_thread(s, 1, 7); }, false, false;
    reset_other_thread_calling_with_nothing => |s| { destroyed_thread(s, 1, 8); }, false, false;
    reset_other_thread_calling_with_a_reply_slot => |s| { destroyed_thread(s, 1, 9); }, false, false;
    reset_other_thread_receiving => |s| { destroyed_thread(s, 1, 3); }, false, false;
    reset_other_thread_awaiting_reply => |s| { destroyed_thread(s, 1, 4); }, false, false;
    reset_other_thread_waiting => |s| { destroyed_thread(s, 1, 5); }, false, false;
    reset_own_thread_beside_inactive => |s| { destroyed_thread(s, 0, 0); }, false, false;
    reset_own_thread_beside_ready => |s| { destroyed_thread(s, 0, 1); }, false, false;
    reset_own_thread_beside_sending_a_capability => |s| { destroyed_thread(s, 0, 2); }, false, false;
    reset_own_thread_beside_sending_nothing => |s| { destroyed_thread(s, 0, 6); }, false, false;
    reset_own_thread_beside_calling_with_a_capability => |s| { destroyed_thread(s, 0, 7); }, false, false;
    reset_own_thread_beside_calling_with_nothing => |s| { destroyed_thread(s, 0, 8); }, false, false;
    reset_own_thread_beside_calling_with_a_reply_slot => |s| { destroyed_thread(s, 0, 9); }, false, false;
    reset_own_thread_beside_receiving => |s| { destroyed_thread(s, 0, 3); }, false, false;
    reset_own_thread_beside_awaiting_reply => |s| { destroyed_thread(s, 0, 4); }, false, false;
    reset_own_thread_beside_waiting => |s| { destroyed_thread(s, 0, 5); }, false, false;
    reset_endpoint_and_capabilities => |s| { s.origins.endpoints[0] = Some(UntypedId(0)); }, true, false;
    reset_endpoint_and_blocked_threads => |s| { s.origins.endpoints[0] = Some(UntypedId(0)); }, false, true;
    reset_notification_and_capabilities => |s| { s.origins.notifications[0] = Some(UntypedId(0)); }, true, false;
    reset_notification_and_waiters => |s| { s.origins.notifications[0] = Some(UntypedId(0)); }, false, true;
    reset_sched_context => |s| { s.origins.sched_contexts[0] = Some(UntypedId(0)); }, true, false;
    reset_descendant => |s| { child_untyped(s); s.origins.endpoints[0] = Some(UntypedId(1)); }, true, false;
    reset_nothing_made => |s| { child_untyped(s); }, true, false;
}

/// Property 4: a thread reaches capabilities only through its own CSpace. Whatever `lookup_cap` returns for any thread
/// and slot number is what that thread's own CNode holds there.
#[kani::proof]
fn lookup_is_confined() {
    let mut s = skeleton();
    any_cnodes(&mut s);
    kani::assume(crate::wf::check(&s).is_ok());
    let t = TcbId(id(MAX_TCBS));
    let cptr = argument();
    if let Ok(cap) = s.lookup_cap(t, cptr) {
        let cspace = s.tcbs.with(t.0 as usize, |t| t.cspace).flatten().expect("a lookup succeeded");
        assert_eq!(s.cnodes.with(cspace.0 as usize, |c| c.get(cptr)), Some(Some(cap)), "found somewhere else");
        assert!(cap != Capability::Null);
    }
}

/// `UntypedRetype`, a harness per object type (`mr1`), and one for an invalid type: every CNode slot and every other
/// argument arbitrary. New objects are the only capabilities allowed to be fresh. The `Untyped` has physical memory
/// behind it, or not, so Frames and child `Untyped`s are reached too; zeroing a new Frame's RAM is the stub. (Under Kani
/// there are no kernel page-table pages, so making a VSpace only reaches its refusal.)
macro_rules! retype_proofs {
    ($($name:ident => $kind:expr);* $(;)?) => {$(
        #[kani::proof]
        #[kani::stub(crate::admin::zero_ram, stubs::zero_ram)]
        fn $name() {
            let mut s = skeleton();
            if kani::any() {
                let (budget, base, len): (usize, usize, usize) = (kani::any(), kani::any(), kani::any());
                // Boot code makes these, from real memory: a range that doesn't wrap the address space.
                kani::assume(base.checked_add(len).is_some());
                s.untypeds.with_mut(0, |u| *u = Untyped::with_memory(budget, base, len));
            }
            any_cnodes(&mut s);
            check_with(s, SyscallNumber::UntypedRetype, |frame| frame.set_mr(1, $kind));
        }
    )*};
}

retype_proofs! {
    retype_cnode => 0;
    retype_untyped => 1;
    retype_endpoint => 2;
    retype_notification => 3;
    retype_tcb => 4;
    retype_sched_context => 5;
    retype_vspace => 6;
    retype_frame_small => 7;
    retype_frame_mega => 8;
    retype_invalid => { let k: usize = kani::any(); kani::assume(k > 8); k };
}

/// `TCBConfigure` and `TcbInvoke`: every CNode slot, the other threads, and every argument arbitrary.
#[kani::proof]
fn tcb_configure() {
    let mut s = skeleton();
    any_cnodes(&mut s);
    any_threads(&mut s);
    check(s, SyscallNumber::TCBConfigure, None);
}

#[kani::proof]
#[kani::stub(<lantern_hal::Hardware as lantern_hal::Hal>::initial_trap_frame, stubs::initial_trap_frame)]
fn tcb_invoke() {
    let mut s = skeleton();
    any_cnodes(&mut s);
    any_threads(&mut s);
    check(s, SyscallNumber::TcbInvoke, None);
}

// ---------------------------------------------------------------------------------------------------------------------
// Devices and the clock: Frames and VSpaces, interrupt lines, deadlines
// ---------------------------------------------------------------------------------------------------------------------

/// Any capability, devices' and memory's included. Only the harnesses for those use it: the wider choice costs.
fn device_capability() -> Capability {
    match kani::any::<u8>() {
        7 => Capability::VSpace { id: VSpaceId(id(MAX_VSPACES)), rights: rights() },
        8 => Capability::Frame { id: FrameId(id(MAX_FRAMES)), rights: rights() },
        9 => Capability::IrqHandler { id: IrqHandlerId(id(MAX_IRQ_HANDLERS)), rights: rights() },
        10 => Capability::Deadline { id: DeadlineId(id(MAX_DEADLINES)), rights: rights() },
        _ => capability(),
    }
}

/// One VSpace, one Frame (mapped into it at any address, or not), one interrupt line and one deadline, each bound to the
/// notification or not; and every CNode slot any capability, theirs included.
fn devices(s: &mut KernelState) {
    s.vspaces.alloc(VSpace { root: 0x1000 });
    let mapped = maybe(|| (VSpaceId(0), kani::any()));
    s.frames.alloc(Frame {
        paddr: kani::any(),
        size: if kani::any() { FrameSize::Small } else { FrameSize::Mega },
        mapped_at: [mapped, None],
        dma: kani::any(),
    });
    let bound = || maybe(|| (NotificationId(0), kani::any::<u64>()));
    s.irq_handlers.alloc(IrqHandler { line: kani::any(), notification: bound(), pending: kani::any() });
    s.deadlines.alloc(Deadline { notification: bound(), at: kani::any() });
    for c in 0..MAX_CNODES {
        s.cnodes.with_mut(c, |cnode| {
            for i in 0..CNODE_SLOTS {
                cnode.set(i, device_capability());
            }
        });
    }
}

/// An invocation on a device object, a harness per label (and one for any other label), with [`devices`] and the
/// other threads arbitrary. Page-table walks are the stubs.
macro_rules! device_proofs {
    ($($name:ident => $number:ident, $label:expr);* $(;)?) => {$(
        #[kani::proof]
        #[kani::stub(lantern_hal::riscv64_unmap, stubs::unmap)]
        #[kani::stub(lantern_hal::riscv64_map_page, stubs::map)]
        #[kani::stub(lantern_hal::riscv64_map_megapage, stubs::map)]
        #[kani::stub(lantern_hal::riscv64_translate, stubs::translate)]
        fn $name() {
            let mut s = skeleton();
            devices(&mut s);
            any_threads(&mut s);
            check(s, SyscallNumber::$number, Some($label));
        }
    )*};
}

fn label_beyond(last: u32) -> u32 {
    let l: u32 = kani::any();
    kani::assume(l == 0 || l > last);
    l
}

device_proofs! {
    frame_map => FrameInvoke, crate::frame::LABEL_MAP;
    frame_unmap => FrameInvoke, crate::frame::LABEL_UNMAP;
    frame_address => FrameInvoke, crate::frame::LABEL_ADDRESS;
    frame_unknown_label => FrameInvoke, label_beyond(crate::frame::LABEL_ADDRESS);
    irq_set_notification => IrqHandlerInvoke, crate::irq::LABEL_SET_NOTIFICATION;
    irq_clear => IrqHandlerInvoke, crate::irq::LABEL_CLEAR;
    irq_ack => IrqHandlerInvoke, crate::irq::LABEL_ACK;
    irq_unknown_label => IrqHandlerInvoke, label_beyond(crate::irq::LABEL_ACK);
    deadline_set_notification => DeadlineInvoke, crate::deadline::LABEL_SET_NOTIFICATION;
    deadline_arm => DeadlineInvoke, crate::deadline::LABEL_ARM;
    deadline_cancel => DeadlineInvoke, crate::deadline::LABEL_CANCEL;
    deadline_now => DeadlineInvoke, crate::deadline::LABEL_NOW;
    deadline_unknown_label => DeadlineInvoke, label_beyond(crate::deadline::LABEL_NOW);
}

// ---------------------------------------------------------------------------------------------------------------------
// Traps: the timer, a fault, an interrupt
// ---------------------------------------------------------------------------------------------------------------------

/// The hardware, for the trap harnesses: the clock reads anything, a line is pending or not, the timer has fired or
/// not. Every other call does nothing. Arbitrary answers cover every real one, and more.
struct KaniHal;

impl lantern_hal::Hal for KaniHal {
    unsafe fn install_trap_handler(_: lantern_hal::TrapHandler) {}
    fn initial_trap_frame(_: usize, _: usize, _: usize) -> TrapFrame {
        TrapFrame::zeroed()
    }
    unsafe fn enter_thread(_: &TrapFrame) -> ! {
        unreachable!("a trap never enters a thread")
    }
    unsafe fn activate_address_space(_: usize) {}
    fn monotonic_time_ns() -> u64 {
        kani::any()
    }
    unsafe fn init_interrupts() {}
    fn interrupt_line_enable(_: u32, _: bool) {}
    fn interrupt_claim() -> u32 {
        if kani::any() { 0 } else { kani::any() }
    }
    fn interrupt_complete(_: u32) {}
    fn set_timer(_: u64) {}
    fn timer_pending() -> bool {
        kani::any()
    }
    fn wait_for_interrupt() {}
    fn ram_window(paddr: usize, _: usize) -> Option<usize> {
        Some(paddr)
    }
}

/// A trap of `cause` while the caller runs: W after it, no capability changed, and bystanders' registers untouched.
/// Another thread is ready, so the trap never reaches the idle loop: that loop waits until an interrupt makes a thread
/// ready, which no bound covers, and it isn't part of these proofs.
fn check_trap(mut s: KernelState, cause: lantern_hal::TrapCause) {
    kani::assume(crate::wf::check(&s).is_ok());
    kani::assume(s.scheduler.has_ready());
    let before = s.clone();
    let mut frame = syscall_frame(&s, SyscallNumber::Yield);
    frame.set_cause(cause);
    crate::handle_trap::<KaniHal>(&mut s, &mut frame);
    assert!(crate::wf::check(&s).is_ok(), "W broken");
    for c in 0..MAX_CNODES {
        assert!(before.cnodes.with(c, |x| *x).map(|x| x.slots_eq(&s.cnodes.with(c, |y| *y).unwrap()))
            .unwrap_or(true), "a trap changed a capability");
    }
    bystanders_untouched(&before, &s, &frame, None);
}

#[kani::proof]
fn trap_timer() {
    let mut s = skeleton();
    any_threads(&mut s);
    s.slice_end = kani::any();
    s.timer_owner = maybe(|| CALLER);
    check_trap(s, lantern_hal::TrapCause::TimerInterrupt);
}

#[kani::proof]
fn trap_fault() {
    let mut s = skeleton();
    any_threads(&mut s);
    check_trap(s, lantern_hal::TrapCause::Fault { cause: kani::any(), value: kani::any() });
}

/// An interrupt never reads a capability, so the CNodes stay as the skeleton has them: what's arbitrary is the line (and
/// whether it's bound, and pending), the deadline, the other threads, and every answer the hardware gives.
#[kani::proof]
fn trap_interrupt() {
    let mut s = skeleton();
    let bound = || maybe(|| (NotificationId(0), kani::any::<u64>()));
    s.irq_handlers.alloc(IrqHandler { line: kani::any(), notification: bound(), pending: kani::any() });
    s.deadlines.alloc(Deadline { notification: bound(), at: kani::any() });
    any_threads(&mut s);
    check_trap(s, lantern_hal::TrapCause::ExternalInterrupt);
}


// ---------------------------------------------------------------------------------------------------------------------
// The Kani-only accessors agree with the ones that run
// ---------------------------------------------------------------------------------------------------------------------

/// `Pool::with` and `with_mut` under Kani find a slot by comparing indices; outside Kani they index directly. Both reach
/// the same slot, by address, for any contents and any index, in range or not. The lookup doesn't depend on the element
/// type beyond `Option`'s, so a pool of bytes stands for every pool.
#[kani::proof]
fn pool_lookups_agree() {
    let slots: [Option<u8>; 3] = [kani::any(), kani::any(), kani::any()];
    let mut pool = crate::pool::Pool::from_slots(slots);
    let index: usize = kani::any();
    let direct = pool.get_by_index(index).map(|r| r as *const u8);
    assert_eq!(pool.with(index, |r| r as *const u8), direct);
    let direct_mut = pool.get_mut_by_index(index).map(|r| r as *mut u8 as *const u8);
    assert_eq!(pool.with_mut(index, |r| r as *mut u8 as *const u8), direct_mut);
}

/// As `pool_lookups_agree`, for a CNode's slots: `get` reads what indexing reads, and `set` writes what indexing writes,
/// for any slot number.
#[kani::proof]
fn cnode_lookups_agree() {
    let mut a = CNode::empty();
    for i in 0..CNODE_SLOTS {
        a.set_by_index(i, capability());
    }
    let mut b = a;
    let cptr: usize = kani::any();
    assert_eq!(a.get(cptr), a.get_by_index(cptr).copied());
    let cap = capability();
    assert_eq!(a.set(cptr, cap), b.set_by_index(cptr, cap));
    for i in 0..CNODE_SLOTS {
        assert_eq!(a.get_by_index(i), b.get_by_index(i));
    }
}

/// As `pool_lookups_agree`, for a queue's element accesses: reading and writing any position in range by comparison
/// does exactly what indexing does.
#[kani::proof]
fn queue_access_agrees() {
    let mut a: crate::queue::ArrayQueue<u8, 3> = crate::queue::ArrayQueue::new();
    for i in 0..3 {
        a.set_by_index(i, kani::any());
    }
    let mut b = a;
    let i: usize = kani::any();
    kani::assume(i < 3);
    assert_eq!(a.get_at_for_proof(i), a.get_by_index(i));
    let v: Option<u8> = kani::any();
    a.set_at_for_proof(i, v);
    b.set_by_index(i, v);
    for j in 0..3 {
        assert_eq!(a.get_by_index(j), b.get_by_index(j));
    }
}
