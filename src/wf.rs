//! W, the kernel's well-formedness invariant ([RFC-0037](../../lantern-rfcs/rfcs/0037-formal-verification-first-properties.md)).
//!
//! Every reachable state satisfies it. The Kani proofs assume it of the state before an operation and prove it of the
//! state after. In debug builds and host tests the kernel also checks it after every syscall and trap, at full pool
//! sizes. Release kernels don't call it.
//!
//! [`check`] returns the first clause that fails, so a violation says which promise was broken.
//!
//! It's written with index loops, not iterator chains: Kani (RFC-0037) encodes an iterator over the kernel's large
//! objects so expensively that the proofs exhaust memory.

use crate::cap::{Capability, CNodeId, EndpointId, NotificationId, Rights, TcbId, UntypedId};
use crate::limits::{
    CNODE_SLOTS, MAX_CNODES, MAX_DEADLINES, MAX_ENDPOINTS, MAX_FRAMES, MAX_IRQ_HANDLERS, MAX_NOTIFICATIONS,
    MAX_SCHED_CONTEXTS, MAX_TCBS, MAX_UNTYPEDS, MAX_VSPACES,
};
use crate::object::{EndpointQueue, ThreadState};
use crate::state::KernelState;

/// Which clause of W failed, and where.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Violation {
    /// A pool or queue's bookkeeping disagrees with its contents.
    Bookkeeping,
    /// A capability in a live CNode names nothing live, of its type.
    DanglingCapability { cnode: CNodeId, slot: usize },
    /// A reply capability is stored. None ever should be (it's implicit in `reply_to`).
    StoredReply { cnode: CNodeId, slot: usize },
    /// A thread's CSpace, scheduling context, reply link, wait or fault notification names nothing live, or a capability
    /// it's sending can't be sent.
    DanglingThreadReference(TcbId),
    /// A queue holds a thread that isn't live.
    QueuedDeadThread(TcbId),
    /// A thread is in more than one queue, or twice in one.
    QueuedTwice(TcbId),
    /// A queued thread's state doesn't say it's waiting there.
    QueueStateMismatch(TcbId),
    /// A thread's state says it's waiting in a queue it isn't in.
    MissingFromQueue(TcbId),
    /// An endpoint holds an empty send or receive queue (an empty one is `Empty`).
    EmptyEndpointQueue(EndpointId),
    /// The current thread is dead, not `Running`, or queued; or a thread is `Running` without being current.
    CurrentThread(Option<TcbId>),
    /// An object's recorded origin is not a live `Untyped`.
    DanglingOrigin,
    /// A Frame's mapping, an interrupt line's or a deadline's binding names nothing live.
    DanglingBinding,
}

/// Checks W. `Ok` if every clause holds.
pub fn check(state: &KernelState) -> Result<(), Violation> {
    bookkeeping(state)?;
    capabilities(state)?;
    threads(state)?;
    queues(state)?;
    current(state)?;
    origins(state)?;
    bindings(state)
}

pub(crate) fn bookkeeping(s: &KernelState) -> Result<(), Violation> {
    let mut ok = s.cnodes.consistent()
        && s.tcbs.consistent()
        && s.endpoints.consistent()
        && s.notifications.consistent()
        && s.untypeds.consistent()
        && s.sched_contexts.consistent()
        && s.vspaces.consistent()
        && s.frames.consistent()
        && s.irq_handlers.consistent()
        && s.deadlines.consistent()
        && s.scheduler.ready.consistent();
    for n in 0..MAX_NOTIFICATIONS {
        if let Some(notification) = s.notifications.with(n, |x| *x) {
            ok &= notification.waiters.consistent();
        }
    }
    for e in 0..MAX_ENDPOINTS {
        if let Some(endpoint) = s.endpoints.with(e, |x| *x) {
            if let EndpointQueue::Send(q) | EndpointQueue::Recv(q) = endpoint.queue {
                ok &= q.consistent();
            }
        }
    }
    if ok {
        Ok(())
    } else {
        Err(Violation::Bookkeeping)
    }
}

fn live_cap(s: &KernelState, cap: &Capability) -> bool {
    let i = |id: u16| id as usize;
    match *cap {
        Capability::Null => true,
        Capability::CNode(id) => s.cnodes.contains(i(id.0)),
        Capability::Untyped { id, .. } => s.untypeds.contains(i(id.0)),
        Capability::Endpoint { id, .. } => s.endpoints.contains(i(id.0)),
        Capability::Notification { id, .. } => s.notifications.contains(i(id.0)),
        Capability::Tcb { id, .. } => s.tcbs.contains(i(id.0)),
        Capability::SchedContext { id, .. } => s.sched_contexts.contains(i(id.0)),
        Capability::VSpace { id, .. } => s.vspaces.contains(i(id.0)),
        Capability::Frame { id, .. } => s.frames.contains(i(id.0)),
        Capability::IrqHandler { id, .. } => s.irq_handlers.contains(i(id.0)),
        Capability::Deadline { id, .. } => s.deadlines.contains(i(id.0)),
        Capability::Reply { .. } => false,
    }
}

pub(crate) fn capabilities(s: &KernelState) -> Result<(), Violation> {
    for c in 0..MAX_CNODES {
        let Some(cnode) = s.cnodes.with(c, |x| *x) else { continue };
        for slot in 0..CNODE_SLOTS {
            let cap = cnode.get(slot).expect("in range");
            let at = CNodeId(c as u16);
            if matches!(cap, Capability::Reply { .. }) {
                return Err(Violation::StoredReply { cnode: at, slot });
            }
            if !live_cap(s, &cap) {
                return Err(Violation::DanglingCapability { cnode: at, slot });
            }
        }
    }
    Ok(())
}

fn live_notification(s: &KernelState, n: NotificationId) -> bool {
    s.notifications.contains(n.0 as usize)
}

pub(crate) fn threads(s: &KernelState) -> Result<(), Violation> {
    for t in 0..MAX_TCBS {
        let Some(tcb) = s.tcbs.with(t, |x| *x) else { continue };
        let ok = tcb.cspace.is_none_or(|c| s.cnodes.contains(c.0 as usize))
            && tcb.sched_context.is_none_or(|sc| s.sched_contexts.contains(sc.0 as usize))
            && tcb.fault_notification.is_none_or(|(n, _)| live_notification(s, n))
            && tcb.reply_to.is_none_or(|r| {
                s.tcbs.with(r.0 as usize, |caller| matches!(caller.state, ThreadState::BlockedReply { .. })).unwrap_or(false)
            })
            && match tcb.state {
                // A capability in flight was checked when it was sent: it can be sent, and it names something live.
                ThreadState::BlockedSend { endpoint, extra_cap, .. } => {
                    s.endpoints.contains(endpoint.0 as usize)
                        && extra_cap.is_none_or(|c| c.rights().contains(Rights::GRANT) && live_cap(s, &c))
                }
                ThreadState::BlockedRecv { endpoint, .. } => s.endpoints.contains(endpoint.0 as usize),
                ThreadState::BlockedWait(n) => live_notification(s, n),
                _ => true,
            };
        if !ok {
            return Err(Violation::DanglingThreadReference(TcbId(t as u16)));
        }
    }
    Ok(())
}

/// Where a thread is queued, as the queues say.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Nowhere,
    Ready,
    Sending(EndpointId),
    Receiving(EndpointId),
    Waiting(NotificationId),
}

/// Records that the queues put `t` at `p`.
fn put(s: &KernelState, place: &mut [Place; MAX_TCBS], t: TcbId, p: Place) -> Result<(), Violation> {
    let i = t.0 as usize;
    if i >= MAX_TCBS || !s.tcbs.contains(i) {
        return Err(Violation::QueuedDeadThread(t));
    }
    let mut already = false;
    for (j, slot) in place.iter_mut().enumerate() {
        if j == i {
            already = *slot != Place::Nowhere;
            *slot = p;
        }
    }
    if already {
        Err(Violation::QueuedTwice(t))
    } else {
        Ok(())
    }
}

pub(crate) fn queues(s: &KernelState) -> Result<(), Violation> {
    let mut place = [Place::Nowhere; MAX_TCBS];
    let ready = &s.scheduler.ready;
    for k in 0..ready.len() {
        put(s, &mut place, ready.nth(k).expect("within len"), Place::Ready)?;
    }
    for e in 0..MAX_ENDPOINTS {
        let Some(endpoint) = s.endpoints.with(e, |x| *x) else { continue };
        let id = EndpointId(e as u16);
        let (q, p) = match endpoint.queue {
            EndpointQueue::Empty => continue,
            EndpointQueue::Send(q) => (q, Place::Sending(id)),
            EndpointQueue::Recv(q) => (q, Place::Receiving(id)),
        };
        if q.is_empty() {
            return Err(Violation::EmptyEndpointQueue(id));
        }
        for k in 0..q.len() {
            put(s, &mut place, q.nth(k).expect("within len"), p)?;
        }
    }
    for n in 0..MAX_NOTIFICATIONS {
        let Some(notification) = s.notifications.with(n, |x| *x) else { continue };
        let waiters = &notification.waiters;
        for k in 0..waiters.len() {
            put(s, &mut place, waiters.nth(k).expect("within len"), Place::Waiting(NotificationId(n as u16)))?;
        }
    }
    // Each thread's state and its place agree, both ways.
    for (t, actual) in place.iter().enumerate() {
        let Some(tcb) = s.tcbs.with(t, |x| *x) else { continue };
        let id = TcbId(t as u16);
        let expected = match tcb.state {
            ThreadState::Ready => Place::Ready,
            ThreadState::BlockedSend { endpoint, .. } => Place::Sending(endpoint),
            ThreadState::BlockedRecv { endpoint, .. } => Place::Receiving(endpoint),
            ThreadState::BlockedWait(n) => Place::Waiting(n),
            ThreadState::Inactive | ThreadState::Running | ThreadState::BlockedReply { .. } => Place::Nowhere,
        };
        if *actual != expected {
            return Err(if *actual == Place::Nowhere {
                Violation::MissingFromQueue(id)
            } else {
                Violation::QueueStateMismatch(id)
            });
        }
    }
    Ok(())
}

pub(crate) fn current(s: &KernelState) -> Result<(), Violation> {
    let current = s.scheduler.current;
    if let Some(t) = current {
        if !s.tcbs.with(t.0 as usize, |tcb| tcb.state == ThreadState::Running).unwrap_or(false) {
            return Err(Violation::CurrentThread(current));
        }
    }
    // `queues` already holds a `Running` thread to no queue; here, only the current one may be `Running`.
    for t in 0..MAX_TCBS {
        if s.tcbs.with(t, |tcb| tcb.state == ThreadState::Running).unwrap_or(false) && current != Some(TcbId(t as u16)) {
            return Err(Violation::CurrentThread(current));
        }
    }
    Ok(())
}

fn live_untyped(s: &KernelState, u: Option<UntypedId>) -> bool {
    u.is_none_or(|u| s.untypeds.contains(u.0 as usize))
}

pub(crate) fn origins(s: &KernelState) -> Result<(), Violation> {
    let o = &s.origins;
    let mut ok = true;
    for i in 0..MAX_CNODES {
        ok &= !s.cnodes.contains(i) || live_untyped(s, o.cnodes[i]);
    }
    for i in 0..MAX_TCBS {
        ok &= !s.tcbs.contains(i) || live_untyped(s, o.tcbs[i]);
    }
    for i in 0..MAX_ENDPOINTS {
        ok &= !s.endpoints.contains(i) || live_untyped(s, o.endpoints[i]);
    }
    for i in 0..MAX_NOTIFICATIONS {
        ok &= !s.notifications.contains(i) || live_untyped(s, o.notifications[i]);
    }
    for i in 0..MAX_SCHED_CONTEXTS {
        ok &= !s.sched_contexts.contains(i) || live_untyped(s, o.sched_contexts[i]);
    }
    for i in 0..MAX_VSPACES {
        ok &= !s.vspaces.contains(i) || live_untyped(s, o.vspaces[i]);
    }
    for i in 0..MAX_FRAMES {
        ok &= !s.frames.contains(i) || live_untyped(s, o.frames[i]);
    }
    for i in 0..MAX_UNTYPEDS {
        ok &= s.untypeds.with(i, |u| live_untyped(s, u.origin)).unwrap_or(true);
    }
    if ok {
        Ok(())
    } else {
        Err(Violation::DanglingOrigin)
    }
}

pub(crate) fn bindings(s: &KernelState) -> Result<(), Violation> {
    let mut ok = true;
    for i in 0..MAX_FRAMES {
        let Some(frame) = s.frames.with(i, |x| *x) else { continue };
        for mapping in frame.mapped_at {
            ok &= mapping.is_none_or(|(v, _)| s.vspaces.contains(v.0 as usize));
        }
    }
    for i in 0..MAX_IRQ_HANDLERS {
        ok &= s.irq_handlers.with(i, |h| h.notification.is_none_or(|(n, _)| live_notification(s, n))).unwrap_or(true);
    }
    for i in 0..MAX_DEADLINES {
        ok &= s.deadlines.with(i, |d| d.notification.is_none_or(|(n, _)| live_notification(s, n))).unwrap_or(true);
    }
    if ok {
        Ok(())
    } else {
        Err(Violation::DanglingBinding)
    }
}

/// Checks W in debug builds, and does nothing in release builds, or under Kani, whose harnesses check W themselves.
#[inline]
pub fn debug_check(state: &KernelState) {
    if cfg!(debug_assertions) && !cfg!(kani) {
        if let Err(v) = check(state) {
            panic!("the kernel broke its well-formedness invariant: {v:?}");
        }
    }
}
