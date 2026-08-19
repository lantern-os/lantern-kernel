//! The IPC fast path: `Send`/`NBSend`/`Recv`/`Call`/`Reply` on endpoints, and
//! `Signal`/`Wait`/`Poll` on notifications. This is "the fast path the whole
//! system's latency budget depends on"
//! ([RFC-0005](../../lantern-rfcs/rfcs/0005-syscall-ipc-abi-and-phase1-scheduling.md)) —
//! everything here is real synchronous rendezvous logic, not a stub, because it's
//! the one part of Phase 1's design this crate can actually exercise end to end
//! without `lantern-boot` or HAL paging support.
//!
//! See [`crate::abi`] for the `mr0`-as-CPtr / `mr0`-as-badge-on-delivery
//! conventions this module relies on throughout.

use lantern_hal::{MessageTag, TrapFrame};

use crate::abi;
use crate::cap::{Capability, CPtr, EndpointId, Rights, TcbId};
use crate::error::SyscallError;
use crate::object::{EndpointQueue, ThreadState};
use crate::queue::ArrayQueue;
use crate::state::KernelState;

/// Resolves `cptr` in `thread`'s CSpace for use as a `tag.extra_caps == 1`
/// transfer source, requiring `Rights::GRANT` — [RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md).
/// `Capability::rights()` returns `Rights::NONE` for `Null`/`CNode`/`Reply`, so
/// those are rejected by the same check without needing a separate type match.
fn resolve_transferable_cap(state: &KernelState, thread: TcbId, cptr: CPtr) -> Result<Capability, SyscallError> {
    let cap = state.lookup_cap(thread, cptr)?;
    if !cap.rights().contains(Rights::GRANT) {
        return Err(SyscallError::IllegalOperation);
    }
    Ok(cap)
}

/// If `tag.extra_caps == 1`, resolves the capability `frame.mr(1)` names in
/// `current`'s CSpace (RFC-0010's sender-side convention); `None` if
/// `extra_caps == 0`. Callers must already have validated `tag` via
/// [`abi::require_fast_path_only`] (so `extra_caps > 1` never reaches here).
fn extract_extra_cap(
    state: &KernelState,
    current: TcbId,
    frame: &TrapFrame,
    tag: MessageTag,
) -> Result<Option<Capability>, SyscallError> {
    if tag.extra_caps == 0 {
        Ok(None)
    } else {
        resolve_transferable_cap(state, current, frame.mr(1)).map(Some)
    }
}

/// The three payload words a `Send`/`Call` message actually delivers. When a
/// capability is attached, `mr1` was spent naming it (RFC-0010), so the
/// delivered payload shrinks to `mr2`/`mr3` and the receiver's `mr1` reads `0`
/// rather than the sender's now-meaningless local CPtr.
fn payload_words(frame: &TrapFrame, transferring: bool) -> (usize, usize, usize) {
    if transferring {
        (0, frame.mr(2), frame.mr(3))
    } else {
        (frame.mr(1), frame.mr(2), frame.mr(3))
    }
}

/// Writes `cap` into `receiver`'s CSpace at `dest`, iff that slot is currently
/// empty. The one place a transferred capability actually lands — RFC-0010's
/// kernel-mediated `grant`.
fn place_transferred_cap(state: &mut KernelState, receiver: TcbId, dest: CPtr, cap: Capability) -> Result<(), SyscallError> {
    let cspace_id = state.tcbs.get(receiver.0 as usize).ok_or(SyscallError::FailedLookup)?.cspace.ok_or(SyscallError::FailedLookup)?;
    let cnode = state.cnodes.get_mut(cspace_id.0 as usize).ok_or(SyscallError::FailedLookup)?;
    let slot = cnode.slot_mut(dest).ok_or(SyscallError::RangeError)?;
    if *slot != Capability::Null {
        return Err(SyscallError::IllegalOperation);
    }
    *slot = cap;
    Ok(())
}

/// The destination CPtr a blocked receiver registered at its own `Recv` time
/// (`ThreadState::BlockedRecv`'s `dest_slot`), or `None` if it isn't currently
/// blocked in `Recv` at all (a kernel-internal inconsistency callers should
/// already have ruled out) or registered no slot.
fn blocked_receiver_dest_slot(state: &KernelState, receiver: TcbId) -> Option<CPtr> {
    match state.tcbs.get(receiver.0 as usize)?.state {
        ThreadState::BlockedRecv { dest_slot, .. } => dest_slot,
        _ => None,
    }
}

fn set_endpoint_queue(state: &mut KernelState, id: EndpointId, queue: EndpointQueue) {
    if let Some(ep) = state.endpoints.get_mut(id.0 as usize) {
        ep.queue = queue;
    }
}

/// Collapses a drained queue back to `Empty` so future callers see a uniform
/// "nobody waiting" state rather than an empty `Send`/`Recv` variant.
fn normalize(queue: EndpointQueue) -> EndpointQueue {
    match queue {
        EndpointQueue::Send(q) if q.is_empty() => EndpointQueue::Empty,
        EndpointQueue::Recv(q) if q.is_empty() => EndpointQueue::Empty,
        other => other,
    }
}

fn deliver_payload(
    state: &mut KernelState,
    target: TcbId,
    badge: u64,
    mr1: usize,
    mr2: usize,
    mr3: usize,
    tag: MessageTag,
) {
    if let Some(tcb) = state.tcbs.get_mut(target.0 as usize) {
        tcb.context.set_mr(0, badge as usize);
        tcb.context.set_mr(1, mr1);
        tcb.context.set_mr(2, mr2);
        tcb.context.set_mr(3, mr3);
        tcb.context.set_tag(tag);
    }
}

fn resolve_endpoint(
    state: &KernelState,
    current: TcbId,
    cptr: CPtr,
    required: Rights,
) -> Result<(EndpointId, u64), SyscallError> {
    match state.lookup_cap(current, cptr)? {
        Capability::Endpoint { id, badge, rights } if rights.contains(required) => Ok((id, badge)),
        Capability::Endpoint { .. } => Err(SyscallError::IllegalOperation),
        _ => Err(SyscallError::InvalidCapability),
    }
}

/// `Send` (blocking) and `NBSend` (`nonblocking = true`) share everything except
/// what happens when no receiver is waiting: `Send` blocks, `NBSend` drops the
/// message (RFC-0005: "dropped if no receiver is ready").
pub fn send(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
    nonblocking: bool,
) -> Result<(), SyscallError> {
    let (id, badge) = resolve_endpoint(state, current, cptr, Rights::WRITE)?;
    let tag = frame.tag();
    abi::require_fast_path_only(tag)?;
    let extra_cap = extract_extra_cap(state, current, frame, tag)?;
    let (mr1, mr2, mr3) = payload_words(frame, extra_cap.is_some());

    let endpoint = *state.endpoints.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if let EndpointQueue::Recv(waiters) = endpoint.queue {
        let receiver = waiters.front().expect("Recv variant implies a waiter");
        // Validate the transfer *before* touching the queue: a receiver with no
        // (or an occupied) destination slot fails the whole Send atomically,
        // leaving the receiver still queued rather than losing the message or
        // the capability (RFC-0010).
        if let Some(cap) = extra_cap {
            let dest = blocked_receiver_dest_slot(state, receiver).ok_or(SyscallError::IllegalOperation)?;
            place_transferred_cap(state, receiver, dest, cap)?;
        }
        let mut waiters = waiters;
        let receiver = waiters.pop_front().expect("front() just confirmed a waiter");
        set_endpoint_queue(state, id, normalize(EndpointQueue::Recv(waiters)));
        deliver_payload(state, receiver, badge, mr1, mr2, mr3, tag);
        state.make_ready(receiver);
        abi::reply_success(frame);
        return Ok(());
    }

    if nonblocking {
        abi::reply_success(frame);
        return Ok(());
    }

    if !state.scheduler.has_ready() {
        return Err(SyscallError::Timeout);
    }
    let mut send_queue = match endpoint.queue {
        EndpointQueue::Send(q) => q,
        EndpointQueue::Empty => ArrayQueue::new(),
        EndpointQueue::Recv(_) => unreachable!("handled above"),
    };
    if !send_queue.push_back(current) {
        return Err(SyscallError::NotEnoughMemory);
    }
    set_endpoint_queue(state, id, EndpointQueue::Send(send_queue));
    if let Some(tcb) = state.tcbs.get_mut(current.0 as usize) {
        tcb.state = ThreadState::BlockedSend { endpoint: id, badge, is_call: false, extra_cap };
    }
    let switched = state.block_current(frame);
    debug_assert!(switched, "has_ready() was checked immediately above");
    Ok(())
}

pub fn recv(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let (id, _own_badge) = resolve_endpoint(state, current, cptr, Rights::READ)?;
    let recv_tag = frame.tag();
    abi::require_fast_path_only(recv_tag)?;
    // RFC-0010: the receiver's own `mr1` doubles as "the destination slot I'm
    // registering for an incoming transferred capability", gated the same way
    // the sender side gates mr1-as-transfer-source: by this request's own
    // `extra_caps` bit, so a plain `Recv` (extra_caps == 0) never treats mr1 as
    // anything but ordinary (ignored) register content.
    let dest_slot = (recv_tag.extra_caps == 1).then(|| frame.mr(1));
    let endpoint = *state.endpoints.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if let EndpointQueue::Send(waiters) = endpoint.queue {
        let sender = waiters.front().expect("Send variant implies a waiter");
        let sender_tcb = *state.tcbs.get(sender.0 as usize).ok_or(SyscallError::FailedLookup)?;
        let ThreadState::BlockedSend { badge: sender_badge, is_call, extra_cap, .. } = sender_tcb.state else {
            // A thread sitting in the endpoint's send queue that isn't marked
            // BlockedSend is a kernel-internal inconsistency, not caller-triggered
            // input — but ADR-0008 still forbids panicking a syscall over it.
            return Err(SyscallError::IllegalOperation);
        };
        // Same atomicity discipline as `send`'s mirror-image case: validate the
        // destination before consuming the sender off the queue.
        if let Some(cap) = extra_cap {
            let dest = dest_slot.ok_or(SyscallError::IllegalOperation)?;
            place_transferred_cap(state, current, dest, cap)?;
        }
        let mut waiters = waiters;
        let sender = waiters.pop_front().expect("front() just confirmed a waiter");
        set_endpoint_queue(state, id, normalize(EndpointQueue::Send(waiters)));

        let payload = sender_tcb.context;
        frame.set_mr(0, sender_badge as usize);
        frame.set_mr(1, if extra_cap.is_some() { 0 } else { payload.mr(1) });
        frame.set_mr(2, payload.mr(2));
        frame.set_mr(3, payload.mr(3));
        frame.set_tag(payload.tag());
        abi::reply_success(frame);

        if is_call {
            if let Some(tcb) = state.tcbs.get_mut(current.0 as usize) {
                tcb.reply_to = Some(sender);
            }
            if let Some(tcb) = state.tcbs.get_mut(sender.0 as usize) {
                tcb.state = ThreadState::BlockedReply;
            }
        } else {
            state.make_ready(sender);
        }
        return Ok(());
    }

    if !state.scheduler.has_ready() {
        return Err(SyscallError::Timeout);
    }
    let mut recv_queue = match endpoint.queue {
        EndpointQueue::Recv(q) => q,
        EndpointQueue::Empty => ArrayQueue::new(),
        EndpointQueue::Send(_) => unreachable!("handled above"),
    };
    if !recv_queue.push_back(current) {
        return Err(SyscallError::NotEnoughMemory);
    }
    set_endpoint_queue(state, id, EndpointQueue::Recv(recv_queue));
    if let Some(tcb) = state.tcbs.get_mut(current.0 as usize) {
        tcb.state = ThreadState::BlockedRecv { endpoint: id, dest_slot };
    }
    let switched = state.block_current(frame);
    debug_assert!(switched, "has_ready() was checked immediately above");
    Ok(())
}

/// `Send` + block for `Reply`, generating the one-shot implicit reply capability
/// (RFC-0005) as a `reply_to` link rather than a storable `Capability` value — see
/// `lantern-kernel/STATUS.md` for the open question on making it first-class.
pub fn call(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let (id, badge) = resolve_endpoint(state, current, cptr, Rights::WRITE)?;
    let tag = frame.tag();
    abi::require_fast_path_only(tag)?;
    let extra_cap = extract_extra_cap(state, current, frame, tag)?;
    let (mr1, mr2, mr3) = payload_words(frame, extra_cap.is_some());

    let endpoint = *state.endpoints.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if let EndpointQueue::Recv(waiters) = endpoint.queue {
        let receiver = waiters.front().expect("Recv variant implies a waiter");
        if let Some(cap) = extra_cap {
            let dest = blocked_receiver_dest_slot(state, receiver).ok_or(SyscallError::IllegalOperation)?;
            place_transferred_cap(state, receiver, dest, cap)?;
        }
        let mut waiters = waiters;
        let receiver = waiters.pop_front().expect("front() just confirmed a waiter");
        set_endpoint_queue(state, id, normalize(EndpointQueue::Recv(waiters)));
        deliver_payload(state, receiver, badge, mr1, mr2, mr3, tag);
        if let Some(tcb) = state.tcbs.get_mut(receiver.0 as usize) {
            tcb.reply_to = Some(current);
        }
        if let Some(tcb) = state.tcbs.get_mut(current.0 as usize) {
            tcb.state = ThreadState::BlockedReply;
        }
        state.switch_to(frame, receiver);
        return Ok(());
    }

    if !state.scheduler.has_ready() {
        return Err(SyscallError::Timeout);
    }
    let mut send_queue = match endpoint.queue {
        EndpointQueue::Send(q) => q,
        EndpointQueue::Empty => ArrayQueue::new(),
        EndpointQueue::Recv(_) => unreachable!("handled above"),
    };
    if !send_queue.push_back(current) {
        return Err(SyscallError::NotEnoughMemory);
    }
    set_endpoint_queue(state, id, EndpointQueue::Send(send_queue));
    if let Some(tcb) = state.tcbs.get_mut(current.0 as usize) {
        tcb.state = ThreadState::BlockedSend { endpoint: id, badge, is_call: true, extra_cap };
    }
    let switched = state.block_current(frame);
    debug_assert!(switched, "has_ready() was checked immediately above");
    Ok(())
}

/// Replies to the most recent unanswered `Call` this thread received (the
/// `reply_to` link `Call`/`Recv` set up). No explicit capability is invoked — per
/// Phase 1 convention (see [`crate::abi`]) `mr0` is simply unused here; the payload
/// is `mr1..mr3`, same as every other IPC operation.
///
/// **Does not yet support attaching a capability** (RFC-0010 left `Call`'s
/// reply-path register layout as an open question — the original caller has no
/// spare register at `Call` time to register a destination slot the way `Recv`'s
/// callers do). `tag.extra_caps > 0` is rejected outright rather than silently
/// ignored, via [`abi::require_no_extra_caps`].
pub fn reply(state: &mut KernelState, current: TcbId, frame: &mut TrapFrame) -> Result<(), SyscallError> {
    abi::require_no_extra_caps(frame.tag())?;
    let target = state
        .tcbs
        .get_mut(current.0 as usize)
        .ok_or(SyscallError::IllegalOperation)?
        .reply_to
        .take()
        .ok_or(SyscallError::IllegalOperation)?;

    let (mr1, mr2, mr3, tag) = (frame.mr(1), frame.mr(2), frame.mr(3), frame.tag());
    match state.tcbs.get_mut(target.0 as usize) {
        Some(tcb) => {
            tcb.context.set_mr(0, 0);
            tcb.context.set_mr(1, mr1);
            tcb.context.set_mr(2, mr2);
            tcb.context.set_mr(3, mr3);
            tcb.context.set_tag(tag);
        }
        None => return Err(SyscallError::IllegalOperation),
    }

    state.make_ready(current);
    state.switch_to(frame, target);
    Ok(())
}

fn resolve_notification(
    state: &KernelState,
    current: TcbId,
    cptr: CPtr,
    required: Rights,
) -> Result<(crate::cap::NotificationId, u64), SyscallError> {
    match state.lookup_cap(current, cptr)? {
        Capability::Notification { id, badge, rights } if rights.contains(required) => Ok((id, badge)),
        Capability::Notification { .. } => Err(SyscallError::IllegalOperation),
        _ => Err(SyscallError::InvalidCapability),
    }
}

/// Non-blocking: OR's this capability's badge into the notification's signal word,
/// waking a waiter if one is blocked in `Wait`.
pub fn signal(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let (id, badge) = resolve_notification(state, current, cptr, Rights::WRITE)?;
    let notif = *state.notifications.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    let mut waiters = notif.waiters;
    if let Some(waiter) = waiters.pop_front() {
        let delivered = notif.signals | badge;
        if let Some(n) = state.notifications.get_mut(id.0 as usize) {
            n.waiters = waiters;
            n.signals = 0;
        }
        if let Some(tcb) = state.tcbs.get_mut(waiter.0 as usize) {
            tcb.context.set_mr(0, delivered as usize);
        }
        state.make_ready(waiter);
    } else if let Some(n) = state.notifications.get_mut(id.0 as usize) {
        n.signals |= badge;
    }
    abi::reply_success(frame);
    Ok(())
}

pub fn wait(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let (id, _badge) = resolve_notification(state, current, cptr, Rights::READ)?;
    let notif = *state.notifications.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if notif.signals != 0 {
        frame.set_mr(0, notif.signals as usize);
        if let Some(n) = state.notifications.get_mut(id.0 as usize) {
            n.signals = 0;
        }
        abi::reply_success(frame);
        return Ok(());
    }

    if !state.scheduler.has_ready() {
        return Err(SyscallError::Timeout);
    }
    let mut waiters = notif.waiters;
    if !waiters.push_back(current) {
        return Err(SyscallError::NotEnoughMemory);
    }
    if let Some(n) = state.notifications.get_mut(id.0 as usize) {
        n.waiters = waiters;
    }
    if let Some(tcb) = state.tcbs.get_mut(current.0 as usize) {
        tcb.state = ThreadState::BlockedWait(id);
    }
    let switched = state.block_current(frame);
    debug_assert!(switched, "has_ready() was checked immediately above");
    Ok(())
}

/// Non-blocking check: always returns success, `mr0` holds whatever signal bits
/// were pending (`0` if none) — RFC-0005 gives `Poll` no separate "nothing pending"
/// error, so the caller distinguishes by inspecting `mr0`.
pub fn poll(
    state: &mut KernelState,
    current: TcbId,
    cptr: CPtr,
    frame: &mut TrapFrame,
) -> Result<(), SyscallError> {
    let (id, _badge) = resolve_notification(state, current, cptr, Rights::READ)?;
    let notif = *state.notifications.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if notif.signals != 0 {
        if let Some(n) = state.notifications.get_mut(id.0 as usize) {
            n.signals = 0;
        }
    }
    frame.set_mr(0, notif.signals as usize);
    abi::reply_success(frame);
    Ok(())
}

#[cfg(test)]
mod transfer_tests {
    use super::*;
    use crate::cap::{CNode, CNodeId, Capability, EndpointId, NotificationId};
    use crate::object::{Notification, Tcb};

    fn frame_for(mr0: usize, mr1: usize, mr2: usize, mr3: usize, extra_caps: u8) -> TrapFrame {
        let mut frame = TrapFrame::zeroed();
        frame.set_tag(MessageTag { label: 0, length: 0, extra_caps, flags: 0 });
        frame.set_mr(0, mr0);
        frame.set_mr(1, mr1);
        frame.set_mr(2, mr2);
        frame.set_mr(3, mr3);
        frame
    }

    /// Two threads, each with their own CNode holding a shared Endpoint capability
    /// at slot 1 (badge 7). Endpoint slot 1 is deliberately pre-occupied on both
    /// sides — several tests below use that to exercise "destination slot already
    /// occupied" for free.
    struct Pair {
        state: KernelState,
        client: TcbId,
        client_cnode: CNodeId,
        server: TcbId,
        server_cnode: CNodeId,
        ep_cptr: CPtr,
        ep_id: EndpointId,
    }

    fn setup() -> Pair {
        let mut state = KernelState::new();
        let ep_idx = state.endpoints.alloc(crate::object::Endpoint::new()).unwrap();
        let ep_id = EndpointId(ep_idx as u16);
        let ep = Capability::Endpoint { id: ep_id, badge: 7, rights: Rights::ALL };

        let client_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        *state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;
        let client = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(client.0 as usize).unwrap().cspace = Some(client_cnode);

        let server_cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        *state.cnodes.get_mut(server_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;
        let server = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(server.0 as usize).unwrap().cspace = Some(server_cnode);

        Pair { state, client, client_cnode, server, server_cnode, ep_cptr: 1, ep_id }
    }

    /// Puts a `Notification` capability with `Rights::GRANT` (plus `READ`, so it's
    /// a plausible real grant, not just a bare marker) into `cnode` at `slot`.
    fn put_grantable_cap(state: &mut KernelState, cnode: CNodeId, slot: CPtr) -> Capability {
        let notif_idx = state.notifications.alloc(Notification::new()).unwrap();
        let cap = Capability::Notification {
            id: NotificationId(notif_idx as u16),
            badge: 0,
            rights: Rights::READ.union(Rights::GRANT),
        };
        *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(slot).unwrap() = cap;
        cap
    }

    #[test]
    fn send_transfers_into_a_waiting_receivers_registered_slot() {
        let mut p = setup();
        let cap = put_grantable_cap(&mut p.state, p.client_cnode, 5);

        // Server blocks in Recv first, registering slot 9 as its destination.
        p.state.make_ready(p.client);
        p.state.scheduler.current = Some(p.server);
        let mut recv_frame = frame_for(p.ep_cptr, 9, 0, 0, 1);
        recv(&mut p.state, p.server, p.ep_cptr, &mut recv_frame).unwrap();
        assert_eq!(p.state.scheduler.current, Some(p.client));

        // Client sends, attaching slot 5's capability plus a two-word payload.
        let mut send_frame = frame_for(p.ep_cptr, 5, 222, 333, 1);
        send(&mut p.state, p.client, p.ep_cptr, &mut send_frame, false).unwrap();
        assert!(!send_frame.tag().is_error());

        // Landed in the server's slot 9, unchanged...
        assert_eq!(p.state.cnodes.get(p.server_cnode.0 as usize).unwrap().get(9), Some(cap));
        // ...and the client still holds its own copy: transfer is a copy, not a move.
        assert_eq!(p.state.cnodes.get(p.client_cnode.0 as usize).unwrap().get(5), Some(cap));

        // The server (blocked, not running) got its payload written into its
        // saved context: mr1 is 0 (spent on the transfer), mr2/mr3 carry through.
        let server_ctx = p.state.tcbs.get(p.server.0 as usize).unwrap().context;
        assert_eq!(server_ctx.mr(0), 7, "badge");
        assert_eq!(server_ctx.mr(1), 0);
        assert_eq!(server_ctx.mr(2), 222);
        assert_eq!(server_ctx.mr(3), 333);
        assert_eq!(server_ctx.tag().extra_caps, 1);
    }

    #[test]
    fn recv_transfers_when_the_sender_blocked_first() {
        let mut p = setup();
        let cap = put_grantable_cap(&mut p.state, p.client_cnode, 5);

        // Client sends first; nobody is receiving yet, so it blocks.
        p.state.make_ready(p.server);
        p.state.scheduler.current = Some(p.client);
        let mut send_frame = frame_for(p.ep_cptr, 5, 222, 333, 1);
        send(&mut p.state, p.client, p.ep_cptr, &mut send_frame, false).unwrap();
        assert_eq!(p.state.scheduler.current, Some(p.server));

        // Server receives, registering slot 9.
        let mut recv_frame = frame_for(p.ep_cptr, 9, 0, 0, 1);
        recv(&mut p.state, p.server, p.ep_cptr, &mut recv_frame).unwrap();

        assert_eq!(p.state.cnodes.get(p.server_cnode.0 as usize).unwrap().get(9), Some(cap));
        assert_eq!(recv_frame.mr(0), 7, "badge");
        assert_eq!(recv_frame.mr(1), 0);
        assert_eq!(recv_frame.mr(2), 222);
        assert_eq!(recv_frame.mr(3), 333);
    }

    #[test]
    fn transfer_without_grant_right_is_rejected() {
        let mut p = setup();
        // READ-only, no GRANT.
        let cap = Capability::Endpoint { id: p.ep_id, badge: 0, rights: Rights::READ };
        *p.state.cnodes.get_mut(p.client_cnode.0 as usize).unwrap().slot_mut(5).unwrap() = cap;

        p.state.make_ready(p.server);
        p.state.scheduler.current = Some(p.client);
        let mut send_frame = frame_for(p.ep_cptr, 5, 0, 0, 1);
        assert_eq!(
            send(&mut p.state, p.client, p.ep_cptr, &mut send_frame, false),
            Err(SyscallError::IllegalOperation)
        );
    }

    #[test]
    fn transfer_to_a_receiver_with_no_registered_slot_is_rejected_and_nothing_is_consumed() {
        let mut p = setup();
        put_grantable_cap(&mut p.state, p.client_cnode, 5);

        // Server blocks in a plain Recv (extra_caps == 0): no destination slot.
        p.state.make_ready(p.client);
        p.state.scheduler.current = Some(p.server);
        let mut recv_frame = frame_for(p.ep_cptr, 0, 0, 0, 0);
        recv(&mut p.state, p.server, p.ep_cptr, &mut recv_frame).unwrap();

        let mut send_frame = frame_for(p.ep_cptr, 5, 0, 0, 1);
        assert_eq!(
            send(&mut p.state, p.client, p.ep_cptr, &mut send_frame, false),
            Err(SyscallError::IllegalOperation)
        );
        // The rendezvous never happened: the server is still parked waiting.
        assert!(matches!(
            p.state.tcbs.get(p.server.0 as usize).unwrap().state,
            ThreadState::BlockedRecv { .. }
        ));
    }

    #[test]
    fn transfer_into_an_occupied_destination_slot_is_rejected() {
        let mut p = setup();
        put_grantable_cap(&mut p.state, p.client_cnode, 5);

        // Server registers slot 1 as its destination — already occupied by its
        // own endpoint capability.
        p.state.make_ready(p.client);
        p.state.scheduler.current = Some(p.server);
        let mut recv_frame = frame_for(p.ep_cptr, 1, 0, 0, 1);
        recv(&mut p.state, p.server, p.ep_cptr, &mut recv_frame).unwrap();

        let mut send_frame = frame_for(p.ep_cptr, 5, 0, 0, 1);
        assert_eq!(
            send(&mut p.state, p.client, p.ep_cptr, &mut send_frame, false),
            Err(SyscallError::IllegalOperation)
        );
        // Untouched: still the original endpoint capability, not clobbered.
        assert_eq!(
            p.state.cnodes.get(p.server_cnode.0 as usize).unwrap().get(1),
            Some(Capability::Endpoint { id: p.ep_id, badge: 7, rights: Rights::ALL })
        );
    }

    #[test]
    fn more_than_one_extra_cap_is_rejected_no_ipc_buffer_exists() {
        let mut p = setup();
        let mut send_frame = frame_for(p.ep_cptr, 0, 0, 0, 2);
        assert_eq!(
            send(&mut p.state, p.client, p.ep_cptr, &mut send_frame, true),
            Err(SyscallError::TruncatedMessage)
        );
    }

    #[test]
    fn call_transfers_a_capability_on_its_outbound_leg() {
        let mut p = setup();
        let cap = put_grantable_cap(&mut p.state, p.client_cnode, 5);

        p.state.make_ready(p.client);
        p.state.scheduler.current = Some(p.server);
        let mut recv_frame = frame_for(p.ep_cptr, 9, 0, 0, 1);
        recv(&mut p.state, p.server, p.ep_cptr, &mut recv_frame).unwrap();

        let mut call_frame = frame_for(p.ep_cptr, 5, 222, 0, 1);
        call(&mut p.state, p.client, p.ep_cptr, &mut call_frame).unwrap();

        assert_eq!(p.state.scheduler.current, Some(p.server));
        assert_eq!(p.state.cnodes.get(p.server_cnode.0 as usize).unwrap().get(9), Some(cap));
        assert_eq!(p.state.tcbs.get(p.server.0 as usize).unwrap().reply_to, Some(p.client));
        assert_eq!(p.state.tcbs.get(p.client.0 as usize).unwrap().state, ThreadState::BlockedReply);
    }

    #[test]
    fn reply_rejects_any_attached_capability() {
        let mut p = setup();

        // Establish a real Call/Recv rendezvous so `server` has something to reply to.
        p.state.make_ready(p.client);
        p.state.scheduler.current = Some(p.server);
        let mut recv_frame = frame_for(p.ep_cptr, 0, 0, 0, 0);
        recv(&mut p.state, p.server, p.ep_cptr, &mut recv_frame).unwrap();
        let mut call_frame = frame_for(p.ep_cptr, 0, 0, 0, 0);
        call(&mut p.state, p.client, p.ep_cptr, &mut call_frame).unwrap();
        assert_eq!(p.state.scheduler.current, Some(p.server));

        let mut reply_frame = frame_for(0, 0, 0, 0, 1);
        assert_eq!(reply(&mut p.state, p.server, &mut reply_frame), Err(SyscallError::TruncatedMessage));
        // Refused before consuming the reply_to link — the client is still
        // parked waiting for a real reply, not left stranded.
        assert_eq!(p.state.tcbs.get(p.client.0 as usize).unwrap().state, ThreadState::BlockedReply);
    }
}
