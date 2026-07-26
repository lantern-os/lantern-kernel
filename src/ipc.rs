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
    abi::require_fast_path_only(frame.tag())?;
    let (mr1, mr2, mr3, tag) = (frame.mr(1), frame.mr(2), frame.mr(3), frame.tag());

    let endpoint = *state.endpoints.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if let EndpointQueue::Recv(mut waiters) = endpoint.queue {
        let receiver = waiters.pop_front().expect("Recv variant implies a waiter");
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
        tcb.state = ThreadState::BlockedSend { endpoint: id, badge, is_call: false };
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
    let endpoint = *state.endpoints.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if let EndpointQueue::Send(mut waiters) = endpoint.queue {
        let sender = waiters.pop_front().expect("Send variant implies a waiter");
        set_endpoint_queue(state, id, normalize(EndpointQueue::Send(waiters)));

        let sender_tcb = *state.tcbs.get(sender.0 as usize).ok_or(SyscallError::FailedLookup)?;
        let ThreadState::BlockedSend { badge: sender_badge, is_call, .. } = sender_tcb.state else {
            // A thread sitting in the endpoint's send queue that isn't marked
            // BlockedSend is a kernel-internal inconsistency, not caller-triggered
            // input — but ADR-0008 still forbids panicking a syscall over it.
            return Err(SyscallError::IllegalOperation);
        };
        let payload = sender_tcb.context;

        frame.set_mr(0, sender_badge as usize);
        frame.set_mr(1, payload.mr(1));
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
        tcb.state = ThreadState::BlockedRecv(id);
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
    abi::require_fast_path_only(frame.tag())?;
    let (mr1, mr2, mr3, tag) = (frame.mr(1), frame.mr(2), frame.mr(3), frame.tag());

    let endpoint = *state.endpoints.get(id.0 as usize).ok_or(SyscallError::InvalidCapability)?;

    if let EndpointQueue::Recv(mut waiters) = endpoint.queue {
        let receiver = waiters.pop_front().expect("Recv variant implies a waiter");
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
        tcb.state = ThreadState::BlockedSend { endpoint: id, badge, is_call: true };
    }
    let switched = state.block_current(frame);
    debug_assert!(switched, "has_ready() was checked immediately above");
    Ok(())
}

/// Replies to the most recent unanswered `Call` this thread received (the
/// `reply_to` link `Call`/`Recv` set up). No explicit capability is invoked — per
/// Phase 1 convention (see [`crate::abi`]) `mr0` is simply unused here; the payload
/// is `mr1..mr3`, same as every other IPC operation.
pub fn reply(state: &mut KernelState, current: TcbId, frame: &mut TrapFrame) -> Result<(), SyscallError> {
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
