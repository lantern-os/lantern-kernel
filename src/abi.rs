//! Phase 1 kernel-internal ABI conventions that [ADR-0008](../../lantern-rfcs/adr/0008-kernel-syscall-ipc-abi.md)
//! left unfixed. ADR-0008 fixes `mr0..mr3`/the tag/the syscall number by name and
//! says a thread "names a capability by an integer CPtr" alongside them, but never
//! pins down *which* register carries that CPtr — this module is where this
//! implementation settles that, so it lives in one documented place rather than as
//! an assumption scattered across `ipc.rs`/`cnode.rs`/etc.
//!
//! - **The invoked capability's `CPtr` is `mr0`.** `mr1..mr3` (three words) are the
//!   actual message payload — one fewer than the four ADR-0008 nominally allows,
//!   since one slot is spent on routing. This is a kernel-internal convention, not
//!   a change to `lantern-hal`'s already-shipped `TrapFrame`/`MessageTag` shape.
//! - **On successful `Recv`/`Call` delivery, the receiver's `mr0` becomes the
//!   sender's endpoint-capability badge**, not a CPtr — the kernel-supplied,
//!   unforgeable caller identifier ADR-0006 describes ("badged so a service can
//!   distinguish callers without trusting their self-asserted identity"). `mr1..3`
//!   carry the sender's payload through unchanged.
//! - **The IPC buffer (extended message words) is not implemented.** Any message
//!   claiming `tag.length > 0` is rejected with `TruncatedMessage` rather than
//!   silently dropping the extra words — Phase 1's fast path is register-only.
//! - **Single-capability transfer (`tag.extra_caps == 1`) is implemented** ([RFC-0010](../../lantern-rfcs/rfcs/0010-cross-process-capability-transfer-and-brokering.md)),
//!   in [`crate::ipc`]: `Send`/`Call` treat `mr1` as the sender's CPtr for the
//!   capability being transferred (payload shrinks to `mr2`/`mr3`), `Recv` treats
//!   its own `mr1` as the receiver's destination CPtr, and `Reply` treats its own
//!   `mr1` the same way `Send`'s does (the replier's transfer CPtr). `tag.extra_caps
//!   > 1` on `Send`/`Recv`/`Reply` still has nowhere to go (no in-memory IPC
//!   buffer exists) and is rejected the same way `length > 0` is.
//! - **`Call`'s reply-leg destination (`tag.extra_caps == 2`, `Call`-only) is
//!   implemented.** This is what RFC-0010 originally left as an open question
//!   ("no spare register at `Call` time to register a destination slot"): the
//!   answer is a second, `Call`-specific meaning for `extra_caps`, mutually
//!   exclusive with `== 1`'s outbound-transfer meaning. `tag.extra_caps == 2`
//!   means "no outbound transfer *this* call, but `mr1` is my own destination
//!   CPtr for a capability the eventual `Reply` might attach" — carried via
//!   `ThreadState::BlockedSend.reply_dest_slot`/`ThreadState::BlockedReply.dest_slot`
//!   through to whenever `Reply` actually runs. A single `Call` cannot both
//!   attach an outbound capability *and* register a reply destination — Phase 1's
//!   three payload words have no room for a fourth argument; `Call` only ever
//!   needed to pick one meaning for `mr1` at a time, unlike `Send`, which never
//!   needs the "register a destination" meaning at all (only `Recv` does).

use lantern_hal::{MessageTag, TrapFrame, FLAG_ERROR};

use crate::error::SyscallError;

pub fn reply_success(frame: &mut TrapFrame) {
    let mut tag = frame.tag();
    tag.flags &= !FLAG_ERROR;
    frame.set_tag(tag);
}

pub fn reply_error(frame: &mut TrapFrame, error: SyscallError) {
    frame.set_mr(0, error.code());
    let mut tag = frame.tag();
    tag.flags |= FLAG_ERROR;
    frame.set_tag(tag);
}

/// `Err` if `tag` claims more than `Send`/`Call`/`Recv`'s register-only fast path
/// (plus the single-capability-transfer slot RFC-0010 adds) can carry: extended
/// message words (`length > 0`), or more than one attached capability
/// (`extra_caps > 1`) — see the module doc.
pub fn require_fast_path_only(tag: MessageTag) -> Result<(), SyscallError> {
    if tag.length > 0 || tag.extra_caps > 1 {
        Err(SyscallError::TruncatedMessage)
    } else {
        Ok(())
    }
}

/// `Call`'s own check: like [`require_fast_path_only`], but `Call` additionally
/// understands `extra_caps == 2` (register a reply-leg destination slot — see
/// the module doc), so the accepted range is `0..=2`, not `0..=1`.
pub fn require_call_tag(tag: MessageTag) -> Result<(), SyscallError> {
    if tag.length > 0 || tag.extra_caps > 2 {
        Err(SyscallError::TruncatedMessage)
    } else {
        Ok(())
    }
}
