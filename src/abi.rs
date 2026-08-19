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
//!   capability being transferred (payload shrinks to `mr2`/`mr3`), and `Recv`
//!   treats its own `mr1` as the receiver's destination CPtr. `tag.extra_caps > 1`
//!   still has nowhere to go (no in-memory IPC buffer exists) and is rejected the
//!   same way `length > 0` is. `Reply`'s return leg does not support a transfer
//!   yet — RFC-0010 left its exact register layout as an open question — and
//!   still rejects any nonzero `extra_caps`.

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

/// `Reply`'s stricter check: its return leg doesn't support capability transfer
/// yet (RFC-0010 left the register layout for it unresolved), so unlike
/// `require_fast_path_only`, *any* nonzero `extra_caps` is rejected here, not
/// just `> 1`.
pub fn require_no_extra_caps(tag: MessageTag) -> Result<(), SyscallError> {
    if tag.length > 0 || tag.extra_caps > 0 {
        Err(SyscallError::TruncatedMessage)
    } else {
        Ok(())
    }
}
