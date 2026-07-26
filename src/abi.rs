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
//! - **The IPC buffer (extended message words, capability transfer) is not
//!   implemented.** Any message claiming `tag.length > 0` or `tag.extra_caps > 0`
//!   is rejected with `TruncatedMessage` rather than silently dropping the extra
//!   words — Phase 1's fast path is register-only.

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

/// `Err` if `tag` claims more than the register-only fast path can carry (see the
/// module doc's "IPC buffer... not implemented" note).
pub fn require_fast_path_only(tag: MessageTag) -> Result<(), SyscallError> {
    if tag.length > 0 || tag.extra_caps > 0 {
        Err(SyscallError::TruncatedMessage)
    } else {
        Ok(())
    }
}
