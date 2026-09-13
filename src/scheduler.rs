//! The ready queue. Per [ADR-0009](../../lantern-rfcs/adr/0009-phase1-scheduling-context-model.md),
//! Phase 1 scheduling is plain round-robin (`budget == period`, no replenishment);
//! per [ADR-0010](../../lantern-rfcs/adr/0010-kernel-concurrency-model.md), scheduling
//! decisions happen inline in the trap-return path of a single-stack kernel, not on
//! a separate scheduler thread — see [`crate::state::KernelState`]'s `switch_to*`
//! methods, which are where the actual context switch happens.

use crate::cap::TcbId;
use crate::limits::MAX_TCBS;
use crate::queue::ArrayQueue;

pub struct Scheduler {
    pub(crate) ready: ArrayQueue<TcbId, MAX_TCBS>,
    pub current: Option<TcbId>,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self { ready: ArrayQueue::new(), current: None }
    }

    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Removes `id` from the ready queue if it's sitting there. Used wherever
    /// a thread transitions to `Running` *without* going through
    /// [`KernelState::block_current`]'s pop — currently only
    /// [`crate::enter_first_thread`] — so it can never end up both `current`
    /// and enqueued as ready at once. See that function's doc for why: a
    /// freshly `TCBConfigure`d thread is auto-enqueued by
    /// [`crate::admin::configure`] the moment it leaves `Inactive`, and
    /// `enter_first_thread` doesn't go through `make_ready`/`block_current`'s
    /// own bookkeeping to clear that.
    pub(crate) fn remove_ready(&mut self, id: TcbId) {
        self.ready.remove(id);
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
