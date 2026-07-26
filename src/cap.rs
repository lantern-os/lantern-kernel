//! The capability/rights model: [RFC-0003](../../lantern-rfcs/rfcs/0003-capability-model.md)/
//! [ADR-0005](../../lantern-rfcs/adr/0005-object-capabilities-as-universal-authority-model.md)
//! fix object capabilities as the sole authority model; this module is the kernel-layer
//! (layer 1 of [ADR-0006](../../lantern-rfcs/adr/0006-three-layer-capability-structure.md))
//! implementation of it. Every kernel object is referenced by a stable pool index
//! (a `*Id` newtype below), never a pointer — see [`crate::pool`].

use crate::limits::CNODE_SLOTS;

/// Names a slot in the invoking thread's CSpace root CNode. Phase 1: the CSpace is a
/// single flat CNode (RFC-0005), so a `CPtr` is just an index into it.
pub type CPtr = usize;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $name(pub u16);
    };
}

define_id!(CNodeId);
define_id!(TcbId);
define_id!(EndpointId);
define_id!(NotificationId);
define_id!(UntypedId);
define_id!(SchedContextId);

/// Rights are a bitset over a fixed, small lattice ([RFC-0003](../../lantern-rfcs/rfcs/0003-capability-model.md)
/// leaves the exact lattice per object type as an open question — this is Phase 1's
/// minimal starting set). `mint` may only narrow rights, never widen them
/// (monotone attenuation, ADR-0005) — enforced in [`crate::cnode`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    /// Permission to grant this capability (or one derived from it) to another
    /// component over IPC (RFC-0003's `grant`).
    pub const GRANT: Rights = Rights(1 << 2);
    pub const ALL: Rights = Rights(Self::READ.0 | Self::WRITE.0 | Self::GRANT.0);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// True if every bit set in `self` is also set in `other` — the check `mint`
    /// uses to enforce monotone attenuation.
    pub const fn is_subset_of(self, other: Rights) -> bool {
        self.0 & !other.0 == 0
    }

    /// Builds a `Rights` from raw bits, silently masking off anything outside
    /// [`Rights::ALL`] — used to decode a caller-supplied rights argument without
    /// ever producing a `Rights` value the rest of the kernel can't interpret.
    pub const fn from_bits_truncate(bits: u8) -> Rights {
        Rights(bits & Self::ALL.0)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    CNode,
    Untyped,
    Endpoint,
    Notification,
    Tcb,
    SchedContext,
}

impl ObjectType {
    /// Decodes `UntypedRetype`'s `mr1` object-type argument (Phase 1 kernel-internal
    /// convention, see [`crate::abi`]).
    pub const fn from_usize(n: usize) -> Option<Self> {
        Some(match n {
            0 => ObjectType::CNode,
            1 => ObjectType::Untyped,
            2 => ObjectType::Endpoint,
            3 => ObjectType::Notification,
            4 => ObjectType::Tcb,
            5 => ObjectType::SchedContext,
            _ => return None,
        })
    }
}

/// A kernel capability: designates an object and the rights to act on it. Copy, not
/// heap-allocated — capability *tables* (CNodes) own the storage; a `Capability`
/// value is just what lives in one slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    /// An empty slot. Distinct from "slot out of range": a `CPtr` past the end of
    /// the CNode is `FailedLookup`; a `CPtr` naming an empty slot is
    /// `InvalidCapability`.
    Null,
    CNode(CNodeId),
    Untyped { id: UntypedId, rights: Rights },
    /// May be badged so a service can distinguish callers without trusting a
    /// self-asserted identity (ADR-0006).
    Endpoint { id: EndpointId, badge: u64, rights: Rights },
    Notification { id: NotificationId, badge: u64, rights: Rights },
    Tcb { id: TcbId, rights: Rights },
    SchedContext { id: SchedContextId, rights: Rights },
    /// A one-shot capability the kernel manufactures for a `Call`, naming the
    /// caller to reply to. Not storable in a CNode slot beyond the duration of the
    /// call — see `lantern-kernel/STATUS.md`'s open question on whether reply caps
    /// become first-class grantable objects (RFC-0005, deferred to Phase 2).
    Reply { tcb: TcbId },
}

impl Capability {
    pub const fn object_type(&self) -> Option<ObjectType> {
        match self {
            Capability::Null | Capability::Reply { .. } => None,
            Capability::CNode(_) => Some(ObjectType::CNode),
            Capability::Untyped { .. } => Some(ObjectType::Untyped),
            Capability::Endpoint { .. } => Some(ObjectType::Endpoint),
            Capability::Notification { .. } => Some(ObjectType::Notification),
            Capability::Tcb { .. } => Some(ObjectType::Tcb),
            Capability::SchedContext { .. } => Some(ObjectType::SchedContext),
        }
    }

    pub const fn rights(&self) -> Rights {
        match self {
            Capability::Null | Capability::CNode(_) | Capability::Reply { .. } => Rights::NONE,
            Capability::Untyped { rights, .. }
            | Capability::Endpoint { rights, .. }
            | Capability::Notification { rights, .. }
            | Capability::Tcb { rights, .. }
            | Capability::SchedContext { rights, .. } => *rights,
        }
    }
}

/// A capability node: stores capabilities in a fixed array of slots. Phase 1: a
/// CNode *is* a CSpace (flat, single-level, per RFC-0005) — there is no multi-level
/// guarded lookup yet.
#[derive(Clone, Copy, Debug)]
pub struct CNode {
    slots: [Capability; CNODE_SLOTS],
}

impl CNode {
    pub const fn empty() -> Self {
        Self { slots: [Capability::Null; CNODE_SLOTS] }
    }

    pub fn get(&self, cptr: CPtr) -> Option<Capability> {
        self.slots.get(cptr).copied()
    }

    pub fn slot_mut(&mut self, cptr: CPtr) -> Option<&mut Capability> {
        self.slots.get_mut(cptr)
    }
}

impl Default for CNode {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_subset_check_is_monotone() {
        let all = Rights::ALL;
        let read_only = Rights::READ;
        assert!(read_only.is_subset_of(all));
        assert!(!all.is_subset_of(read_only));
        assert!(all.is_subset_of(all));
    }

    #[test]
    fn cnode_slot_out_of_range_is_none_not_null() {
        let cnode = CNode::empty();
        assert_eq!(cnode.get(0), Some(Capability::Null));
        assert_eq!(cnode.get(CNODE_SLOTS), None);
    }

    #[test]
    fn cnode_slot_mut_writes_through() {
        let mut cnode = CNode::empty();
        let cap = Capability::Endpoint { id: EndpointId(1), badge: 0, rights: Rights::ALL };
        *cnode.slot_mut(3).unwrap() = cap;
        assert_eq!(cnode.get(3), Some(cap));
    }
}
