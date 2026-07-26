//! The fixed syscall error enum, per [ADR-0008](../../lantern-rfcs/adr/0008-kernel-syscall-ipc-abi.md):
//! "no syscall panics the kernel on caller-supplied input" — every fallible kernel
//! path returns one of these instead. This list is closed: adding a variant is an
//! ABI change and needs its own RFC (ADR-0008's "Committed to").

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyscallError {
    InvalidCapability,
    InvalidArgument,
    IllegalOperation,
    RangeError,
    AlignmentError,
    FailedLookup,
    TruncatedMessage,
    NotEnoughMemory,
    /// Also reused, for now, to mean "no other thread is ready to run, so this
    /// operation cannot block without stranding the hart" — Phase 1 has no idle
    /// thread yet (needs a boot-provided idle loop). Not a perfect semantic fit;
    /// tracked as a rough edge in `lantern-kernel/STATUS.md` rather than adding a
    /// tenth variant to a deliberately closed enum.
    Timeout,
}

impl SyscallError {
    /// The `mr0` value a caller sees on error, per ADR-0008's error model.
    pub const fn code(self) -> usize {
        match self {
            SyscallError::InvalidCapability => 1,
            SyscallError::InvalidArgument => 2,
            SyscallError::IllegalOperation => 3,
            SyscallError::RangeError => 4,
            SyscallError::AlignmentError => 5,
            SyscallError::FailedLookup => 6,
            SyscallError::TruncatedMessage => 7,
            SyscallError::NotEnoughMemory => 8,
            SyscallError::Timeout => 9,
        }
    }
}
