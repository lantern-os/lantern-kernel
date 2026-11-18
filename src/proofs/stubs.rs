//! The hardware, as the Kani proofs see it ([RFC-0037](../../../lantern-rfcs/rfcs/0037-formal-verification-first-properties.md)).
//!
//! Page-table walks and RAM zeroing go through raw physical addresses, which these proofs don't model. Each stub keeps
//! the real function's signature and its contract as far as the kernel relies on it: a mapping either exists or doesn't
//! (`translate` answers arbitrarily, so both cases are explored), and writes succeed.

#![allow(dead_code)] // for the harnesses that reach page-table code: `Revoke`, retype, `FrameInvoke`

use lantern_hal::{Riscv64PageTable, Riscv64PteFlags};

pub unsafe fn unmap(_root: *mut Riscv64PageTable, _vaddr: usize) -> bool {
    kani::any()
}

pub unsafe fn map(
    _root: *mut Riscv64PageTable,
    _vaddr: usize,
    _paddr: usize,
    _flags: Riscv64PteFlags,
    _alloc_frame: &mut dyn FnMut() -> usize,
) {
}

pub unsafe fn translate(_root: *const Riscv64PageTable, _vaddr: usize) -> Option<usize> {
    if kani::any() {
        Some(kani::any())
    } else {
        None
    }
}

pub unsafe fn share_root_entry(_dst: *mut Riscv64PageTable, _src: *const Riscv64PageTable, _index: usize) {}

pub unsafe fn for_each_table(_root: *const Riscv64PageTable, _skip: usize, _f: &mut dyn FnMut(usize)) {}

pub fn zero_ram(_window: usize, _len: usize) {}

/// A thread's first registers, as the HAL lays them out: here, arbitrary. The host's HAL has none to give (it panics);
/// what matters to the kernel is only that it stores whatever frame comes back.
pub fn initial_trap_frame(_pc: usize, _sp: usize, _arg0: usize) -> lantern_hal::TrapFrame {
    let mut frame = lantern_hal::TrapFrame::zeroed();
    for i in 0..lantern_hal::RAW_WORDS {
        frame.set_raw_word(i, kani::any());
    }
    frame
}
