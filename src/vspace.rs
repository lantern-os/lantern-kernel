//! What every address space shares —
//! [RFC-0030](../../lantern-rfcs/rfcs/0030-process-lifecycle-faults-and-reclamation.md).
//!
//! Boot code tells the kernel once, through [`add_kernel_megapage`] and [`install_direct_map`], which S-mode-only mappings
//! every VSpace needs: the kernel image, the UART and the PLIC, replicated into each VSpace's own tables because they share
//! 1 GiB regions with a program's own mappings; and the direct map of RAM, shared as one root entry, since nothing else
//! lives in its region. [`populate`] puts them in every VSpace that `UntypedRetype` makes, so a process built from user
//! space traps into the kernel like one built at boot. The kernel learns no layout: it copies what it was given.

use lantern_hal::{Riscv64PageTable, Riscv64PteFlags};

use crate::error::SyscallError;
use crate::state::KernelState;

/// How many kernel megapages the template holds.
pub const MAX_KERNEL_MEGAPAGES: usize = 8;

#[derive(Clone, Copy)]
pub struct Template {
    megapages: [Option<(usize, usize, Riscv64PteFlags)>; MAX_KERNEL_MEGAPAGES],
    /// A root table holding only the direct map's entry, shared by every VSpace.
    direct_root: Option<usize>,
    /// A VSpace with only the kernel's mappings, to run on while `crate::reclaim` frees the one that was active.
    pub idle_root: Option<usize>,
}

impl Template {
    pub const fn new() -> Self {
        Self { megapages: [None; MAX_KERNEL_MEGAPAGES], direct_root: None, idle_root: None }
    }

    pub fn is_empty(&self) -> bool {
        self.megapages.iter().all(Option::is_none) && self.direct_root.is_none()
    }
}

impl Default for Template {
    fn default() -> Self {
        Self::new()
    }
}

/// Adds one S-mode-only megapage every VSpace gets. `false` if the template is full, or the addresses aren't
/// megapage-aligned.
pub fn add_kernel_megapage(state: &mut KernelState, vaddr: usize, paddr: usize, flags: Riscv64PteFlags) -> bool {
    let mega = lantern_hal::RISCV64_MEGAPAGE_SIZE;
    if !vaddr.is_multiple_of(mega) || !paddr.is_multiple_of(mega) {
        return false;
    }
    let Some(free) = state.kernel_template.megapages.iter_mut().find(|m| m.is_none()) else { return false };
    *free = Some((vaddr, paddr, flags));
    true
}

/// Builds the direct map once: RAM's first GiB, S-mode read/write, in a table every VSpace will share. `false` if the
/// page-table pool has no room.
pub fn install_direct_map(state: &mut KernelState) -> bool {
    if state.kernel_template.direct_root.is_some() {
        return true;
    }
    // The root, and the one L1 table all 512 megapages share.
    if state.kernel_page_tables.available() < 2 {
        return false;
    }
    let root = state.kernel_page_tables.alloc().expect("checked available");
    let flags = Riscv64PteFlags::READ.union(Riscv64PteFlags::WRITE);
    let mega = lantern_hal::RISCV64_MEGAPAGE_SIZE;
    let tables = &mut state.kernel_page_tables;
    let mut alloc = || tables.alloc().expect("checked available: one L1 table at most");
    for i in 0..lantern_hal::RISCV64_DIRECT_MAP_SPAN / mega {
        // SAFETY: `root` was just allocated, zeroed, from the kernel's own page-table pool; the addresses are megapage
        // aligned constants, all in one 1 GiB region, so at most one table is allocated.
        unsafe {
            lantern_hal::riscv64_map_megapage(
                root as *mut Riscv64PageTable,
                lantern_hal::RISCV64_DIRECT_MAP_BASE + i * mega,
                lantern_hal::RISCV64_DIRECT_MAP_RAM_BASE + i * mega,
                flags,
                &mut alloc,
            )
        };
    }
    state.kernel_template.direct_root = Some(root);
    // Built last, so it has every kernel megapage registered before this, and the direct map.
    let Some(idle) = state.kernel_page_tables.alloc() else { return false };
    if populate(state, idle).is_err() {
        return false;
    }
    state.kernel_template.idle_root = Some(idle);
    true
}

/// Puts the template's mappings into a fresh VSpace root. On `Err`, the root may hold some of them, and its tables are the
/// caller's to give back.
pub fn populate(state: &mut KernelState, root: usize) -> Result<(), SyscallError> {
    let template = state.kernel_template;
    for &(vaddr, paddr, flags) in template.megapages.iter().flatten() {
        // A megapage needs at most one new table. Checked first, so the paging code is never handed a table that isn't there.
        if state.kernel_page_tables.available() < 1 {
            return Err(SyscallError::NotEnoughMemory);
        }
        let tables = &mut state.kernel_page_tables;
        let mut alloc = || tables.alloc().expect("checked available");
        // SAFETY: `root` is a VSpace root this kernel just allocated; the template's entries were checked aligned when
        // boot gave them.
        unsafe { lantern_hal::riscv64_map_megapage(root as *mut Riscv64PageTable, vaddr, paddr, flags, &mut alloc) };
    }
    if let Some(direct) = template.direct_root {
        // SAFETY: both are root tables from the kernel's own pool, and the shared entry holds only the direct map.
        unsafe {
            lantern_hal::riscv64_share_root_entry(
                root as *mut Riscv64PageTable,
                direct as *const Riscv64PageTable,
                lantern_hal::RISCV64_DIRECT_MAP_ROOT_INDEX,
            )
        };
    }
    Ok(())
}

/// Gives back every table a VSpace root owns, and the root itself. The shared direct map stays.
pub fn free_tables(state: &mut KernelState, root: usize) {
    let mut owned = [0usize; crate::limits::MAX_KERNEL_PAGE_TABLES];
    let mut count = 0;
    // SAFETY: `root` is a VSpace root from the kernel's pool, whose tables are all from that pool too.
    unsafe {
        lantern_hal::riscv64_for_each_table(root as *const Riscv64PageTable, lantern_hal::RISCV64_DIRECT_MAP_ROOT_INDEX, &mut |t| {
            if count < owned.len() {
                owned[count] = t;
                count += 1;
            }
        })
    };
    for &table in &owned[..count] {
        state.kernel_page_tables.free(table);
    }
    state.kernel_page_tables.free(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vspace_gets_the_template_and_gives_back_only_its_own_tables() {
        let mut state = KernelState::new();
        let flags = Riscv64PteFlags::READ.union(Riscv64PteFlags::WRITE);
        assert!(add_kernel_megapage(&mut state, 0x8020_0000, 0x8020_0000, flags));
        assert!(add_kernel_megapage(&mut state, 0x1000_0000, 0x1000_0000, flags));
        assert!(install_direct_map(&mut state));
        let before = state.kernel_page_tables.in_use();

        let root = state.kernel_page_tables.alloc().unwrap();
        populate(&mut state, root).unwrap();
        // The root, and one L1 table for each of the two 1 GiB regions the megapages are in; the direct map is shared.
        assert_eq!(state.kernel_page_tables.in_use(), before + 3);
        // SAFETY: host test: the tables are this test's own memory.
        unsafe {
            let r = root as *const Riscv64PageTable;
            assert_eq!(lantern_hal::riscv64_translate(r, 0x8020_1234), Some(0x8020_1234));
            assert_eq!(
                lantern_hal::riscv64_translate(r, lantern_hal::RISCV64_DIRECT_MAP_BASE + 0x40_0010),
                Some(lantern_hal::RISCV64_DIRECT_MAP_RAM_BASE + 0x40_0010)
            );
        }
        free_tables(&mut state, root);
        assert_eq!(state.kernel_page_tables.in_use(), before, "everything it owned came back");
        // And it's reused, zeroed.
        let again = state.kernel_page_tables.alloc().unwrap();
        // SAFETY: as above.
        unsafe { assert_eq!(lantern_hal::riscv64_translate(again as *const Riscv64PageTable, 0x8020_0000), None) };
    }

    #[test]
    fn the_template_is_bounded() {
        let mut state = KernelState::new();
        for i in 0..MAX_KERNEL_MEGAPAGES {
            assert!(add_kernel_megapage(&mut state, i << 21, i << 21, Riscv64PteFlags::READ));
        }
        assert!(!add_kernel_megapage(&mut state, 0, 0, Riscv64PteFlags::READ));
    }
}
