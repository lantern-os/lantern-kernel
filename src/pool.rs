//! A fixed-capacity object pool: kernel objects live at a stable index for their
//! lifetime (seL4-style "everything is a table index," never a raw pointer, per
//! `lantern-kernel/ARCHITECTURE.md`'s minimal-TCB/no-dynamic-allocation goals).
//! Allocation is a linear scan for the first free slot — fine at Phase 1's pool
//! sizes ([`crate::limits`]), not tuned for scale.

#[derive(Clone, Copy, Debug)]
pub struct Pool<T: Copy, const N: usize> {
    slots: [Option<T>; N],
    len: usize,
}

impl<T: Copy, const N: usize> Pool<T, N> {
    pub const fn new() -> Self {
        Self { slots: [None; N], len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn is_full(&self) -> bool {
        self.len >= N
    }

    /// A pool holding exactly `slots`. For the Kani proofs (RFC-0037), which build arbitrary pools directly.
    #[cfg(kani)]
    pub fn from_slots(slots: [Option<T>; N]) -> Self {
        let mut len = 0;
        for slot in &slots {
            if slot.is_some() {
                len += 1;
            }
        }
        Self { slots, len }
    }

    /// Whether `len` matches the occupied slots. For [`crate::wf`].
    pub fn consistent(&self) -> bool {
        let mut occupied = 0;
        for i in 0..N {
            occupied += usize::from(self.slots[i].is_some());
        }
        occupied == self.len
    }

    /// Allocates `value` into the first free slot, returning its stable index.
    pub fn alloc(&mut self, value: T) -> Option<usize> {
        if self.is_full() {
            return None;
        }
        // The first free slot, written in place: a reference to it, found by an iterator, would put the write at an
        // offset the Kani proofs can't resolve (RFC-0037).
        for i in 0..N {
            if self.slots[i].is_none() {
                self.slots[i] = Some(value);
                self.len += 1;
                return Some(i);
            }
        }
        None
    }

    #[cfg(not(kani))]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    #[cfg(not(kani))]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.slots.get_mut(index)?.as_mut()
    }

    // Under Kani (RFC-0037) there's no `get` or `get_mut`: a reference returned from a lookup with an arbitrary index
    // points at an offset the proofs can't resolve, and every later access through it, or of the kernel state at all,
    // becomes a selection over all of it. Only `with` and `with_mut` remain, so the compiler finds every such lookup.

    /// The lookups that run outside Kani, kept under Kani for `proofs::pool_lookups_agree`.
    #[cfg(kani)]
    pub fn get_by_index(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    #[cfg(kani)]
    pub fn get_mut_by_index(&mut self, index: usize) -> Option<&mut T> {
        self.slots.get_mut(index)?.as_mut()
    }

    /// Applies `f` to the object at `index`, if there is one. The kernel reads and writes objects through these two, not
    /// through a reference it keeps: under Kani (RFC-0037), `f` then runs at a concrete address. A reference kept past a
    /// lookup with an arbitrary index points at an offset the proofs can't resolve, which makes every later read of the
    /// kernel state a selection over all of it.
    #[cfg(not(kani))]
    pub fn with<R>(&self, index: usize, f: impl FnOnce(&T) -> R) -> Option<R> {
        self.get(index).map(f)
    }

    /// As [`Self::with`], to change the object.
    #[cfg(not(kani))]
    pub fn with_mut<R>(&mut self, index: usize, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        self.get_mut(index).map(f)
    }

    #[cfg(kani)]
    pub fn with<R>(&self, index: usize, f: impl FnOnce(&T) -> R) -> Option<R> {
        for i in 0..N {
            if i == index {
                return self.slots[i].as_ref().map(f);
            }
        }
        None
    }

    #[cfg(kani)]
    pub fn with_mut<R>(&mut self, index: usize, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        for i in 0..N {
            if i == index {
                return self.slots[i].as_mut().map(f);
            }
        }
        None
    }

    /// Whether `index` names a live object.
    pub fn contains(&self, index: usize) -> bool {
        self.with(index, |_| ()).is_some()
    }

    /// Frees the slot at `index`, returning its value if it was occupied.
    ///
    /// By comparison, not by indexing, in every build: an index the Kani proofs can't resolve would put the write at an
    /// offset they can't either (RFC-0037), and freeing is rare.
    pub fn free(&mut self, index: usize) -> Option<T> {
        for i in 0..N {
            if i == index {
                let value = self.slots[i].take();
                if value.is_some() {
                    self.len -= 1;
                }
                return value;
            }
        }
        None
    }
}

impl<T: Copy, const N: usize> Default for Pool<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_get_free_roundtrip() {
        let mut pool: Pool<u32, 4> = Pool::new();
        let a = pool.alloc(10).unwrap();
        let b = pool.alloc(20).unwrap();
        assert_eq!(pool.get(a), Some(&10));
        assert_eq!(pool.get(b), Some(&20));
        assert_eq!(pool.len(), 2);

        assert_eq!(pool.free(a), Some(10));
        assert_eq!(pool.get(a), None);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn reuses_freed_slots() {
        let mut pool: Pool<u32, 2> = Pool::new();
        let a = pool.alloc(1).unwrap();
        pool.alloc(2).unwrap();
        assert!(pool.alloc(3).is_none());

        pool.free(a);
        let reused = pool.alloc(3).unwrap();
        assert_eq!(reused, a);
        assert_eq!(pool.get(reused), Some(&3));
    }

    #[test]
    fn out_of_range_index_is_none() {
        let pool: Pool<u32, 2> = Pool::new();
        assert_eq!(pool.get(5), None);
    }
}
