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

    /// Allocates `value` into the first free slot, returning its stable index.
    pub fn alloc(&mut self, value: T) -> Option<usize> {
        if self.is_full() {
            return None;
        }
        let (index, slot) = self.slots.iter_mut().enumerate().find(|(_, s)| s.is_none())?;
        *slot = Some(value);
        self.len += 1;
        Some(index)
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.slots.get_mut(index)?.as_mut()
    }

    /// Frees the slot at `index`, returning its value if it was occupied.
    pub fn free(&mut self, index: usize) -> Option<T> {
        let value = self.slots.get_mut(index)?.take();
        if value.is_some() {
            self.len -= 1;
        }
        value
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
