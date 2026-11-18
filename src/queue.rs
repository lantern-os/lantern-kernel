//! A fixed-capacity FIFO, used for the scheduler's ready queue and endpoint/
//! notification blocked-thread queues. No heap: backed by a `[Option<T>; N]` ring
//! buffer, per ADR-0004's no-dynamic-allocation-after-boot commitment.

#[derive(Clone, Copy, Debug)]
pub struct ArrayQueue<T: Copy, const N: usize> {
    items: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T: Copy, const N: usize> ArrayQueue<T, N> {
    /// Every element access goes through these two. Under Kani (RFC-0037) they find the slot by comparison: the queue's
    /// position is often arbitrary there, and an access at an offset Kani can't resolve makes every later read of the
    /// kernel state a selection over all of it. That both versions agree is proved (`proofs::queue_access_agrees`).
    #[cfg(not(kani))]
    fn get_at(&self, i: usize) -> Option<T> {
        self.items[i]
    }

    #[cfg(not(kani))]
    fn set_at(&mut self, i: usize, value: Option<T>) {
        self.items[i] = value;
    }

    #[cfg(kani)]
    fn get_at(&self, i: usize) -> Option<T> {
        assert!(i < N, "index out of bounds");
        let mut value = None;
        for j in 0..N {
            if j == i {
                value = self.items[j];
            }
        }
        value
    }

    #[cfg(kani)]
    fn set_at(&mut self, i: usize, value: Option<T>) {
        assert!(i < N, "index out of bounds");
        for j in 0..N {
            if j == i {
                self.items[j] = value;
            }
        }
    }

    /// The direct accesses, kept under Kani for `proofs::queue_access_agrees`.
    #[cfg(kani)]
    pub fn get_by_index(&self, i: usize) -> Option<T> {
        self.items[i]
    }

    #[cfg(kani)]
    pub fn set_by_index(&mut self, i: usize, value: Option<T>) {
        self.items[i] = value;
    }

    #[cfg(kani)]
    pub fn get_at_for_proof(&self, i: usize) -> Option<T> {
        self.get_at(i)
    }

    #[cfg(kani)]
    pub fn set_at_for_proof(&mut self, i: usize, value: Option<T>) {
        self.set_at(i, value)
    }

    pub const fn new() -> Self {
        Self { items: [None; N], head: 0, len: 0 }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    /// The head element, if any, without removing it — lets a caller validate
    /// something about the front of the queue before committing to `pop_front`
    /// (RFC-0010's capability-transfer path needs this: check the receiver has a
    /// valid destination slot *before* dequeuing it, so a failed transfer leaves
    /// the queue untouched rather than losing an entry).
    pub fn front(&self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.get_at(self.head)
        }
    }

    /// The `k`-th element from the front. For [`crate::wf`]'s checks: nothing in the kernel's own logic walks a queue.
    pub fn nth(&self, k: usize) -> Option<T> {
        if k < self.len {
            self.get_at((self.head + k) % N)
        } else {
            None
        }
    }

    /// Whether the representation is consistent: exactly the `len` slots from `head` are occupied.
    pub fn consistent(&self) -> bool {
        if self.len > N || self.head >= N.max(1) {
            return false;
        }
        let mut ok = true;
        for i in 0..N {
            ok &= self.get_at((self.head + i) % N).is_some() == (i < self.len);
        }
        ok
    }

    pub fn push_back(&mut self, value: T) -> bool {
        if self.len >= N {
            return false;
        }
        let idx = (self.head + self.len) % N;
        self.set_at(idx, Some(value));
        self.len += 1;
        true
    }

    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.get_at(self.head);
        self.set_at(self.head, None);
        self.head = (self.head + 1) % N;
        self.len -= 1;
        value
    }
}

impl<T: Copy + PartialEq, const N: usize> ArrayQueue<T, N> {
    /// Removes the first occurrence of `value`, preserving the relative order
    /// of everything else. Returns whether it was found.
    ///
    /// `head` never moves — surviving elements are rewritten starting there as
    /// they're found, so the write cursor never overtakes the (always
    /// further-ahead, or equal) read cursor within this same pass.
    pub fn remove(&mut self, value: T) -> bool {
        let mut found = false;
        let mut write = self.head;
        let mut new_len = 0;
        for i in 0..self.len {
            let idx = (self.head + i) % N;
            let item = self.get_at(idx);
            self.set_at(idx, None);
            if !found && item == Some(value) {
                found = true;
                continue;
            }
            self.set_at(write, item);
            write = (write + 1) % N;
            new_len += 1;
        }
        self.len = new_len;
        found
    }
}

impl<T: Copy, const N: usize> Default for ArrayQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_order() {
        let mut q: ArrayQueue<u32, 4> = ArrayQueue::new();
        assert!(q.is_empty());
        assert!(q.push_back(1));
        assert!(q.push_back(2));
        assert!(q.push_back(3));
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.pop_front(), Some(2));
        assert!(q.push_back(4));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.pop_front(), Some(4));
        assert_eq!(q.pop_front(), None);
        assert!(q.is_empty());
    }

    #[test]
    fn front_peeks_without_removing() {
        let mut q: ArrayQueue<u32, 4> = ArrayQueue::new();
        assert_eq!(q.front(), None);
        q.push_back(1);
        q.push_back(2);
        assert_eq!(q.front(), Some(1));
        assert_eq!(q.front(), Some(1), "front does not mutate the queue");
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.front(), Some(2));
    }

    #[test]
    fn rejects_push_past_capacity() {
        let mut q: ArrayQueue<u32, 2> = ArrayQueue::new();
        assert!(q.push_back(1));
        assert!(q.push_back(2));
        assert!(!q.push_back(3));
    }

    #[test]
    fn wraps_around_the_backing_array() {
        let mut q: ArrayQueue<u32, 2> = ArrayQueue::new();
        q.push_back(1);
        q.pop_front();
        q.push_back(2);
        q.push_back(3);
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(3));
    }

    #[test]
    fn remove_drops_the_named_entry_and_preserves_order() {
        let mut q: ArrayQueue<u32, 4> = ArrayQueue::new();
        q.push_back(1);
        q.push_back(2);
        q.push_back(3);
        assert!(q.remove(2));
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn remove_reports_absence_without_touching_the_queue() {
        let mut q: ArrayQueue<u32, 4> = ArrayQueue::new();
        q.push_back(1);
        q.push_back(2);
        assert!(!q.remove(99));
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.pop_front(), Some(2));
    }

    #[test]
    fn remove_only_drops_the_first_occurrence() {
        let mut q: ArrayQueue<u32, 4> = ArrayQueue::new();
        q.push_back(1);
        q.push_back(1);
        q.push_back(2);
        assert!(q.remove(1));
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn remove_works_after_the_backing_array_has_wrapped() {
        let mut q: ArrayQueue<u32, 3> = ArrayQueue::new();
        q.push_back(1);
        q.push_back(2);
        q.pop_front();
        q.push_back(3);
        q.push_back(4);
        // Backing layout now wraps: head sits mid-array, [2, 3, 4] logically.
        assert!(q.remove(3));
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(4));
        assert_eq!(q.pop_front(), None);
    }
}
