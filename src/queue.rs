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
    pub const fn new() -> Self {
        Self { items: [None; N], head: 0, len: 0 }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
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
            self.items[self.head]
        }
    }

    pub fn push_back(&mut self, value: T) -> bool {
        if self.len >= N {
            return false;
        }
        let idx = (self.head + self.len) % N;
        self.items[idx] = Some(value);
        self.len += 1;
        true
    }

    pub fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.items[self.head].take();
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
            let item = self.items[idx].take();
            if !found && item == Some(value) {
                found = true;
                continue;
            }
            self.items[write] = item;
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
