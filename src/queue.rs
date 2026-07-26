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
}
