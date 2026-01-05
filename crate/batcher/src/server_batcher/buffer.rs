mod error;

pub use error::Error;

pub struct Buffer<T> {
    capacity: usize,
    data: Vec<T>,
}

impl<T> Buffer<T> {
    /* The buffer invariant is that the data length is strictly smaller than its
    ,* capacity: as soon as a method modifying its capacity or data invalidates
    ,* this invariant, the buffer is flushed and its values returned.
    ,*/

    pub const fn new() -> Self {
        Self {
            capacity: 0,
            data: Vec::new(),
        }
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub const fn len(&self) -> usize {
        self.data.len()
    }

    pub const fn resize(&mut self, capacity: usize) -> Result<(), Error> {
        if capacity < self.capacity {
            Err(Error::InvalidResizing {
                old: self.capacity,
                new: capacity,
            })
        } else {
            self.capacity = capacity;
            Ok(())
        }
    }

    fn flush_if_full(&mut self) -> Option<Vec<T>> {
        if self.capacity == self.data.len() {
            Some(std::mem::take(&mut self.data))
        } else {
            None
        }
    }

    pub fn shrink(&mut self) -> Option<Vec<T>> {
        if self.capacity == 0 {
            None
        } else {
            self.capacity -= 1;
            self.flush_if_full()
        }
    }

    pub fn push(&mut self, datum: T) -> Option<Vec<T>> {
        self.data.push(datum);
        self.flush_if_full()
    }
}
