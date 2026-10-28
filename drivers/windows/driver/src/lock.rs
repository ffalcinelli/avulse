//! A kernel spin lock around a value. Holding it raises the IRQL to DISPATCH_LEVEL, so it can be
//! taken from the packet hooks as from the dispatch routines; keep what runs under it short.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

use crate::sys;

pub struct SpinLock<T> {
    lock: UnsafeCell<sys::KSPIN_LOCK>,
    value: UnsafeCell<T>,
}

// SAFETY: the value is only reached through the lock.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: as above.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// `KeInitializeSpinLock` sets the lock to zero.
    pub const fn new(value: T) -> Self {
        SpinLock {
            lock: UnsafeCell::new(0),
            value: UnsafeCell::new(value),
        }
    }

    /// Takes the lock. At IRQL <= DISPATCH_LEVEL.
    pub fn lock(&self) -> Guard<'_, T> {
        // SAFETY: the lock is initialized, and this is at IRQL <= DISPATCH_LEVEL.
        let irql = unsafe { sys::KeAcquireSpinLockRaiseToDpc(self.lock.get()) };
        Guard { lock: self, irql }
    }
}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
    irql: sys::KIRQL,
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the lock is held.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the lock is held, and this guard is the only one.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: held since `lock`, with this IRQL saved.
        unsafe { sys::KeReleaseSpinLock(self.lock.lock.get(), self.irql) };
    }
}
