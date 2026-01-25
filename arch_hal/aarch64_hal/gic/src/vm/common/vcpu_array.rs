use crate::GicError;
use crate::VcpuId;
use crate::VgicVcpuModel;
use core::mem::MaybeUninit;

pub(crate) struct VcpuArray<const VCPUS: usize, V> {
    len: usize,
    buf: [MaybeUninit<V>; VCPUS],
}

impl<const VCPUS: usize, V: VgicVcpuModel> VcpuArray<VCPUS, V> {
    pub(crate) fn new_with(
        len: usize,
        mut make: impl FnMut(VcpuId) -> V,
    ) -> Result<Self, GicError> {
        if len > VCPUS {
            return Err(GicError::OutOfResources);
        }
        // SAFETY: `[MaybeUninit<V>; VCPUS]` is uninitialised storage. `len <= VCPUS` is checked
        // above, we write every slot in the initialised prefix exactly once, and `Drop` only
        // touches that prefix so the remaining elements stay uninitialised and never dropped.
        let mut buf: [MaybeUninit<V>; VCPUS] = unsafe { MaybeUninit::uninit().assume_init() };
        for i in 0..len {
            buf[i] = MaybeUninit::new(make(VcpuId(i as u16)));
        }
        Ok(Self { len, buf })
    }
}

impl<const VCPUS: usize, V> VcpuArray<VCPUS, V> {
    pub(crate) fn get(&self, idx: usize) -> Option<&V> {
        if idx >= self.len {
            return None;
        }
        // SAFETY: `idx < len` is enforced above so the slot is initialised; returning `&V`
        // maintains aliasing rules because we only hand out shared references here.
        Some(unsafe { self.buf[idx].assume_init_ref() })
    }
}

impl<const VCPUS: usize, V> Drop for VcpuArray<VCPUS, V> {
    fn drop(&mut self) {
        for i in 0..self.len {
            // SAFETY: `len` tracks the initialised prefix; each element in `[0, len)` was
            // written exactly once in `new_with` and is dropped exactly once here.
            unsafe { self.buf[i].assume_init_drop() };
        }
    }
}
