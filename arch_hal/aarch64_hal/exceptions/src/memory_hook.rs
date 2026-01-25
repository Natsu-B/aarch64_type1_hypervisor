#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AccessClass {
    /// Normal memory semantics; splitting/unaligned accesses do not change behavior.
    NormalMemory,
    /// Device or MMIO semantics; splitting/unaligned accesses can change device-visible effects.
    DeviceMmio,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SplitPolicy {
    /// Never split an access.
    Never,
    /// Allow split only when a side-effect-free probe confirms each sub-access is safe.
    OnlyIfProbe,
    /// Always allow split emulation (intended for `NormalMemory` only).
    Always,
}

#[derive(Copy, Clone, Debug)]
pub enum MmioError {
    Unhandled,
    Fault,
}

#[derive(Copy, Clone)]
pub struct MmioHandler {
    pub ctx: *const (),
    pub read: fn(*const (), u64, u8) -> Result<u64, MmioError>,
    pub write: fn(*const (), u64, u8, u64) -> Result<(), MmioError>,
    /// Optional capability probe to check whether a sub-access can be handled
    /// without side effects.
    pub probe: Option<fn(*const (), u64, u8, bool) -> bool>,
    /// Optional pair access hooks to avoid partial side effects on LDP/STP.
    pub read_pair: Option<fn(*const (), u64, u64, u8) -> Result<(u64, u64), MmioError>>,
    pub write_pair: Option<fn(*const (), u64, u64, u8, u64, u64) -> Result<(), MmioError>>,
    /// Whether this handler models normal RAM semantics or device/MMIO semantics.
    pub access_class: AccessClass,
    /// Policy for allowing split emulation of an access.
    pub split_policy: SplitPolicy,
}

// SAFETY: The handler callbacks (including `probe`) must be thread-safe, and
// `ctx` must remain valid for concurrent access while the handler is in use.
unsafe impl Sync for MmioHandler {}

impl MmioHandler {
    #[inline]
    pub fn read(&self, ipa: u64, size: u8) -> Result<u64, MmioError> {
        (self.read)(self.ctx, ipa, size)
    }

    #[inline]
    pub fn write(&self, ipa: u64, size: u8, value: u64) -> Result<(), MmioError> {
        (self.write)(self.ctx, ipa, size, value)
    }

    #[inline]
    pub fn read_pair(&self, ipa0: u64, ipa1: u64, size: u8) -> Result<(u64, u64), MmioError> {
        match self.read_pair {
            Some(f) => f(self.ctx, ipa0, ipa1, size),
            None => Err(MmioError::Unhandled),
        }
    }

    #[inline]
    pub fn write_pair(
        &self,
        ipa0: u64,
        ipa1: u64,
        size: u8,
        v0: u64,
        v1: u64,
    ) -> Result<(), MmioError> {
        match self.write_pair {
            Some(f) => f(self.ctx, ipa0, ipa1, size, v0, v1),
            None => Err(MmioError::Unhandled),
        }
    }

    /// Side-effect-free probe for split sub-accesses. Single accesses should use read/write directly.
    #[inline]
    pub fn probe_subaccess(&self, ipa: u64, size: u8, is_write: bool) -> bool {
        match self.probe {
            Some(f) => f(self.ctx, ipa, size, is_write),
            None => false,
        }
    }

    #[inline]
    pub fn can_split_without_probe(&self) -> bool {
        self.access_class == AccessClass::NormalMemory && self.split_policy == SplitPolicy::Always
    }

    #[inline]
    pub fn can_split_subaccess(&self, ipa: u64, size: u8, is_write: bool) -> bool {
        match self.split_policy {
            SplitPolicy::Never => false,
            SplitPolicy::Always => {
                debug_assert!(
                    self.access_class == AccessClass::NormalMemory,
                    "Always split policy is only safe for normal memory"
                );
                self.access_class == AccessClass::NormalMemory
            }
            SplitPolicy::OnlyIfProbe => self.probe_subaccess(ipa, size, is_write),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_read(_: *const (), _: u64, _: u8) -> Result<u64, MmioError> {
        Ok(0)
    }
    fn dummy_write(_: *const (), _: u64, _: u8, _: u64) -> Result<(), MmioError> {
        Ok(())
    }

    fn make_handler(
        access_class: AccessClass,
        split_policy: SplitPolicy,
        probe: Option<fn(*const (), u64, u8, bool) -> bool>,
    ) -> MmioHandler {
        MmioHandler {
            ctx: core::ptr::null(),
            read: dummy_read,
            write: dummy_write,
            probe,
            read_pair: None,
            write_pair: None,
            access_class,
            split_policy,
        }
    }

    fn probe_true(_: *const (), _: u64, _: u8, _: bool) -> bool {
        true
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(all(test, not(target_arch = "aarch64")), test)]
    fn device_never_disallows_split() {
        let h = make_handler(AccessClass::DeviceMmio, SplitPolicy::Never, None);
        assert!(!h.can_split_subaccess(0, 4, false));
        let h_probe = make_handler(
            AccessClass::DeviceMmio,
            SplitPolicy::Never,
            Some(probe_true),
        );
        assert!(!h_probe.can_split_subaccess(0, 4, false));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(all(test, not(target_arch = "aarch64")), test)]
    fn device_probe_requires_probe() {
        let h = make_handler(AccessClass::DeviceMmio, SplitPolicy::OnlyIfProbe, None);
        assert!(!h.can_split_subaccess(0, 4, false));
        let h_probe = make_handler(
            AccessClass::DeviceMmio,
            SplitPolicy::OnlyIfProbe,
            Some(probe_true),
        );
        assert!(h_probe.can_split_subaccess(0, 4, false));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(all(test, not(target_arch = "aarch64")), test)]
    fn normal_always_allows_without_probe() {
        let h = make_handler(AccessClass::NormalMemory, SplitPolicy::Always, None);
        assert!(h.can_split_without_probe());
        assert!(h.can_split_subaccess(0, 8, true));
    }

    #[cfg_attr(all(test, target_arch = "aarch64"), test_case)]
    #[cfg_attr(all(test, not(target_arch = "aarch64")), test)]
    fn normal_probe_tracks_probe() {
        let h = make_handler(AccessClass::NormalMemory, SplitPolicy::OnlyIfProbe, None);
        assert!(!h.can_split_subaccess(0, 8, false));
        let h_probe = make_handler(
            AccessClass::NormalMemory,
            SplitPolicy::OnlyIfProbe,
            Some(probe_true),
        );
        assert!(h_probe.can_split_subaccess(0, 8, false));
    }
}
