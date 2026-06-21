//! Pure BCM2712 PCIe range and policy helpers, kept host-testable.

use super::Rp1InitMode;

pub const MIB: u64 = 1024 * 1024;

pub const fn outbound_window_is_valid(cpu_base: u64, pcie_base: u64, size: u64) -> bool {
    size != 0
        && cpu_base % MIB == 0
        && pcie_base % MIB == 0
        && size % MIB == 0
        && cpu_base.checked_add(size - 1).is_some()
        && (cpu_base >> 20) <= 0x000f_ffff
        && ((cpu_base + size - 1) >> 20) <= 0x000f_ffff
}

pub fn translate_pcie_to_cpu(
    cpu_base: u64,
    pcie_base: u64,
    size: u64,
    pcie_address: u64,
    len: u64,
) -> Option<u64> {
    if len == 0 || size == 0 {
        return None;
    }
    let Some(end) = pcie_address.checked_add(len) else {
        return None;
    };
    let Some(window_end) = pcie_base.checked_add(size) else {
        return None;
    };
    if pcie_address < pcie_base || end > window_end {
        return None;
    }
    cpu_base.checked_add(pcie_address - pcie_base)
}

pub const fn encode_config_bdf(bus: u8, device: u8, function: u8) -> Option<u32> {
    if device > 31 || function > 7 {
        return None;
    }
    Some(((bus as u32) << 20) | ((device as u32) << 15) | ((function as u32) << 12))
}

pub const fn requires_full_pcie_init(mode: Rp1InitMode, link_is_up: bool) -> bool {
    match mode {
        Rp1InitMode::FullPcieInit => true,
        Rp1InitMode::Auto => !link_is_up,
        Rp1InitMode::FirmwareAssisted | Rp1InitMode::AuditOnly => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_window_validation_rejects_unaligned_and_overflowed_ranges() {
        assert!(outbound_window_is_valid(0x1f_0000_0000, 0, 0x4000_0000));
        assert!(!outbound_window_is_valid(1, 0, MIB));
        assert!(!outbound_window_is_valid(0, 0, MIB - 1));
        assert!(!outbound_window_is_valid(u64::MAX & !(MIB - 1), 0, MIB));
    }

    #[test]
    fn translation_covers_entire_bar_only() {
        assert_eq!(
            translate_pcie_to_cpu(0x1f_0000_0000, 0, 0x4000_0000, 0x41_0000, 0x1_0000),
            Some(0x1f_0041_0000)
        );
        assert_eq!(translate_pcie_to_cpu(0, 0, 0x1000, 0xfff, 2), None);
    }

    #[test]
    fn bdf_encoding_matches_brcm_config_aperture() {
        assert_eq!(encode_config_bdf(1, 0, 0), Some(0x0010_0000));
        assert_eq!(encode_config_bdf(1, 32, 0), None);
    }

    #[test]
    fn only_auto_and_full_mode_can_request_a_reset() {
        assert!(requires_full_pcie_init(Rp1InitMode::FullPcieInit, true));
        assert!(requires_full_pcie_init(Rp1InitMode::Auto, false));
        assert!(!requires_full_pcie_init(Rp1InitMode::Auto, true));
        assert!(!requires_full_pcie_init(
            Rp1InitMode::FirmwareAssisted,
            false
        ));
        assert!(!requires_full_pcie_init(Rp1InitMode::AuditOnly, false));
    }
}
