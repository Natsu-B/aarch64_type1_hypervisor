//! Pure BCM2712 PCIe range and policy helpers, kept host-testable.

use super::Rp1InitMode;

pub const MIB: u64 = 1024 * 1024;
pub const RP1_LOW_BAR1_BASE: u64 = 0x0000_0000;
pub const RP1_LOW_BAR2_BASE: u64 = 0x0040_0000;
pub const RP1_LOW_BAR0_BASE: u64 = 0x0080_0000;
pub const RP1_PERIPHERAL_SIZE: u64 = 0x40_0000;
pub const RP1_PERIPHERAL_DMA_BASE: u64 = 0xc0_4000_0000;

pub const fn bar_size_from_mask(mask: u32) -> Option<u64> {
    let size = (!(mask & !0xf)).wrapping_add(1) as u64;
    if size != 0 && size.is_power_of_two() {
        Some(size)
    } else {
        None
    }
}

pub const fn assigned_bar_is_probe_mask(raw: u32, probe_mask: u32) -> bool {
    raw == probe_mask || (raw & !0xf) == (probe_mask & !0xf)
}

pub const fn assigned_bar_address_is_valid(bar: u8, address: u64) -> bool {
    address != 0 || bar == 1
}

pub const fn range_fits(base: u64, size: u64, outer_base: u64, outer_size: u64) -> bool {
    if size == 0 || outer_size == 0 || base < outer_base {
        return false;
    }
    match (base.checked_add(size), outer_base.checked_add(outer_size)) {
        (Some(end), Some(outer_end)) => end <= outer_end,
        _ => false,
    }
}

pub const fn encode_dw_axi_dmac_cfg2_l(dst_per: u32) -> Option<u32> {
    if dst_per > 0x3f {
        return None;
    }
    // Linked-list multiblock source/destination and CFG2 destination request.
    Some((3 << 0) | (3 << 2) | (dst_per << 11))
}

pub const fn encode_dw_axi_dmac_cfg2_h(priority: u32) -> Option<u32> {
    if priority > 0x7 {
        return None;
    }
    // Mem->peripheral, DMAC flow controller, both handshake selectors HW.
    Some(1 | (priority << 20))
}

pub const fn rp1_peripheral_dma_address(
    bar_cpu_base: u64,
    cpu_alias: u64,
    len: u64,
) -> Option<u64> {
    if len == 0 || cpu_alias < bar_cpu_base {
        return None;
    }
    let offset = cpu_alias - bar_cpu_base;
    let end = match offset.checked_add(len) {
        Some(value) => value,
        None => return None,
    };
    if end > RP1_PERIPHERAL_SIZE {
        return None;
    }
    RP1_PERIPHERAL_DMA_BASE.checked_add(offset)
}

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

    #[test]
    fn bar_size_masks_decode_to_rp1_layout_sizes() {
        assert_eq!(bar_size_from_mask(0xffff_c000), Some(0x4000));
        assert_eq!(bar_size_from_mask(0xffc0_0000), Some(0x400000));
        assert_eq!(bar_size_from_mask(0xffff_0000), Some(0x10000));
    }

    #[test]
    fn low_rp1_layout_is_nonoverlapping_and_accepts_bar1_zero() {
        assert!(range_fits(RP1_LOW_BAR1_BASE, 0x400000, 0, 0x0090_0000));
        assert!(range_fits(RP1_LOW_BAR2_BASE, 0x10000, 0, 0x0090_0000));
        assert!(range_fits(RP1_LOW_BAR0_BASE, 0x4000, 0, 0x0090_0000));
        assert_eq!(RP1_LOW_BAR1_BASE + 0x400000, RP1_LOW_BAR2_BASE);
        assert!(RP1_LOW_BAR2_BASE + 0x10000 <= RP1_LOW_BAR0_BASE);
    }

    #[test]
    fn only_rp1_bar1_accepts_zero_address() {
        assert!(!assigned_bar_address_is_valid(0, 0));
        assert!(assigned_bar_address_is_valid(1, 0));
        assert!(!assigned_bar_address_is_valid(2, 0));
        assert!(assigned_bar_address_is_valid(0, 0x0080_0000));
        assert!(assigned_bar_address_is_valid(2, 0x0040_0000));
    }

    #[test]
    fn low_layout_translation_and_probe_mask_rejection() {
        assert_eq!(
            translate_pcie_to_cpu(0x1f_0000_0000, 0, 0x0100_0000, 0, 0x400000),
            Some(0x1f_0000_0000)
        );
        assert!(assigned_bar_is_probe_mask(0xffff_c000, 0xffff_c000));
        assert!(!assigned_bar_is_probe_mask(0x0080_0000, 0xffff_c000));
    }

    #[test]
    fn cfg2_encodes_rp1_tx_request_without_old_layout_bits() {
        assert_eq!(encode_dw_axi_dmac_cfg2_l(0x1a), Some(0x0000_d00f));
        assert_eq!(encode_dw_axi_dmac_cfg2_h(0), Some(1));
        assert_eq!(encode_dw_axi_dmac_cfg2_h(3), Some(0x0030_0001));
        assert_eq!(encode_dw_axi_dmac_cfg2_l(64), None);
    }

    #[test]
    fn rp1_uart_dr_uses_local_dma_address_not_cpu_alias() {
        assert_eq!(
            rp1_peripheral_dma_address(0x1f_0000_0000, 0x1f_0003_0000, 4),
            Some(0xc0_4003_0000)
        );
    }

    #[test]
    fn rp1_peripheral_dma_accepts_last_byte_in_bar1() {
        assert_eq!(
            rp1_peripheral_dma_address(0x1f_0000_0000, 0x1f_003f_ffff, 1),
            Some(0xc0_403f_ffff)
        );
    }

    #[test]
    fn rp1_peripheral_dma_rejects_first_byte_after_bar1() {
        assert_eq!(
            rp1_peripheral_dma_address(0x1f_0000_0000, 0x1f_0040_0000, 1),
            None
        );
    }

    #[test]
    fn rp1_peripheral_dma_rejects_range_crossing_bar1_end() {
        assert_eq!(
            rp1_peripheral_dma_address(0x1f_0000_0000, 0x1f_003f_ffff, 2),
            None
        );
    }
}
