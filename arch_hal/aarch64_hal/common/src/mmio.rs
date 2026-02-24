/// An MMIO region describing a device register frame.
///
/// `base` is the physical or already-mapped virtual base address used for volatile access.
/// `size` is the byte size of the region.
///
/// Implementations typically require:
/// - `base` aligned to the frame granule (commonly 4KiB),
/// - a mapping with device memory attributes,
/// - a region size matching the register block layout used by the backend.
#[derive(Copy, Clone, Debug)]
pub struct MmioRegion {
    pub base: usize,
    pub size: usize,
}
