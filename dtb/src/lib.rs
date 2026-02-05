#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod ast;
pub(crate) mod dtb_parser;
pub mod overlay;

pub use dtb_parser::DtbGenerator;
pub use dtb_parser::DtbNodeView;
pub use dtb_parser::DtbParser;
pub use dtb_parser::InterruptCellsIter;
pub use dtb_parser::RangesEntry;
pub use dtb_parser::RangesIter;
pub use dtb_parser::RegIter;
pub use dtb_parser::Unchecked;
pub use dtb_parser::Validated;

pub use ast::Borrowed;
pub use ast::DeviceTree;
pub use ast::DeviceTreeBorrowed;
pub use ast::DeviceTreeEditExt;
pub use ast::DeviceTreeOwned;
pub use ast::DeviceTreeQueryExt;
pub use ast::Header;
pub use ast::MemReserve;
pub use ast::MmioCollectExt;
pub use ast::NameRef;
pub use ast::NodeEditExt;
pub use ast::NodeId;
pub use ast::NodeQueryExt;
pub use ast::Owned;
pub use ast::ValueRef;

#[cfg(test)]
mod tests {
    use super::*;
    use allocator::AlignedSliceBox;
    use core::mem::MaybeUninit;
    use core::mem::align_of;
    use core::ops::ControlFlow;
    use std::env;
    use std::path::PathBuf;

    fn align_dtb(bytes: &[u8]) -> AlignedSliceBox<u8> {
        let mut buf = AlignedSliceBox::<u8>::new_uninit_with_align(bytes.len(), align_of::<u64>())
            .expect("failed to allocate aligned dtb buffer");
        for (dst, &src) in buf.iter_mut().zip(bytes.iter()) {
            *dst = MaybeUninit::new(src);
        }
        unsafe { buf.assume_init() }
    }

    const PL011_DEBUG_UART_ADDRESS: usize = 0x10_7D00_1000;
    const PL011_DEBUG_UART_SIZE: usize = 0x200;
    const MEMORY_ADDRESS: usize = 0x0;
    const MEMORY_SIZE: usize = 0x2800_0000;
    #[test]
    fn it_works() {
        let test_data = std::fs::read("test/test.dtb").expect("failed to load dtb files");
        let aligned = align_dtb(&test_data);
        let test_data_addr = aligned.as_ptr() as usize;
        let parser = DtbParser::init(test_data_addr).unwrap();

        let mut counter = 0;
        parser
            .find_node(None, Some("arm,pl011"), &mut |address, size| {
                pr_debug!("find pl011 node, address: {} size: {}", address, size);
                assert_eq!(address, PL011_DEBUG_UART_ADDRESS);
                assert_eq!(size, PL011_DEBUG_UART_SIZE);
                counter += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(counter, 1);

        counter = 0;
        parser
            .find_node(Some("memory"), None, &mut |address, size| {
                pr_debug!("find memory node, address: {} size: {}", address, size);
                assert_eq!(address, MEMORY_ADDRESS);
                assert_eq!(size, MEMORY_SIZE);
                counter += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(counter, 1);
        counter = 0;
        parser
            .find_node(None, Some("arm,gic-400"), &mut |address, size| {
                pr_debug!("find gic node, address: {} size: {}", address, size);
                counter += 1;
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(counter, 4);
    }

    #[test]
    fn reserved_memory_generated_dtb() {
        let out_dir = env!("OUT_DIR");
        let mut path = PathBuf::from(out_dir);
        path.push("reserved_memory.dtb");
        assert!(
            path.exists(),
            "{} not found. dtc is required to build DTS fixtures.",
            path.display()
        );
        let test_data = std::fs::read(&path).expect("failed to load generated dtb file");
        let aligned = align_dtb(&test_data);
        let test_data_addr = aligned.as_ptr() as usize;
        let parser = DtbParser::init(test_data_addr).unwrap();

        let mut captured: Option<(usize, usize)> = None;
        parser
            .find_reserved_memory_node(
                &mut |addr, size| {
                    captured = Some((addr, size));
                    ControlFlow::Break(())
                },
                &mut |_, _, _| -> Result<ControlFlow<()>, ()> { unreachable!() },
            )
            .unwrap();
        let (addr, size) = captured.expect("no reserved-memory region found");
        assert_eq!(addr, 0x20);
        assert_eq!(size, 0x10);
    }

    #[test]
    fn reserved_memory_dynamic_generated_dtb() {
        let out_dir = env!("OUT_DIR");
        let mut path = PathBuf::from(out_dir);
        path.push("reserved_memory_dynamic.dtb");
        assert!(
            path.exists(),
            "{} not found. dtc is required to build DTS fixtures.",
            path.display()
        );

        let test_data = std::fs::read(&path).expect("failed to load generated dtb file");
        let aligned = align_dtb(&test_data);
        let test_data_addr = aligned.as_ptr() as usize;
        let parser = DtbParser::init(test_data_addr).unwrap();

        let mut static_called = false;
        let mut dynamic_captured: Option<(usize, Option<usize>, Option<(usize, usize)>)> = None;

        parser
            .find_reserved_memory_node(
                &mut |addr, size| {
                    static_called = true;
                    pr_debug!(
                        "unexpected static reserved-memory: {:#x}, {:#x}",
                        addr,
                        size
                    );
                    ControlFlow::Continue(())
                },
                &mut |alloc_size, alignment, alloc_range| {
                    dynamic_captured = Some((alloc_size, alignment, alloc_range));
                    Ok(ControlFlow::Break(()))
                },
            )
            .expect("failed to parse reserved-memory node");

        assert!(
            !static_called,
            "static reserved-memory entry unexpectedly called"
        );
        let (alloc_size, alignment, alloc_range) =
            dynamic_captured.expect("no dynamic reserved-memory captured");

        assert_eq!(alloc_size, 0x0001_0000);
        assert_eq!(alignment, Some(0x0001_0000));
        assert_eq!(alloc_range, Some((0x4000_0000, 0x1000_0000)));
    }

    #[test]
    fn node_view_interrupts() {
        let out_dir = env!("OUT_DIR");
        let mut path = PathBuf::from(out_dir);
        path.push("node_view_interrupts.dtb");
        assert!(
            path.exists(),
            "{} not found. dtc is required to build DTS fixtures.",
            path.display()
        );

        let test_data = std::fs::read(&path).expect("failed to load generated dtb file");
        let aligned = align_dtb(&test_data);
        let test_data_addr = aligned.as_ptr() as usize;
        let parser = DtbParser::init(test_data_addr).unwrap();

        let mut found = false;

        let result = parser
            .for_each_node_view(&mut |node| match node.compatible_contains("arm,pl011") {
                Ok(true) => {
                    found = true;
                    match node.interrupt_cells() {
                        Ok(value) => assert_eq!(value, Some(3)),
                        Err(err) => return ControlFlow::Break(Err(err)),
                    }
                    let mut spec = None;
                    if let Err(err) = node.for_each_interrupt_specifier(&mut |cells| {
                        spec = Some([cells[0], cells[1], cells[2]]);
                        ControlFlow::Break(())
                    }) {
                        return ControlFlow::Break(Err(err));
                    }
                    assert_eq!(spec, Some([0, 0x79, 4]));
                    ControlFlow::Break(Ok(()))
                }
                Ok(false) => ControlFlow::Continue(()),
                Err(err) => ControlFlow::Break(Err(err)),
            })
            .unwrap();

        match result {
            ControlFlow::Continue(()) | ControlFlow::Break(Ok(())) => {}
            ControlFlow::Break(Err(err)) => panic!("{}", err),
        }
        assert!(found);
    }

    #[test]
    fn ranges_pci_3cells_translation_works() {
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let mut path = PathBuf::from(out_dir);
        path.push("ranges_pci_3cells.dtb");

        let data = std::fs::read(&path).unwrap();
        let parser = DtbParser::init(data.as_ptr() as usize).unwrap();

        let mut found = None;
        parser
            .find_node(None, Some("test,dev"), &mut |addr, size| {
                found = Some((addr, size));
                ControlFlow::Break(())
            })
            .unwrap();
        let (addr, size) = found.unwrap();
        assert_eq!(addr, 0x4000_1020);
        assert_eq!(size, 0x100);
    }

    #[test]
    fn pcie_reg_iter_skips_self_ranges() {
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let mut path = PathBuf::from(out_dir);
        path.push("pcie_reg_ranges_not_covered.dtb");

        assert!(
            path.exists(),
            "{} not found. dtc is required to build DTS fixtures.",
            path.display()
        );

        let test_data = std::fs::read(&path).expect("failed to load generated dtb file");
        let aligned = align_dtb(&test_data);
        let test_data_addr = aligned.as_ptr() as usize;
        let parser = DtbParser::init(test_data_addr).unwrap();

        let mut found = false;

        let result = parser
            .for_each_node_view(
                &mut |node| match node.compatible_contains("brcm,bcm2712-pcie") {
                    Ok(true) => {
                        found = true;
                        match node.reg_iter() {
                            Ok(mut iter) => match iter.next() {
                                Some(Ok((addr, size))) => {
                                    assert_eq!(addr, 0x10_0012_0000);
                                    assert_eq!(size, 0x9310);
                                }
                                Some(Err(err)) => return ControlFlow::Break(Err(err)),
                                None => return ControlFlow::Break(Err("reg_iter: no entries")),
                            },
                            Err(err) => return ControlFlow::Break(Err(err)),
                        }
                        ControlFlow::Break(Ok(()))
                    }
                    Ok(false) => ControlFlow::Continue(()),
                    Err(err) => ControlFlow::Break(Err(err)),
                },
            )
            .unwrap();

        match result {
            ControlFlow::Continue(()) | ControlFlow::Break(Ok(())) => {}
            ControlFlow::Break(Err(err)) => panic!("{}", err),
        }
        assert!(found);
    }
}

#[cfg(test)]
#[macro_export]
macro_rules! pr_debug {
    ($fmt:expr) => (println!($fmt));
    ($fmt:expr, $($arg:tt)*) => (println!($fmt, $($arg)*));
}

#[cfg(not(test))]
#[macro_export]
macro_rules! pr_debug {
    ($fmt:expr) => {};
    ($fmt:expr, $($arg:tt)*) => {};
}
