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
pub use dtb_parser::WalkError;
pub use dtb_parser::WalkResult;

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

    fn assert_walk_ok(result: WalkResult<(), ()>) {
        match result {
            Ok(ControlFlow::Continue(())) | Ok(ControlFlow::Break(())) => {}
            Err(WalkError::Dtb(err)) => panic!("{}", err),
            Err(WalkError::User(())) => panic!("unexpected user error"),
        }
    }
    #[test]
    fn it_works() {
        let test_data = std::fs::read("test/test.dtb").expect("failed to load dtb files");
        let aligned = align_dtb(&test_data);
        let test_data_addr = aligned.as_ptr() as usize;
        let parser = DtbParser::init(test_data_addr).unwrap();

        let mut counter = 0;
        let result = parser.find_node(None, Some("arm,pl011"), &mut |address, size| {
            pr_debug!("find pl011 node, address: {} size: {}", address, size);
            assert_eq!(address, PL011_DEBUG_UART_ADDRESS);
            assert_eq!(size, PL011_DEBUG_UART_SIZE);
            counter += 1;
            Ok(ControlFlow::Continue(()))
        });
        assert_walk_ok(result);
        assert_eq!(counter, 1);

        counter = 0;
        let result = parser.find_node(Some("memory"), None, &mut |address, size| {
            pr_debug!("find memory node, address: {} size: {}", address, size);
            assert_eq!(address, MEMORY_ADDRESS);
            assert_eq!(size, MEMORY_SIZE);
            counter += 1;
            Ok(ControlFlow::Continue(()))
        });
        assert_walk_ok(result);
        assert_eq!(counter, 1);
        counter = 0;
        let result = parser.find_node(None, Some("arm,gic-400"), &mut |address, size| {
            pr_debug!("find gic node, address: {} size: {}", address, size);
            counter += 1;
            Ok(ControlFlow::Continue(()))
        });
        assert_walk_ok(result);
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
        let result = parser.find_reserved_memory_node(
            &mut |addr, size| {
                captured = Some((addr, size));
                Ok(ControlFlow::Break(()))
            },
            &mut |_, _, _| -> WalkResult<(), ()> {
                Err(WalkError::Dtb("reserved-memory: unexpected dynamic entry"))
            },
        );
        match result {
            Ok(ControlFlow::Break(())) => {}
            Ok(ControlFlow::Continue(())) => panic!("reserved-memory: node not found"),
            Err(WalkError::Dtb(err)) => panic!("{}", err),
            Err(WalkError::User(())) => panic!("unexpected user error"),
        }
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

        let result = parser.find_reserved_memory_node(
            &mut |addr, size| {
                static_called = true;
                pr_debug!(
                    "unexpected static reserved-memory: {:#x}, {:#x}",
                    addr,
                    size
                );
                Ok(ControlFlow::Continue(()))
            },
            &mut |alloc_size, alignment, alloc_range| {
                dynamic_captured = Some((alloc_size, alignment, alloc_range));
                Ok(ControlFlow::Break(()))
            },
        );
        match result {
            Ok(ControlFlow::Break(())) => {}
            Ok(ControlFlow::Continue(())) => panic!("reserved-memory: node not found"),
            Err(WalkError::Dtb(err)) => panic!("{}", err),
            Err(WalkError::User(())) => panic!("unexpected user error"),
        }

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

        let result = parser.for_each_node_view(&mut |node| {
            if node
                .compatible_contains("arm,pl011")
                .map_err(WalkError::Dtb)?
            {
                found = true;
                let value = node.interrupt_cells().map_err(WalkError::Dtb)?;
                assert_eq!(value, Some(3));
                let mut spec = None;
                let _ = node.for_each_interrupt_specifier(&mut |cells| {
                    spec = Some([cells[0], cells[1], cells[2]]);
                    Ok(ControlFlow::Break(()))
                })?;
                assert_eq!(spec, Some([0, 0x79, 4]));
                return Ok(ControlFlow::Break(()));
            }
            Ok(ControlFlow::Continue(()))
        });
        assert_walk_ok(result);
        assert!(found);
    }

    #[test]
    fn node_view_by_phandle_callback_has_ancestors() {
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
        let mut parent_phandle: Option<u32> = None;

        let result = parser.for_each_node_view(&mut |node| {
            if node
                .compatible_contains("arm,pl011")
                .map_err(WalkError::Dtb)?
            {
                found = true;
                let phandle = node
                    .interrupt_parent_phandle()
                    .map_err(WalkError::Dtb)?
                    .ok_or(WalkError::Dtb("interrupt-parent: missing phandle"))?;
                parent_phandle = Some(phandle);
                return Ok(ControlFlow::Break(()));
            }
            Ok(ControlFlow::Continue(()))
        });
        assert_walk_ok(result);
        assert!(found);

        let phandle = parent_phandle.expect("interrupt-parent: missing phandle");
        let result = parser.with_node_view_by_phandle(phandle, &mut |ctrl| {
            assert!(ctrl.parent_address_cells().is_ok());
            assert!(ctrl.parent_size_cells().is_ok());
            Ok(())
        });
        match result {
            Ok(Some(())) => {}
            Ok(None) => panic!("interrupt-parent: controller not found"),
            Err(err) => panic!("{}", err),
        }
    }

    #[test]
    fn ranges_pci_3cells_translation_works() {
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let mut path = PathBuf::from(out_dir);
        path.push("ranges_pci_3cells.dtb");

        let data = std::fs::read(&path).unwrap();
        let parser = DtbParser::init(data.as_ptr() as usize).unwrap();

        let mut found = None;
        let result = parser.find_node(None, Some("test,dev"), &mut |addr, size| {
            found = Some((addr, size));
            Ok(ControlFlow::Break(()))
        });
        match result {
            Ok(ControlFlow::Break(())) => {}
            Ok(ControlFlow::Continue(())) => panic!("find_node: device not found"),
            Err(WalkError::Dtb(err)) => panic!("{}", err),
            Err(WalkError::User(())) => panic!("unexpected user error"),
        }
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

        let result = parser.for_each_node_view(&mut |node| {
            if node
                .compatible_contains("brcm,bcm2712-pcie")
                .map_err(WalkError::Dtb)?
            {
                found = true;
                let mut iter = node.reg_iter().map_err(WalkError::Dtb)?;
                match iter.next() {
                    Some(Ok((addr, size))) => {
                        assert_eq!(addr, 0x10_0012_0000);
                        assert_eq!(size, 0x9310);
                    }
                    Some(Err(err)) => return Err(WalkError::Dtb(err)),
                    None => return Err(WalkError::Dtb("reg_iter: no entries")),
                }
                return Ok(ControlFlow::Break(()));
            }
            Ok(ControlFlow::Continue(()))
        });
        assert_walk_ok(result);
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
