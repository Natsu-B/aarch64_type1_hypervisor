extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::DeviceTree;
use crate::DeviceTreeEditExt;
use crate::DeviceTreeQueryExt;
use crate::NameRef;
use crate::NodeEditExt;
use crate::NodeId;
use crate::Owned;
use crate::ValueRef;

pub fn node_path<'dtb, State>(
    tree: &DeviceTree<'dtb, State>,
    node_id: NodeId,
) -> Result<String, &'static str> {
    if tree.node(node_id).is_none() {
        return Err("dtb: invalid node id");
    }
    if node_id == tree.root {
        return Ok("/".to_string());
    }

    let mut segments = Vec::new();
    let mut current = Some(node_id);
    while let Some(id) = current {
        let node = tree.node(id).ok_or("dtb: invalid node id")?;
        if id == tree.root {
            break;
        }
        segments.push(node.name.as_str().to_string());
        current = node.parent;
    }

    let mut path = String::from("/");
    for (index, segment) in segments.iter().rev().enumerate() {
        if index > 0 {
            path.push('/');
        }
        path.push_str(segment);
    }
    Ok(path)
}

pub fn copy_node_properties<'src, 'dst, State>(
    source: &DeviceTree<'src, State>,
    source_id: NodeId,
    target: &mut DeviceTree<'dst, Owned>,
    target_id: NodeId,
) -> Result<(), &'static str> {
    let source_node = source
        .node(source_id)
        .ok_or("dtb: invalid source node id")?;
    let target_node = target
        .node_mut(target_id)
        .ok_or("dtb: invalid target node id")?;

    for prop in &source_node.properties {
        target_node.set_property(
            NameRef::Owned(prop.name.as_str().to_string()),
            ValueRef::Owned(prop.value.as_slice().to_vec()),
        );
    }
    Ok(())
}

pub fn copy_node_with_ancestors<'src, 'dst, State>(
    source: &DeviceTree<'src, State>,
    target: &mut DeviceTree<'dst, Owned>,
    source_id: NodeId,
) -> Result<NodeId, &'static str> {
    let mut lineage = Vec::new();
    let mut current = Some(source_id);
    while let Some(id) = current {
        let node = source.node(id).ok_or("dtb: invalid source node id")?;
        lineage.push(id);
        current = node.parent;
    }
    lineage.reverse();

    let mut target_id = target.root;
    for &id in &lineage {
        if id == source.root {
            copy_node_properties(source, id, target, target.root)?;
            target_id = target.root;
            continue;
        }

        let child_name = source
            .node(id)
            .ok_or("dtb: invalid source node id")?
            .name
            .as_str()
            .to_string();

        let existing = {
            let parent = target
                .node(target_id)
                .ok_or("dtb: invalid target node id")?;
            parent.children.iter().copied().find(|&child_id| {
                target
                    .node(child_id)
                    .map(|child| child.name.as_str() == child_name)
                    .unwrap_or(false)
            })
        };

        let child_id = match existing {
            Some(child_id) => child_id,
            None => target.add_child(target_id, NameRef::Owned(child_name))?,
        };

        copy_node_properties(source, id, target, child_id)?;
        target_id = child_id;
    }

    Ok(target_id)
}

pub fn copy_subtree<'src, 'dst, State>(
    source: &DeviceTree<'src, State>,
    target: &mut DeviceTree<'dst, Owned>,
    source_id: NodeId,
) -> Result<NodeId, &'static str> {
    let target_id = copy_node_with_ancestors(source, target, source_id)?;
    let children = source
        .node(source_id)
        .ok_or("dtb: invalid source node id")?
        .children
        .clone();
    for child_id in children {
        copy_subtree(source, target, child_id)?;
    }
    Ok(target_id)
}

pub fn copy_subtree_to_path<'src, 'dst, State>(
    source: &DeviceTree<'src, State>,
    target: &mut DeviceTree<'dst, Owned>,
    source_id: NodeId,
    target_path: &str,
) -> Result<NodeId, &'static str> {
    let target_id = target.get_or_create_node_by_path(target_path)?;
    copy_node_properties(source, source_id, target, target_id)?;

    let children = source
        .node(source_id)
        .ok_or("dtb: invalid source node id")?
        .children
        .clone();
    for child_id in children {
        let child_name = source
            .node(child_id)
            .ok_or("dtb: invalid source node id")?
            .name
            .as_str();
        let child_target_path = if target_path == "/" {
            format!("/{child_name}")
        } else {
            format!("{target_path}/{child_name}")
        };
        copy_subtree_to_path(source, target, child_id, &child_target_path)?;
    }
    Ok(target_id)
}

pub fn encode_reg_entries(
    entries: &[(u64, u64)],
    addr_cells: usize,
    size_cells: usize,
) -> Result<Vec<u8>, &'static str> {
    if addr_cells == 0 {
        return Err("dtb: #address-cells must be non-zero");
    }
    if size_cells == 0 {
        return Err("dtb: #size-cells must be non-zero");
    }
    let cells_per_entry = addr_cells
        .checked_add(size_cells)
        .ok_or("dtb: reg cells overflow")?;
    let bytes_per_entry = cells_per_entry
        .checked_mul(4)
        .ok_or("dtb: reg byte length overflow")?;
    let total_len = entries
        .len()
        .checked_mul(bytes_per_entry)
        .ok_or("dtb: reg total length overflow")?;
    let mut bytes = vec![0u8; total_len];
    for (index, &(base, size)) in entries.iter().enumerate() {
        let offset = index
            .checked_mul(bytes_per_entry)
            .ok_or("dtb: reg offset overflow")?;
        write_be_u32s(&mut bytes, offset, addr_cells, base)?;
        write_be_u32s(&mut bytes, offset + addr_cells * 4, size_cells, size)?;
    }
    Ok(bytes)
}

pub fn encode_gic_spi_interrupts_with_mapper<F>(
    entries: &[(u32, u32)],
    mut intid_from_cell: F,
) -> Result<Vec<u8>, &'static str>
where
    F: FnMut(u32) -> Result<u32, &'static str>,
{
    let total_len = entries
        .len()
        .checked_mul(12)
        .ok_or("dtb: interrupt byte length overflow")?;
    let mut bytes = vec![0u8; total_len];
    for (index, &(cell0, flags)) in entries.iter().enumerate() {
        let intid = intid_from_cell(cell0)?;
        if intid < 32 {
            return Err("dtb: GIC SPI intid must be >= 32");
        }
        let offset = index
            .checked_mul(12)
            .ok_or("dtb: interrupt offset overflow")?;
        write_be_u32(&mut bytes, offset, 0)?;
        write_be_u32(&mut bytes, offset + 4, intid - 32)?;
        write_be_u32(&mut bytes, offset + 8, flags)?;
    }
    Ok(bytes)
}

fn write_be_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), &'static str> {
    let end = offset.checked_add(4).ok_or("dtb: write_be_u32 overflow")?;
    let slice = bytes.get_mut(offset..end).ok_or("dtb: write_be_u32 oob")?;
    slice.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn write_be_u32s(
    bytes: &mut [u8],
    offset: usize,
    cells: usize,
    value: u64,
) -> Result<(), &'static str> {
    for index in 0..cells {
        let shift = 32 * (cells - 1 - index);
        let cell = ((value >> shift) & 0xffff_ffff) as u32;
        write_be_u32(bytes, offset + index * 4, cell)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceTreeEditExt;
    use crate::DeviceTreeQueryExt;
    use crate::DtbParser;
    use crate::NodeEditExt;
    use crate::NodeQueryExt;

    fn build_source_tree() -> DeviceTree<'static, Owned> {
        let mut tree = DeviceTree::with_root(NameRef::Borrowed("/"));
        tree.node_mut(tree.root).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"test,root\0".to_vec()),
        );

        let axi = tree.add_child(tree.root, NameRef::Borrowed("axi")).unwrap();
        tree.node_mut(axi).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"simple-bus\0".to_vec()),
        );

        let pcie = tree
            .add_child(axi, NameRef::Borrowed("pcie@1000120000"))
            .unwrap();
        tree.node_mut(pcie).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"brcm,bcm2712-pcie\0".to_vec()),
        );

        let rp1 = tree.add_child(pcie, NameRef::Borrowed("rp1")).unwrap();
        tree.node_mut(rp1).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"raspberrypi,rp1\0".to_vec()),
        );

        let csi = tree
            .add_child(rp1, NameRef::Borrowed("csi@110000"))
            .unwrap();
        tree.node_mut(csi).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"raspberrypi,rp1-cfe\0".to_vec()),
        );
        let endpoint = tree
            .add_child(csi, NameRef::Borrowed("endpoint@0"))
            .unwrap();
        tree.node_mut(endpoint).unwrap().set_property(
            NameRef::Borrowed("remote-endpoint"),
            ValueRef::Owned(1u32.to_be_bytes().to_vec()),
        );

        let other = tree
            .add_child(rp1, NameRef::Borrowed("unused@200000"))
            .unwrap();
        tree.node_mut(other).unwrap().set_property(
            NameRef::Borrowed("status"),
            ValueRef::Owned(b"disabled\0".to_vec()),
        );

        tree
    }

    fn build_projection_source_tree() -> DeviceTree<'static, Owned> {
        let mut tree = DeviceTree::with_root(NameRef::Borrowed("/"));
        tree.node_mut(tree.root).unwrap().set_property(
            NameRef::Borrowed("#address-cells"),
            ValueRef::Owned(2u32.to_be_bytes().to_vec()),
        );
        tree.node_mut(tree.root).unwrap().set_property(
            NameRef::Borrowed("#size-cells"),
            ValueRef::Owned(1u32.to_be_bytes().to_vec()),
        );

        let soc = tree
            .add_child(tree.root, NameRef::Borrowed("soc@107c000000"))
            .unwrap();
        tree.node_mut(soc).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"simple-bus\0".to_vec()),
        );
        tree.node_mut(soc).unwrap().set_property(
            NameRef::Borrowed("#address-cells"),
            ValueRef::Owned(2u32.to_be_bytes().to_vec()),
        );
        tree.node_mut(soc).unwrap().set_property(
            NameRef::Borrowed("#size-cells"),
            ValueRef::Owned(1u32.to_be_bytes().to_vec()),
        );

        let axi = tree.add_child(tree.root, NameRef::Borrowed("axi")).unwrap();
        tree.node_mut(axi).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"simple-bus\0".to_vec()),
        );

        let pcie = tree
            .add_child(axi, NameRef::Borrowed("pcie@1000120000"))
            .unwrap();
        tree.node_mut(pcie).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"brcm,bcm2712-pcie\0".to_vec()),
        );

        let rp1 = tree.add_child(pcie, NameRef::Borrowed("rp1")).unwrap();
        tree.node_mut(rp1).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"raspberrypi,rp1\0".to_vec()),
        );

        let i2c = tree.add_child(rp1, NameRef::Borrowed("i2c@70000")).unwrap();
        tree.node_mut(i2c).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"snps,designware-i2c\0".to_vec()),
        );
        tree.node_mut(i2c).unwrap().set_property(
            NameRef::Borrowed("reg"),
            ValueRef::Owned(
                [
                    0x00u32.to_be_bytes().as_slice(),
                    0x0007_0000u32.to_be_bytes().as_slice(),
                    0x00u32.to_be_bytes().as_slice(),
                    0x1000u32.to_be_bytes().as_slice(),
                ]
                .concat(),
            ),
        );
        tree.node_mut(i2c).unwrap().set_property(
            NameRef::Borrowed("interrupts"),
            ValueRef::Owned(
                [
                    0x07u32.to_be_bytes().as_slice(),
                    0x04u32.to_be_bytes().as_slice(),
                ]
                .concat(),
            ),
        );

        let sensor = tree.add_child(i2c, NameRef::Borrowed("imx219@10")).unwrap();
        tree.node_mut(sensor).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Owned(b"sony,imx219\0".to_vec()),
        );
        tree.node_mut(sensor).unwrap().set_property(
            NameRef::Borrowed("reg"),
            ValueRef::Owned(0x10u32.to_be_bytes().to_vec()),
        );

        tree
    }

    #[test]
    fn copy_subtree_preserves_ancestor_chain_and_descendants() {
        let source = build_source_tree();
        let source_id = source
            .find_node_by_path("/axi/pcie@1000120000/rp1/csi@110000")
            .expect("source csi node");

        let mut target = DeviceTree::with_root(NameRef::Borrowed("/"));
        copy_subtree(&source, &mut target, source_id).expect("copy subtree");

        let copied = target
            .find_node_by_path("/axi/pcie@1000120000/rp1/csi@110000")
            .expect("copied csi node");
        assert_eq!(
            node_path(&target, copied).expect("copied path"),
            "/axi/pcie@1000120000/rp1/csi@110000"
        );
        assert!(target.find_node_by_path("/axi").is_some());
        assert!(target.find_node_by_path("/axi/pcie@1000120000").is_some());
        assert!(
            target
                .find_node_by_path("/axi/pcie@1000120000/rp1/csi@110000/endpoint@0")
                .is_some()
        );
        assert!(
            target
                .find_node_by_path("/axi/pcie@1000120000/rp1/unused@200000")
                .is_none()
        );

        let pcie = target
            .find_node_by_path("/axi/pcie@1000120000")
            .expect("copied pcie node");
        let pcie_node = target.node(pcie).unwrap();
        assert_eq!(
            pcie_node.property("compatible").unwrap().value.as_slice(),
            b"brcm,bcm2712-pcie\0"
        );

        let dtb = target.into_dtb_box().expect("serialize copied tree");
        let parser = DtbParser::init(dtb.as_ptr() as usize).expect("parse serialized tree");
        let reparsed = DeviceTree::from_parser(&parser).expect("reparse copied tree");
        assert!(
            reparsed
                .find_node_by_path("/axi/pcie@1000120000/rp1/csi@110000/endpoint@0")
                .is_some()
        );
    }

    #[test]
    fn copy_node_with_ancestors_keeps_node_but_not_siblings() {
        let source = build_source_tree();
        let source_id = source
            .find_node_by_path("/axi/pcie@1000120000/rp1")
            .expect("source rp1 node");

        let mut target = DeviceTree::with_root(NameRef::Borrowed("/"));
        copy_node_with_ancestors(&source, &mut target, source_id).expect("copy node");

        assert!(
            target
                .find_node_by_path("/axi/pcie@1000120000/rp1")
                .is_some()
        );
        assert!(
            target
                .find_node_by_path("/axi/pcie@1000120000/rp1/csi@110000")
                .is_none()
        );
    }

    #[test]
    fn copy_subtree_to_path_projects_subtree_and_preserves_children() {
        let source = build_projection_source_tree();
        let source_id = source
            .find_node_by_path("/axi/pcie@1000120000/rp1/i2c@70000")
            .expect("source i2c node");

        let mut target = DeviceTree::with_root(NameRef::Borrowed("/"));
        let soc = target
            .get_or_create_node_by_path("/soc@107c000000")
            .expect("create soc");
        target.node_mut(soc).unwrap().set_property(
            NameRef::Borrowed("#address-cells"),
            ValueRef::Owned(2u32.to_be_bytes().to_vec()),
        );
        target.node_mut(soc).unwrap().set_property(
            NameRef::Borrowed("#size-cells"),
            ValueRef::Owned(1u32.to_be_bytes().to_vec()),
        );

        let copied = copy_subtree_to_path(
            &source,
            &mut target,
            source_id,
            "/soc@107c000000/i2c@1c00070000",
        )
        .expect("project subtree");
        target.node_mut(copied).unwrap().set_property(
            NameRef::Borrowed("reg"),
            ValueRef::Owned(
                encode_reg_entries(&[(0x1c00_070000, 0x1000)], 2, 1).expect("encode reg"),
            ),
        );
        target.node_mut(copied).unwrap().set_property(
            NameRef::Borrowed("interrupts"),
            ValueRef::Owned(
                encode_gic_spi_interrupts_with_mapper(&[(7, 4)], |index| Ok(160 + index))
                    .expect("encode interrupts"),
            ),
        );

        assert!(target.find_node_by_path("/axi/pcie@1000120000").is_none());
        assert!(
            target
                .find_node_by_path("/soc@107c000000/i2c@1c00070000/imx219@10")
                .is_some()
        );
        let reg = target
            .node(copied)
            .unwrap()
            .property("reg")
            .unwrap()
            .value
            .as_slice();
        assert_eq!(
            reg,
            [
                0x1cu32.to_be_bytes().as_slice(),
                0x0007_0000u32.to_be_bytes().as_slice(),
                0x1000u32.to_be_bytes().as_slice(),
            ]
            .concat()
        );
        let interrupts = target
            .node(copied)
            .unwrap()
            .property("interrupts")
            .unwrap()
            .value
            .as_slice();
        assert_eq!(
            interrupts,
            [
                0u32.to_be_bytes().as_slice(),
                135u32.to_be_bytes().as_slice(),
                4u32.to_be_bytes().as_slice(),
            ]
            .concat()
        );
    }
}
