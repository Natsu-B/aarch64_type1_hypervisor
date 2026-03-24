extern crate alloc;

use alloc::string::String;
use alloc::string::ToString;
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
}
