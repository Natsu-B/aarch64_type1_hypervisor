extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use allocator::AlignedSliceBox;
use arch_hal::gic::MmioRegion;
use core::convert::TryInto;

use ::dtb::Borrowed;
use ::dtb::DeviceTree;
use ::dtb::DeviceTreeEditExt;
use ::dtb::DeviceTreeQueryExt;
use ::dtb::DtbParser;
use ::dtb::MemReserve;
use ::dtb::NameRef;
use ::dtb::NodeEditExt;
use ::dtb::NodeId;
use ::dtb::NodeQueryExt;
use ::dtb::Owned;
use ::dtb::ValueRef;
use ::dtb::patch::Pl011Spec;
use ::dtb::tree_copy::copy_node_properties;
use ::dtb::tree_copy::copy_node_with_ancestors;
use ::dtb::tree_copy::copy_subtree;
use ::dtb::tree_copy::node_path;

use crate::Gicv2Info;
use crate::PL011_UART_ADDR;
use crate::vgic;

type SourceTree<'dtb> = DeviceTree<'dtb, Borrowed>;
type TargetTree<'dtb> = DeviceTree<'dtb, Owned>;

const CORE_GIC_PATHS: [&str; 2] = [
    "/soc@107c000000/interrupt-controller@7fff9000",
    "/soc/interrupt-controller@7fff9000",
];
const CORE_MAILBOX_PATHS: [&str; 2] = ["/soc@107c000000/mailbox@7c013880", "/soc/mailbox@7c013880"];
const CORE_SDIO1_PATHS: [&str; 2] = ["/soc@107c000000/mmc@fff000", "/soc/mmc@fff000"];
const CORE_PCIE_HOST_PATH: &str = "/axi/pcie@1000120000";
const CORE_RP1_PATH: &str = "/axi/pcie@1000120000/rp1";
const CAMERA_SEED_PATHS: [&str; 18] = [
    "/axi/pcie@1000120000/rp1/i2c@70000",
    "/axi/pcie@1000120000/rp1/i2c@88000",
    "/axi/pcie@1000120000/rp1/csi@110000",
    "/axi/pcie@1000120000/rp1/csi@128000",
    "/axi/pcie@1000120000/rp1/mailbox@8000",
    "/axi/pcie@1000120000/rp1/clocks@18000",
    "/axi/iommu@5280",
    "/axi/iommuc@5b00",
    "/axi/msi-controller@1000130000",
    "/soc@107c000000/reset-controller@119500",
    "/soc@107c000000/reset-controller@1504318",
    "/clocks/clk_xosc",
    "/clocks/clk_emmc2",
    "/clocks/clk_uart",
    "/clocks/clk_vpu",
    "/clocks/sdio_src",
    "/clocks/sdhci_core",
    "/rp1_firmware",
];
const HELPER_SEED_PATHS: [&str; 10] = [
    "/sd_io_1v8_reg",
    "/sd_vcc_reg",
    "/cam0_clk",
    "/cam1_clk",
    "/cam0_reg",
    "/cam1_reg",
    "/cam_dummy_reg",
    "/i2c0if",
    "/i2c0mux",
    "/rp1_firmware",
];
const CPU_KEEP_NAMES: [&str; 3] = ["cpu@0", "cpu@1", "cpu@2"];
const SOURCE_METADATA_NODES: [&str; 4] = [
    "/__symbols__",
    "/__fixups__",
    "/__local_fixups__",
    "/__overrides__",
];

pub(crate) fn build_guest_dtb(
    source: &DtbParser,
    reserved_memory: &[(usize, usize)],
    gic_info: &Gicv2Info,
    uart_irq: vgic::UartIrq,
) -> Result<AlignedSliceBox<u8>, &'static str> {
    let source_tree = DeviceTree::from_parser(source)?;
    let mut target = DeviceTree::with_root(NameRef::Borrowed("/"));
    target.header = source_tree.header.clone();
    let target_root = target.root;
    copy_node_properties(&source_tree, source_tree.root, &mut target, target_root)?;
    target.mem_reserve = source_tree.mem_reserve.clone();

    let chosen_id = copy_chosen(&source_tree, &mut target)?;
    let initrd_range = remove_initrd(&mut target, chosen_id);
    remove_initrd_memreserve(&mut target, initrd_range);

    copy_memory_nodes(&source_tree, &mut target)?;
    copy_cpus(&source_tree, &mut target)?;
    copy_required_subtree(
        &source_tree,
        &mut target,
        &CORE_GIC_PATHS,
        "dtb: missing GIC node",
    )?;
    copy_required_subtree(
        &source_tree,
        &mut target,
        &CORE_MAILBOX_PATHS,
        "dtb: missing mailbox node",
    )?;
    copy_required_subtree(
        &source_tree,
        &mut target,
        &CORE_SDIO1_PATHS,
        "dtb: missing sdio1 node",
    )?;
    copy_required_shallow(
        &source_tree,
        &mut target,
        &[CORE_PCIE_HOST_PATH],
        "dtb: missing PCIe host node",
    )?;
    copy_required_shallow(
        &source_tree,
        &mut target,
        &[CORE_RP1_PATH],
        "dtb: missing RP1 node",
    )?;
    copy_optional_subtree(&source_tree, &mut target, "/psci")?;
    copy_optional_subtree(&source_tree, &mut target, "/timer")?;

    let phandle_map = build_phandle_map(&source_tree)?;
    let mut seed_roots = collect_existing_paths(&source_tree, &CAMERA_SEED_PATHS);
    seed_roots.extend(collect_existing_paths(&source_tree, &HELPER_SEED_PATHS));
    let mut allow_all = |_| Ok(true);
    let (camera_keep_nodes, camera_copy_roots) =
        collect_subtree_phandle_closure(&source_tree, &seed_roots, &phandle_map, &mut allow_all)?;

    let pcie_host_id = source_tree.find_node_by_path(CORE_PCIE_HOST_PATH);
    let rp1_id = source_tree.find_node_by_path(CORE_RP1_PATH);
    for root_id in camera_copy_roots {
        if is_source_metadata_node(&source_tree, root_id)? {
            continue;
        }
        if is_reserved_memory_child(&source_tree, root_id)? {
            continue;
        }
        if Some(root_id) == pcie_host_id || Some(root_id) == rp1_id {
            copy_node_with_ancestors(&source_tree, &mut target, root_id)?;
            continue;
        }
        copy_subtree(&source_tree, &mut target, root_id)?;
    }

    copy_reserved_memory(&source_tree, &mut target, &camera_keep_nodes)?;

    ::dtb::patch::inject_standalone_pl011(
        &mut target,
        Pl011Spec {
            base: PL011_UART_ADDR.0 as u64,
            size: 0x1000,
            uartclk_hz: PL011_UART_ADDR.1 as u32,
            pintid: uart_irq.pintid,
            irq_sense: uart_irq.sense,
        },
    )?;

    copy_filtered_aliases(&source_tree, &mut target)?;
    copy_symbols(&source_tree, &mut target)?;
    copy_fixups(&source_tree, &mut target)?;
    copy_local_fixups(&source_tree, &mut target)?;
    copy_overrides(&source_tree, &mut target, &phandle_map)?;

    configure_uart_console(&mut target, chosen_id, PL011_UART_ADDR.0)?;
    let gicv = gic_info
        .gicv
        .ok_or("gic: missing GICV region for DT update")?;
    update_gicv2_cpu_interface_reg(&mut target, gicv)?;
    append_reserved_memory(&mut target, reserved_memory);

    target.into_dtb_box()
}

fn copy_chosen(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
) -> Result<NodeId, &'static str> {
    let target_id = target.get_or_create_node_by_path("/chosen")?;
    if let Some(source_id) = source.find_node_by_path("/chosen") {
        copy_node_properties(source, source_id, target, target_id)?;
    }
    Ok(target_id)
}

fn copy_memory_nodes(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
) -> Result<(), &'static str> {
    let root_children = source
        .node(source.root)
        .ok_or("dtb: missing source root")?
        .children
        .clone();
    let mut copied_any = false;
    for child_id in root_children {
        if is_memory_node(source, child_id)? {
            copy_subtree(source, target, child_id)?;
            copied_any = true;
        }
    }
    if copied_any {
        Ok(())
    } else {
        Err("dtb: missing memory node")
    }
}

fn copy_cpus(source: &SourceTree<'_>, target: &mut TargetTree<'_>) -> Result<(), &'static str> {
    let cpus_id = source
        .find_node_by_path("/cpus")
        .ok_or("dtb: missing /cpus node")?;
    copy_node_with_ancestors(source, target, cpus_id)?;

    let phandle_map = build_phandle_map(source)?;
    let cpus_node = source.node(cpus_id).ok_or("dtb: invalid /cpus node")?;
    let mut seed_roots = Vec::new();
    for cpu_name in CPU_KEEP_NAMES {
        let cpu_id = cpus_node
            .children
            .iter()
            .copied()
            .find(|&child_id| {
                source
                    .node(child_id)
                    .map(|child| child.name.as_str() == cpu_name)
                    .unwrap_or(false)
            })
            .ok_or("dtb: missing required CPU node")?;
        seed_roots.push(cpu_id);
    }

    let mut allow_cpu_ref = |node_id| {
        Ok(is_same_or_descendant_of(source, node_id, cpus_id)?
            && node_path(source, node_id)? != "/cpus/cpu@3")
    };
    let (keep_nodes, copy_roots) =
        collect_subtree_phandle_closure(source, &seed_roots, &phandle_map, &mut allow_cpu_ref)?;

    for root_id in copy_roots {
        if keep_nodes.contains(&root_id) {
            copy_subtree(source, target, root_id)?;
        }
    }
    Ok(())
}

fn copy_reserved_memory(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
    keep_nodes: &BTreeSet<NodeId>,
) -> Result<(), &'static str> {
    let Some(reserved_id) = source.find_node_by_path("/reserved-memory") else {
        return Ok(());
    };
    let children = source
        .node(reserved_id)
        .ok_or("dtb: invalid reserved-memory node")?
        .children
        .clone();
    for child_id in children {
        if is_linux_cma_node(source, child_id)? || keep_nodes.contains(&child_id) {
            copy_subtree(source, target, child_id)?;
        }
    }
    Ok(())
}

fn copy_filtered_aliases(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
) -> Result<(), &'static str> {
    let Some(source_id) = source.find_node_by_path("/aliases") else {
        return Ok(());
    };
    let source_node = source.node(source_id).ok_or("dtb: invalid aliases node")?;
    let mut kept = Vec::new();

    for prop in &source_node.properties {
        let name = prop.name.as_str();
        if matches!(name, "serial0" | "uart0") {
            continue;
        }
        let Some(path) = first_cstr(prop.value.as_slice()) else {
            continue;
        };
        if target.find_node_by_path(path).is_none() {
            continue;
        }
        kept.push((name.to_string(), prop.value.as_slice().to_vec()));
    }
    if kept.is_empty() {
        return Ok(());
    }
    let target_id = target.get_or_create_node_by_path("/aliases")?;
    let target_node = target
        .node_mut(target_id)
        .ok_or("dtb: invalid aliases target node")?;
    for (name, value) in kept {
        target_node.set_property(NameRef::Owned(name), ValueRef::Owned(value));
    }
    Ok(())
}

fn copy_symbols(source: &SourceTree<'_>, target: &mut TargetTree<'_>) -> Result<(), &'static str> {
    let Some(source_id) = source.find_node_by_path("/__symbols__") else {
        return Ok(());
    };
    let source_node = source
        .node(source_id)
        .ok_or("dtb: invalid __symbols__ node")?;
    let mut kept = Vec::new();
    for prop in &source_node.properties {
        let Some(path) = first_cstr(prop.value.as_slice()) else {
            continue;
        };
        if target.find_node_by_path(path).is_some() {
            kept.push((
                prop.name.as_str().to_string(),
                prop.value.as_slice().to_vec(),
            ));
        }
    }
    if kept.is_empty() {
        return Ok(());
    }
    let target_id = target.get_or_create_node_by_path("/__symbols__")?;
    let target_node = target
        .node_mut(target_id)
        .ok_or("dtb: invalid __symbols__ target node")?;
    for (name, value) in kept {
        target_node.set_property(NameRef::Owned(name), ValueRef::Owned(value));
    }
    Ok(())
}

fn copy_fixups(source: &SourceTree<'_>, target: &mut TargetTree<'_>) -> Result<(), &'static str> {
    let Some(source_id) = source.find_node_by_path("/__fixups__") else {
        return Ok(());
    };
    let source_node = source
        .node(source_id)
        .ok_or("dtb: invalid __fixups__ node")?;
    let mut kept = Vec::new();
    for prop in &source_node.properties {
        let value = filter_fixup_entries(prop.value.as_slice(), target)?;
        if !value.is_empty() {
            kept.push((prop.name.as_str().to_string(), value));
        }
    }
    if kept.is_empty() {
        return Ok(());
    }
    let target_id = target.get_or_create_node_by_path("/__fixups__")?;
    let target_node = target
        .node_mut(target_id)
        .ok_or("dtb: invalid __fixups__ target node")?;
    for (name, value) in kept {
        target_node.set_property(NameRef::Owned(name), ValueRef::Owned(value));
    }
    Ok(())
}

fn copy_local_fixups(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
) -> Result<(), &'static str> {
    let Some(source_id) = source.find_node_by_path("/__local_fixups__") else {
        return Ok(());
    };
    copy_local_fixups_node(source, target, source_id, String::new())?;
    Ok(())
}

fn copy_local_fixups_node(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
    source_id: NodeId,
    relative_path: String,
) -> Result<bool, &'static str> {
    let source_node = source
        .node(source_id)
        .ok_or("dtb: invalid __local_fixups__ node")?;
    let children = source_node.children.clone();
    let mut kept_child = false;
    for child_id in children {
        let child_name = source
            .node(child_id)
            .ok_or("dtb: invalid __local_fixups__ child")?
            .name
            .as_str()
            .to_string();
        let child_rel = if relative_path.is_empty() {
            child_name
        } else {
            format!("{relative_path}/{child_name}")
        };
        if copy_local_fixups_node(source, target, child_id, child_rel)? {
            kept_child = true;
        }
    }

    let mirrored_exists = if relative_path.is_empty() {
        true
    } else {
        let mirrored_path = format!("/{relative_path}");
        target.find_node_by_path(&mirrored_path).is_some()
    };
    if !mirrored_exists && !kept_child {
        return Ok(false);
    }

    let target_path = if relative_path.is_empty() {
        "/__local_fixups__".to_string()
    } else {
        format!("/__local_fixups__/{relative_path}")
    };
    let target_id = target.get_or_create_node_by_path(&target_path)?;
    if mirrored_exists {
        copy_node_properties(source, source_id, target, target_id)?;
    }
    Ok(true)
}

fn copy_overrides(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
    phandle_map: &BTreeMap<u32, NodeId>,
) -> Result<(), &'static str> {
    let Some(source_id) = source.find_node_by_path("/__overrides__") else {
        return Ok(());
    };
    let source_node = source
        .node(source_id)
        .ok_or("dtb: invalid __overrides__ node")?;
    let mut kept = Vec::new();
    for prop in &source_node.properties {
        let keep =
            property_references_target_node(source, target, prop.value.as_slice(), phandle_map)?
                || is_camera_override_name(prop.name.as_str());
        if keep {
            kept.push((
                prop.name.as_str().to_string(),
                prop.value.as_slice().to_vec(),
            ));
        }
    }
    if kept.is_empty() {
        return Ok(());
    }
    let target_id = target.get_or_create_node_by_path("/__overrides__")?;
    let target_node = target
        .node_mut(target_id)
        .ok_or("dtb: invalid __overrides__ target node")?;
    for (name, value) in kept {
        target_node.set_property(NameRef::Owned(name), ValueRef::Owned(value));
    }
    Ok(())
}

fn copy_required_subtree(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
    paths: &[&str],
    err: &'static str,
) -> Result<(), &'static str> {
    let source_id = find_node_by_any_path(source, paths).ok_or(err)?;
    copy_subtree(source, target, source_id)?;
    Ok(())
}

fn copy_required_shallow(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
    paths: &[&str],
    err: &'static str,
) -> Result<(), &'static str> {
    let source_id = find_node_by_any_path(source, paths).ok_or(err)?;
    copy_node_with_ancestors(source, target, source_id)?;
    Ok(())
}

fn copy_optional_subtree(
    source: &SourceTree<'_>,
    target: &mut TargetTree<'_>,
    path: &str,
) -> Result<(), &'static str> {
    if let Some(source_id) = source.find_node_by_path(path) {
        copy_subtree(source, target, source_id)?;
    }
    Ok(())
}

fn collect_existing_paths(source: &SourceTree<'_>, paths: &[&str]) -> Vec<NodeId> {
    paths
        .iter()
        .filter_map(|path| source.find_node_by_path(path))
        .collect()
}

fn build_phandle_map(source: &SourceTree<'_>) -> Result<BTreeMap<u32, NodeId>, &'static str> {
    let mut map = BTreeMap::new();
    for node_id in 0..source.nodes.len() {
        let Some(node) = source.node(node_id) else {
            continue;
        };
        for key in ["phandle", "linux,phandle"] {
            let Some(prop) = node.property(key) else {
                continue;
            };
            if prop.value.as_slice().len() != 4 {
                continue;
            }
            let phandle = read_be_u32(prop.value.as_slice(), 0)?;
            map.entry(phandle).or_insert(node_id);
        }
    }
    Ok(map)
}

fn collect_subtree_phandle_closure(
    source: &SourceTree<'_>,
    seed_roots: &[NodeId],
    phandle_map: &BTreeMap<u32, NodeId>,
    allow_ref: &mut impl FnMut(NodeId) -> Result<bool, &'static str>,
) -> Result<(BTreeSet<NodeId>, BTreeSet<NodeId>), &'static str> {
    let mut keep_nodes = BTreeSet::new();
    let mut processed_roots = BTreeSet::new();
    let mut pending = seed_roots.to_vec();
    while let Some(root_id) = pending.pop() {
        if !processed_roots.insert(root_id) {
            continue;
        }
        walk_seed_subtree(
            source,
            root_id,
            phandle_map,
            allow_ref,
            &mut keep_nodes,
            &mut pending,
        )?;
    }
    Ok((keep_nodes, processed_roots))
}

fn walk_seed_subtree(
    source: &SourceTree<'_>,
    node_id: NodeId,
    phandle_map: &BTreeMap<u32, NodeId>,
    allow_ref: &mut impl FnMut(NodeId) -> Result<bool, &'static str>,
    keep_nodes: &mut BTreeSet<NodeId>,
    pending: &mut Vec<NodeId>,
) -> Result<(), &'static str> {
    let node = source.node(node_id).ok_or("dtb: invalid source node id")?;
    keep_nodes.insert(node_id);

    for prop in &node.properties {
        try_for_each_tree_property_phandle_candidate(
            prop.name.as_str(),
            prop.value.as_slice(),
            &mut |candidate| {
                let Some(&target_id) = phandle_map.get(&candidate) else {
                    return Ok(());
                };
                if allow_ref(target_id)? {
                    pending.push(target_id);
                }
                Ok(())
            },
        )?;
    }

    let children = node.children.clone();
    for child_id in children {
        walk_seed_subtree(
            source,
            child_id,
            phandle_map,
            allow_ref,
            keep_nodes,
            pending,
        )?;
    }
    Ok(())
}

fn try_for_each_tree_property_phandle_candidate(
    name: &str,
    bytes: &[u8],
    f: &mut impl FnMut(u32) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    if name.starts_with('#') || matches!(name, "phandle" | "linux,phandle") {
        return Ok(());
    }
    if bytes.len() < 4 {
        return Ok(());
    }
    if property_looks_like_string_list(bytes) {
        return Ok(());
    }
    if bytes.len() == 4 && !property_can_hold_scalar_phandle(name) {
        return Ok(());
    }
    for chunk in bytes.chunks_exact(4) {
        f(u32::from_be_bytes(
            chunk.try_into().map_err(|_| "dtb: invalid u32 cell")?,
        ))?;
    }
    Ok(())
}

fn property_looks_like_string_list(bytes: &[u8]) -> bool {
    if !bytes.contains(&0) {
        return false;
    }
    bytes.split(|byte| *byte == 0).all(|segment| {
        segment.is_empty() || segment.iter().all(|byte| matches!(*byte, b' '..=b'~'))
    })
}

fn property_can_hold_scalar_phandle(name: &str) -> bool {
    matches!(
        name,
        "interrupt-parent"
            | "msi-parent"
            | "memory-region"
            | "operating-points-v2"
            | "backlight"
            | "remote-endpoint"
            | "sound-dai"
            | "firmware"
            | "cooling-device"
    ) || name.starts_with("pinctrl-")
        || name.ends_with("-parent")
        || name.ends_with("-supply")
        || name.ends_with("-endpoint")
}

fn property_references_target_node(
    source: &SourceTree<'_>,
    target: &TargetTree<'_>,
    bytes: &[u8],
    phandle_map: &BTreeMap<u32, NodeId>,
) -> Result<bool, &'static str> {
    for chunk in bytes.chunks_exact(4) {
        let candidate = u32::from_be_bytes(chunk.try_into().map_err(|_| "dtb: invalid u32 cell")?);
        let Some(&node_id) = phandle_map.get(&candidate) else {
            continue;
        };
        let path = node_path(source, node_id)?;
        if target.find_node_by_path(&path).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn filter_fixup_entries(bytes: &[u8], target: &TargetTree<'_>) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    for entry in split_nul_terminated(bytes) {
        let text = core::str::from_utf8(entry).map_err(|_| "dtb: invalid __fixups__ entry")?;
        let Some((path, _)) = text.split_once(':') else {
            continue;
        };
        if target.find_node_by_path(path).is_none() {
            continue;
        }
        out.extend_from_slice(entry);
        out.push(0);
    }
    Ok(out)
}

fn split_nul_terminated(bytes: &[u8]) -> Vec<&[u8]> {
    let mut entries = Vec::new();
    let mut start = 0usize;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == 0)
            .map(|offset| start + offset)
            .unwrap_or(bytes.len());
        if end > start {
            entries.push(&bytes[start..end]);
        }
        if end == bytes.len() {
            break;
        }
        start = end + 1;
    }
    entries
}

fn first_cstr(bytes: &[u8]) -> Option<&str> {
    let raw = bytes.split(|byte| *byte == 0).next()?;
    if raw.is_empty() {
        return None;
    }
    core::str::from_utf8(raw).ok()
}

fn is_camera_override_name(name: &str) -> bool {
    name.starts_with("cam0_") || name.starts_with("cam1_") || name.starts_with("i2c_csi_dsi")
}

fn is_memory_node(source: &SourceTree<'_>, node_id: NodeId) -> Result<bool, &'static str> {
    let node = source.node(node_id).ok_or("dtb: invalid memory node")?;
    if node.name.as_str().starts_with("memory@") {
        return Ok(true);
    }
    Ok(property_string_equals(node, "device_type", "memory"))
}

fn is_linux_cma_node(source: &SourceTree<'_>, node_id: NodeId) -> Result<bool, &'static str> {
    let node = source
        .node(node_id)
        .ok_or("dtb: invalid reserved-memory child")?;
    if node.name.as_str().starts_with("linux,cma") {
        return Ok(true);
    }
    if node.property("linux,cma-default").is_some() {
        return Ok(true);
    }
    Ok(false)
}

fn property_string_equals(node: &::dtb::ast::Node<'_>, key: &str, expected: &str) -> bool {
    let Some(prop) = node.property(key) else {
        return false;
    };
    first_cstr(prop.value.as_slice()).is_some_and(|text| text == expected)
}

fn is_same_or_descendant_of(
    source: &SourceTree<'_>,
    node_id: NodeId,
    ancestor_id: NodeId,
) -> Result<bool, &'static str> {
    let mut current = Some(node_id);
    while let Some(id) = current {
        if id == ancestor_id {
            return Ok(true);
        }
        current = source.node(id).ok_or("dtb: invalid source node id")?.parent;
    }
    Ok(false)
}

fn is_reserved_memory_child(
    source: &SourceTree<'_>,
    node_id: NodeId,
) -> Result<bool, &'static str> {
    let Some(reserved_id) = source.find_node_by_path("/reserved-memory") else {
        return Ok(false);
    };
    Ok(node_id != reserved_id && is_same_or_descendant_of(source, node_id, reserved_id)?)
}

fn is_source_metadata_node(source: &SourceTree<'_>, node_id: NodeId) -> Result<bool, &'static str> {
    let path = node_path(source, node_id)?;
    Ok(SOURCE_METADATA_NODES
        .iter()
        .any(|candidate| path == *candidate || path.starts_with(&format!("{candidate}/"))))
}

fn find_node_by_any_path(source: &SourceTree<'_>, paths: &[&str]) -> Option<NodeId> {
    paths.iter().find_map(|path| source.find_node_by_path(path))
}

fn be_bytes_to_u64(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u32::from_be_bytes(bytes.try_into().ok()?) as u64),
        8 => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn remove_initrd(tree: &mut DeviceTree<'_>, chosen: NodeId) -> Option<(u64, u64)> {
    let start = tree
        .node(chosen)
        .and_then(|node| node.property("linux,initrd-start"))
        .and_then(|p| be_bytes_to_u64(p.value.as_slice()));
    let end = tree
        .node(chosen)
        .and_then(|node| node.property("linux,initrd-end"))
        .and_then(|p| be_bytes_to_u64(p.value.as_slice()));

    if let Some(node) = tree.node_mut(chosen) {
        node.remove_property("linux,initrd-start");
        node.remove_property("linux,initrd-end");
    }

    if let (Some(start), Some(end)) = (start, end)
        && end > start
    {
        return Some((start, end - start));
    }
    None
}

fn remove_initrd_memreserve(tree: &mut DeviceTree<'_>, initrd: Option<(u64, u64)>) {
    if let Some((addr, size)) = initrd {
        tree.mem_reserve
            .retain(|entry| !(entry.address == addr && entry.size == size));
    }
}

fn append_reserved_memory(tree: &mut DeviceTree<'_>, reserved_memory: &[(usize, usize)]) {
    for &(addr, size) in reserved_memory {
        if size == 0 {
            continue;
        }
        let entry = MemReserve {
            address: addr as u64,
            size: size as u64,
        };
        if tree
            .mem_reserve
            .iter()
            .any(|existing| existing.address == entry.address && existing.size == entry.size)
        {
            continue;
        }
        tree.mem_reserve.push(entry);
    }
}

fn configure_uart_console(
    tree: &mut DeviceTree<'_>,
    chosen: NodeId,
    pl011_uart_addr: usize,
) -> Result<(), &'static str> {
    let alias = pick_uart_alias(tree);
    let stdout_value = format!("{alias}:115200\0").into_bytes();
    let node = tree.node_mut(chosen).ok_or("chosen node missing")?;
    node.set_property(
        NameRef::Borrowed("stdout-path"),
        ValueRef::Owned(stdout_value.clone()),
    );
    node.set_property(
        NameRef::Borrowed("linux,stdout-path"),
        ValueRef::Owned(stdout_value),
    );

    update_bootargs(tree, chosen, pl011_uart_addr)
}

fn pick_uart_alias(tree: &DeviceTree<'_>) -> &'static str {
    if let Some(alias_id) = tree.find_node_by_path("/aliases")
        && let Some(node) = tree.node(alias_id)
    {
        if node.property("uart0").is_some() {
            return "uart0";
        }
        if node.property("serial0").is_some() {
            return "serial0";
        }
    }
    "uart0"
}

fn update_bootargs(
    tree: &mut DeviceTree<'_>,
    chosen: NodeId,
    pl011_uart_addr: usize,
) -> Result<(), &'static str> {
    let mut args = String::new();

    if let Some(existing) = tree
        .node(chosen)
        .and_then(|node| node.property("bootargs"))
        .map(|prop| prop.value.as_slice())
        && let Some(raw) = existing.split(|byte| *byte == 0).next()
        && let Ok(text) = core::str::from_utf8(raw)
    {
        for token in text.split_whitespace() {
            if token.starts_with("console=") || token.starts_with("earlycon=") {
                continue;
            }
            if !args.is_empty() {
                args.push(' ');
            }
            args.push_str(token);
        }
    }

    let earlycon = format!("earlycon=pl011,0x{pl011_uart_addr:x}");
    let console = "console=ttyAMA0,115200";
    for token in [earlycon.as_str(), console] {
        if !args.is_empty() {
            args.push(' ');
        }
        args.push_str(token);
    }

    let mut bytes = args.into_bytes();
    if !bytes.ends_with(&[0]) {
        bytes.push(0);
    }

    tree.node_mut(chosen)
        .ok_or("chosen node missing")?
        .set_property(NameRef::Borrowed("bootargs"), ValueRef::Owned(bytes));
    Ok(())
}

fn update_gicv2_cpu_interface_reg(
    tree: &mut DeviceTree<'_>,
    gicv: MmioRegion,
) -> Result<(), &'static str> {
    const COMPATS: [&str; 2] = ["arm,gic-400", "arm,cortex-a15-gic"];
    let mut gic_node = None;
    for node_id in 0..tree.nodes.len() {
        for compat in COMPATS {
            if node_compatible_contains(tree, node_id, compat)? {
                gic_node = Some(node_id);
                break;
            }
        }
        if gic_node.is_some() {
            break;
        }
    }
    let Some(node_id) = gic_node else {
        return Ok(());
    };

    let parent = tree
        .node(node_id)
        .and_then(|node| node.parent)
        .unwrap_or(tree.root);
    let addr_cells = property_u32(tree, parent, "#address-cells")?.unwrap_or(2) as usize;
    let size_cells = property_u32(tree, parent, "#size-cells")?.unwrap_or(1) as usize;
    let stride = (addr_cells + size_cells) * 4;
    let Some(node) = tree.node(node_id) else {
        return Ok(());
    };
    let Some(reg) = node.property("reg") else {
        return Ok(());
    };
    let mut bytes = reg.value.as_slice().to_vec();
    if bytes.len() < stride * 2 {
        return Err("gic: reg property too short");
    }
    let base_offset = stride;
    write_be_u32s(&mut bytes, base_offset, addr_cells, gicv.base as u64)?;
    write_be_u32s(
        &mut bytes,
        base_offset + addr_cells * 4,
        size_cells,
        gicv.size as u64,
    )?;

    if let Some(node) = tree.node_mut(node_id) {
        node.set_property(NameRef::Borrowed("reg"), ValueRef::Owned(bytes));
    }
    Ok(())
}

fn node_compatible_contains(
    tree: &DeviceTree<'_>,
    node_id: NodeId,
    needle: &str,
) -> Result<bool, &'static str> {
    let Some(node) = tree.node(node_id) else {
        return Ok(false);
    };
    let Some(prop) = node.property("compatible") else {
        return Ok(false);
    };
    let bytes = prop.value.as_slice();
    let mut start = 0usize;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|&byte| byte == 0)
            .map(|offset| start + offset)
            .unwrap_or(bytes.len());
        if let Ok(entry) = core::str::from_utf8(&bytes[start..end])
            && entry == needle
        {
            return Ok(true);
        }
        start = end + 1;
    }
    Ok(false)
}

fn property_u32(
    tree: &DeviceTree<'_>,
    node_id: NodeId,
    key: &str,
) -> Result<Option<u32>, &'static str> {
    let Some(node) = tree.node(node_id) else {
        return Ok(None);
    };
    let Some(prop) = node.property(key) else {
        return Ok(None);
    };
    let bytes = prop.value.as_slice();
    if bytes.len() != 4 {
        return Ok(None);
    }
    Ok(Some(read_be_u32(bytes, 0)?))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset.checked_add(4).ok_or("dtb: read_be_u32 overflow")?;
    let slice = bytes.get(offset..end).ok_or("dtb: read_be_u32 oob")?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
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
