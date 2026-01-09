#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use allocator::AlignedSliceBox;
use core::convert::TryFrom;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::mem::align_of;
use core::mem::size_of;
use typestate::Be;

use crate::dtb_parser::DtbParser;
use crate::dtb_parser::Validated;
use crate::dtb_parser::big_endian::Dtb;
use crate::dtb_parser::big_endian::FdtProperty;
use crate::dtb_parser::big_endian::FdtReserveEntry;

const FDT_MAGIC: u32 = 0xd00dfeed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

#[inline]
fn align4(x: usize) -> usize {
    (x + 3) & !3
}

fn read_be_u32(buf: &[u8], offset: usize) -> Result<u32, &'static str> {
    let end = offset
        .checked_add(4)
        .ok_or("dtb: overflow in read_be_u32")?;
    let bytes = buf
        .get(offset..end)
        .ok_or("dtb: out of bounds in read_be_u32")?;
    let be = unsafe { &*(bytes.as_ptr() as *const Be<u32>) };
    Ok(be.read())
}

fn read_cstr<'dtb>(buf: &'dtb [u8], offset: usize) -> Result<&'dtb str, &'static str> {
    let slice = buf
        .get(offset..)
        .ok_or("dtb: out of bounds in read_cstr start")?;
    let len = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or("dtb: missing NUL terminator in read_cstr")?;
    let bytes = &slice[..len];
    core::str::from_utf8(bytes).map_err(|_| "dtb: invalid UTF-8 in string")
}

fn write_be_u32(buf: &mut [u8], offset: usize, v: u32) -> Result<(), &'static str> {
    let end = offset
        .checked_add(4)
        .ok_or("dtb: overflow in write_be_u32")?;
    let slice = buf
        .get_mut(offset..end)
        .ok_or("dtb: out of bounds in write_be_u32")?;
    slice.copy_from_slice(&v.to_be_bytes());
    Ok(())
}

fn write_be_u64(buf: &mut [u8], offset: usize, v: u64) -> Result<(), &'static str> {
    let end = offset
        .checked_add(8)
        .ok_or("dtb: overflow in write_be_u64")?;
    let slice = buf
        .get_mut(offset..end)
        .ok_or("dtb: out of bounds in write_be_u64")?;
    slice.copy_from_slice(&v.to_be_bytes());
    Ok(())
}

/// Dense identifier used to index into the `nodes` array of a `DeviceTree`.
pub type NodeId = usize;

/// Marker for DTB AST that borrows names/values from an external buffer.
#[derive(Clone, Copy, Debug)]
pub struct Borrowed;

/// Marker for DTB AST that owns its names/values.
#[derive(Clone, Copy, Debug)]
pub struct Owned;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub magic: u32,
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemReserve {
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameRef<'dtb> {
    Borrowed(&'dtb str),
    Owned(String),
}

impl<'dtb> NameRef<'dtb> {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Borrowed(s) => s,
            Self::Owned(s) => s.as_str(),
        }
    }
}

impl<'dtb> From<&'dtb str> for NameRef<'dtb> {
    fn from(value: &'dtb str) -> Self {
        Self::Borrowed(value)
    }
}

impl From<String> for NameRef<'_> {
    fn from(value: String) -> Self {
        Self::Owned(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueRef<'dtb> {
    Borrowed(&'dtb [u8]),
    Owned(Vec<u8>),
}

impl<'dtb> ValueRef<'dtb> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(v) => v,
            Self::Owned(v) => v.as_slice(),
        }
    }
}

impl<'dtb> From<&'dtb [u8]> for ValueRef<'dtb> {
    fn from(value: &'dtb [u8]) -> Self {
        Self::Borrowed(value)
    }
}

impl From<Vec<u8>> for ValueRef<'_> {
    fn from(value: Vec<u8>) -> Self {
        Self::Owned(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Property<'dtb> {
    pub name: NameRef<'dtb>,
    pub value: ValueRef<'dtb>,
}

impl<'dtb> Property<'dtb> {
    pub fn new(name: NameRef<'dtb>, value: ValueRef<'dtb>) -> Self {
        Self { name, value }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node<'dtb> {
    pub name: NameRef<'dtb>,
    pub properties: Vec<Property<'dtb>>,
    pub children: Vec<NodeId>,
    pub parent: Option<NodeId>,
}

impl<'dtb> Node<'dtb> {
    pub fn new(name: NameRef<'dtb>) -> Self {
        Self {
            name,
            properties: Vec::new(),
            children: Vec::new(),
            parent: None,
        }
    }
}

/// Device tree AST with a typestate marker for storage/ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceTree<'dtb, State = Owned> {
    pub header: Header,
    pub mem_reserve: Vec<MemReserve>,
    pub nodes: Vec<Node<'dtb>>,
    pub root: NodeId,
    _state: PhantomData<State>,
}

pub type DeviceTreeBorrowed<'dtb> = DeviceTree<'dtb, Borrowed>;
pub type DeviceTreeOwned<'dtb> = DeviceTree<'dtb, Owned>;

impl<'dtb> DeviceTree<'dtb, Owned> {
    pub fn with_root(root_name: NameRef<'dtb>) -> Self {
        let root = Node::new(root_name);
        Self {
            header: Header::default(),
            mem_reserve: Vec::new(),
            root: 0,
            nodes: vec![root],
            _state: PhantomData,
        }
    }
}

impl<'dtb> DeviceTree<'dtb, Borrowed> {
    /// Parse a flattened device tree (DTB/FDT) blob into an AST.
    ///
    /// All names and property values are borrowed from `dtb`
    /// using `NameRef::Borrowed` / `ValueRef::Borrowed`.
    pub fn from_dtb(dtb: &'dtb [u8]) -> Result<Self, &'static str> {
        const HEADER_SIZE: usize = size_of::<u32>() * 10;
        if dtb.is_empty() {
            return Err("dtb: empty buffer");
        }
        if dtb.len() < HEADER_SIZE {
            return Err("dtb: too small for header");
        }

        let base = dtb.as_ptr() as usize;
        let dtb_header = Dtb::new(base)?;
        Self::parse_with_header(dtb, &dtb_header)
    }

    /// Build AST using an existing low-level parser.
    ///
    /// Reuses the underlying DTB buffer referenced by `parser`.
    pub fn from_parser(parser: &'dtb DtbParser<Validated>) -> Result<Self, &'static str> {
        let header = parser.dtb_header();
        let totalsize = header.get_total_size() as usize;
        if totalsize == 0 {
            return Err("dtb: totalsize is zero");
        }
        let base = header.get_fdt_address() as *const u8;
        // Safety: caller guarantees the original DTB memory is valid for the parser's lifetime.
        let dtb = unsafe { core::slice::from_raw_parts(base, totalsize) };
        Self::parse_with_header(dtb, header)
    }

    fn parse_with_header(
        dtb: &'dtb [u8],
        dtb_header: &Dtb<Validated>,
    ) -> Result<Self, &'static str> {
        let base = dtb.as_ptr() as usize;
        if base != dtb_header.get_fdt_address() {
            return Err("dtb: parser/base mismatch");
        }
        let totalsize = dtb_header.get_total_size() as usize;
        if totalsize > dtb.len() {
            return Err("dtb: totalsize larger than buffer");
        }

        let off_dt_struct = dtb_header
            .get_struct_start_address()
            .checked_sub(base)
            .ok_or("dtb: struct before base")? as u32;
        let size_dt_struct = dtb_header.get_struct_size();
        let off_dt_strings = dtb_header
            .get_string_start_address()
            .checked_sub(base)
            .ok_or("dtb: strings before base")? as u32;
        let size_dt_strings = dtb_header.get_string_size();
        let off_mem_rsvmap = dtb_header
            .get_memory_reservation_start_address()
            .checked_sub(base)
            .ok_or("dtb: memreserve before base")? as u32;
        let size_dt_struct_u32 =
            u32::try_from(size_dt_struct).map_err(|_| "dtb: struct size overflow")?;
        let size_dt_strings_u32 =
            u32::try_from(size_dt_strings).map_err(|_| "dtb: strings size overflow")?;

        let header = Header {
            magic: FDT_MAGIC,
            totalsize: dtb_header.get_total_size(),
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version: dtb_header.get_version(),
            last_comp_version: dtb_header.get_last_comp_version(),
            boot_cpuid_phys: dtb_header.get_boot_cpuid_phys(),
            size_dt_strings: size_dt_strings_u32,
            size_dt_struct: size_dt_struct_u32,
        };

        let totalsize_usize = totalsize;
        let struct_off = off_dt_struct as usize;
        let struct_end = struct_off
            .checked_add(size_dt_struct)
            .ok_or("dtb: header offsets out of bounds")?;
        let strings_off = off_dt_strings as usize;
        let strings_end = strings_off
            .checked_add(size_dt_strings)
            .ok_or("dtb: header offsets out of bounds")?;
        if struct_end > totalsize_usize
            || strings_end > totalsize_usize
            || off_mem_rsvmap as usize > totalsize_usize
        {
            return Err("dtb: header offsets out of bounds");
        }

        let mut mem_reserve = Vec::new();
        let mut reserve_ptr = dtb_header.get_memory_reservation_start_address();
        loop {
            let offset_in_blob = reserve_ptr
                .checked_sub(base)
                .ok_or("dtb: memreserve before base")?;
            let entry_end = offset_in_blob
                .checked_add(size_of::<FdtReserveEntry>())
                .ok_or("dtb: memreserve out of bounds")?;
            if entry_end > totalsize_usize {
                return Err("dtb: memreserve out of bounds");
            }

            let address = FdtReserveEntry::get_address(reserve_ptr);
            let size = FdtReserveEntry::get_size(reserve_ptr);
            if address == 0 && size == 0 {
                break;
            }
            mem_reserve.push(MemReserve { address, size });
            reserve_ptr = reserve_ptr
                .checked_add(size_of::<FdtReserveEntry>())
                .ok_or("dtb: memreserve overflow")?;
        }

        if struct_end > dtb.len() || strings_end > dtb.len() {
            return Err("dtb: struct/strings out of bounds");
        }

        let struct_slice = &dtb[struct_off..struct_end];
        let strings_slice = &dtb[strings_off..strings_end];

        let mut nodes: Vec<Node<'dtb>> = Vec::new();
        let mut stack: Vec<NodeId> = Vec::new();
        let mut root: Option<NodeId> = None;
        let mut cursor: usize = 0;

        while cursor + 4 <= struct_slice.len() {
            let token = read_be_u32(struct_slice, cursor)?;
            cursor += 4;

            match token {
                FDT_NOP => {}
                FDT_BEGIN_NODE => {
                    let name = read_cstr(struct_slice, cursor)?;
                    let name_len = name.len() + 1;
                    let next_cursor = align4(cursor + name_len);
                    if next_cursor > struct_slice.len() {
                        return Err("dtb: node name out of bounds");
                    }
                    cursor = next_cursor;

                    let mut node = Node::new(NameRef::Borrowed(name));
                    node.parent = stack.last().copied();
                    let id = nodes.len();
                    if let Some(parent) = node.parent {
                        nodes
                            .get_mut(parent)
                            .ok_or("dtb: invalid parent id")?
                            .children
                            .push(id);
                    }
                    if root.is_none() {
                        root = Some(id);
                    }
                    nodes.push(node);
                    stack.push(id);
                }
                FDT_END_NODE => {
                    stack.pop().ok_or("dtb: unmatched FDT_END_NODE")?;
                }
                FDT_PROP => {
                    if cursor + size_of::<FdtProperty>() > struct_slice.len() {
                        return Err("dtb: property header out of bounds");
                    }

                    let prop_ptr = struct_slice[cursor..].as_ptr() as *const FdtProperty;
                    // Safety: bounds checked above; validated struct offset keeps this aligned.
                    let property = unsafe { &*prop_ptr };
                    let len = property.get_property_len() as usize;
                    let nameoff = property.get_name_offset() as usize;
                    cursor += size_of::<FdtProperty>();

                    let name = read_cstr(strings_slice, nameoff)?;
                    let value_start = cursor;
                    let value_end = value_start
                        .checked_add(len)
                        .ok_or("dtb: overflow in property length")?;
                    if value_end > struct_slice.len() {
                        return Err("dtb: property value out of bounds");
                    }
                    let value_bytes = &struct_slice[value_start..value_end];
                    cursor = align4(value_end);
                    if cursor > struct_slice.len() {
                        return Err("dtb: property padding out of bounds");
                    }

                    let current = stack.last().copied().ok_or("dtb: PROP with no open node")?;
                    nodes
                        .get_mut(current)
                        .ok_or("dtb: invalid node id")?
                        .properties
                        .push(Property::new(
                            NameRef::Borrowed(name),
                            ValueRef::Borrowed(value_bytes),
                        ));
                }
                FDT_END => {
                    break;
                }
                _ => return Err("dtb: unknown FDT token"),
            }
        }

        if !stack.is_empty() {
            return Err("dtb: unmatched BEGIN_NODE/END_NODE");
        }
        let root = root.ok_or("dtb: no root node")?;

        Ok(DeviceTree {
            header,
            mem_reserve,
            nodes,
            root,
            _state: PhantomData,
        })
    }

    pub fn into_owned(self) -> DeviceTree<'static, Owned> {
        fn name_to_owned<'dtb>(name: NameRef<'dtb>) -> NameRef<'static> {
            match name {
                NameRef::Borrowed(s) => NameRef::Owned(s.to_string()),
                NameRef::Owned(s) => NameRef::Owned(s),
            }
        }

        fn value_to_owned<'dtb>(value: ValueRef<'dtb>) -> ValueRef<'static> {
            match value {
                ValueRef::Borrowed(v) => ValueRef::Owned(v.to_vec()),
                ValueRef::Owned(v) => ValueRef::Owned(v),
            }
        }

        fn prop_to_owned<'dtb>(prop: Property<'dtb>) -> Property<'static> {
            Property {
                name: name_to_owned(prop.name),
                value: value_to_owned(prop.value),
            }
        }

        fn node_to_owned<'dtb>(node: Node<'dtb>) -> Node<'static> {
            Node {
                name: name_to_owned(node.name),
                properties: node.properties.into_iter().map(prop_to_owned).collect(),
                children: node.children,
                parent: node.parent,
            }
        }

        let nodes = self.nodes.into_iter().map(node_to_owned).collect();

        DeviceTree {
            header: self.header,
            mem_reserve: self.mem_reserve,
            nodes,
            root: self.root,
            _state: PhantomData,
        }
    }

    pub fn to_owned(&self) -> DeviceTree<'static, Owned> {
        self.clone().into_owned()
    }
}

impl<'dtb, State> DeviceTree<'dtb, State> {
    /// Serialize this AST into a newly allocated DTB blob.
    ///
    /// The returned `AlignedSliceBox<u8>` owns the DTB bytes with alignment suitable for FDT access.
    /// The AST can be dropped afterwards to free its heap.
    pub fn into_dtb_box(self) -> Result<AlignedSliceBox<u8>, &'static str> {
        let mut string_offsets: BTreeMap<String, u32> = BTreeMap::new();
        let mut strings_size: usize = 0;

        for node in &self.nodes {
            for prop in &node.properties {
                let name = prop.name.as_str();
                if !string_offsets.contains_key(name) {
                    let offset = strings_size as u32;
                    string_offsets.insert(name.to_string(), offset);
                    strings_size = strings_size
                        .checked_add(name.len() + 1)
                        .ok_or("dtb: overflow in strings_size")?;
                }
            }
        }

        fn estimate_node_size<'dtb, State>(
            tree: &DeviceTree<'dtb, State>,
            node_id: NodeId,
        ) -> Result<usize, &'static str> {
            let node = tree
                .nodes
                .get(node_id)
                .ok_or("dtb: invalid node id in estimate_node_size")?;
            if node.name.as_str() == "__removed" {
                return Ok(0);
            }
            let mut size = 4; // FDT_BEGIN_NODE
            size += align4(node.name.as_str().len() + 1);
            for prop in &node.properties {
                let len = prop.value.as_slice().len();
                size = size
                    .checked_add(4 + 8 + align4(len))
                    .ok_or("dtb: overflow in property sizing")?;
            }
            for &child in &node.children {
                size = size
                    .checked_add(estimate_node_size(tree, child)?)
                    .ok_or("dtb: overflow in child sizing")?;
            }
            size = size
                .checked_add(4)
                .ok_or("dtb: overflow in end node sizing")?; // FDT_END_NODE
            Ok(size)
        }

        let size_dt_struct = estimate_node_size(&self, self.root)?
            .checked_add(4)
            .ok_or("dtb: overflow in struct size")?; // FDT_END

        let mem_rsv_size = (self.mem_reserve.len() + 1)
            .checked_mul(16)
            .ok_or("dtb: overflow in memreserve sizing")?;

        let header_size = 40usize;
        let off_mem_rsvmap = header_size;
        let off_dt_struct = align4(
            off_mem_rsvmap
                .checked_add(mem_rsv_size)
                .ok_or("dtb: overflow in struct offset")?,
        );
        let off_dt_strings = off_dt_struct
            .checked_add(size_dt_struct)
            .ok_or("dtb: overflow in strings offset")?;
        let totalsize = off_dt_strings
            .checked_add(strings_size)
            .ok_or("dtb: overflow in totalsize")?;
        if totalsize > core::u32::MAX as usize {
            return Err("dtb: totalsize exceeds u32");
        }

        let mut buf_uninit =
            AlignedSliceBox::<u8>::new_uninit_with_align(totalsize, align_of::<u64>())
                .map_err(|_| "dtb: allocation failed")?;
        for byte in buf_uninit.iter_mut() {
            *byte = MaybeUninit::new(0u8);
        }
        let mut buf = unsafe { buf_uninit.assume_init() };

        let version = if self.header.version == 0 {
            17
        } else {
            self.header.version
        };
        let last_comp_version = if self.header.last_comp_version == 0 {
            16
        } else {
            self.header.last_comp_version
        };

        write_be_u32(&mut buf, 0, FDT_MAGIC)?;
        write_be_u32(&mut buf, 4, totalsize as u32)?;
        write_be_u32(&mut buf, 8, off_dt_struct as u32)?;
        write_be_u32(&mut buf, 12, off_dt_strings as u32)?;
        write_be_u32(&mut buf, 16, off_mem_rsvmap as u32)?;
        write_be_u32(&mut buf, 20, version)?;
        write_be_u32(&mut buf, 24, last_comp_version)?;
        write_be_u32(&mut buf, 28, self.header.boot_cpuid_phys)?;
        write_be_u32(&mut buf, 32, strings_size as u32)?;
        write_be_u32(&mut buf, 36, size_dt_struct as u32)?;

        let mut reserve_off = off_mem_rsvmap;
        for entry in &self.mem_reserve {
            write_be_u64(&mut buf, reserve_off, entry.address)?;
            write_be_u64(&mut buf, reserve_off + 8, entry.size)?;
            reserve_off += 16;
        }
        write_be_u64(&mut buf, reserve_off, 0)?;
        write_be_u64(&mut buf, reserve_off + 8, 0)?;

        for (name, offset) in &string_offsets {
            let pos = off_dt_strings
                .checked_add(*offset as usize)
                .ok_or("dtb: overflow in strings position")?;
            let end = pos
                .checked_add(name.len() + 1)
                .ok_or("dtb: overflow in strings write")?;
            if end > buf.len() {
                return Err("dtb: strings block out of bounds");
            }
            buf[pos..pos + name.len()].copy_from_slice(name.as_bytes());
            buf[pos + name.len()] = 0;
        }

        fn emit_node<'dtb, State>(
            tree: &DeviceTree<'dtb, State>,
            buf: &mut [u8],
            struct_base: usize,
            cursor: &mut usize,
            string_offsets: &BTreeMap<String, u32>,
            node_id: NodeId,
        ) -> Result<(), &'static str> {
            let node = tree
                .nodes
                .get(node_id)
                .ok_or("dtb: invalid node id in emit_node")?;
            if node.name.as_str() == "__removed" {
                return Ok(());
            }

            write_be_u32(buf, struct_base + *cursor, FDT_BEGIN_NODE)?;
            *cursor += 4;

            let name = node.name.as_str();
            let name_len = name.len() + 1;
            let aligned_len = align4(name_len);
            if struct_base + *cursor + aligned_len > buf.len() {
                return Err("dtb: node name out of bounds in emit_node");
            }
            let base = struct_base + *cursor;
            buf[base..base + name.len()].copy_from_slice(name.as_bytes());
            buf[base + name.len()] = 0;
            for i in name.len() + 1..aligned_len {
                buf[base + i] = 0;
            }
            *cursor += aligned_len;

            for prop in &node.properties {
                let prop_name = prop.name.as_str();
                let name_offset = *string_offsets
                    .get(prop_name)
                    .ok_or("dtb: missing string offset")?;
                let value_bytes = prop.value.as_slice();
                let len = value_bytes.len();
                let aligned_len = align4(len);

                write_be_u32(buf, struct_base + *cursor, FDT_PROP)?;
                *cursor += 4;
                write_be_u32(buf, struct_base + *cursor, len as u32)?;
                write_be_u32(buf, struct_base + *cursor + 4, name_offset)?;
                *cursor += 8;

                if struct_base + *cursor + aligned_len > buf.len() {
                    return Err("dtb: property out of bounds in emit_node");
                }
                let base_prop = struct_base + *cursor;
                buf[base_prop..base_prop + len].copy_from_slice(value_bytes);
                for i in len..aligned_len {
                    buf[base_prop + i] = 0;
                }
                *cursor += aligned_len;
            }

            for &child in &node.children {
                emit_node(tree, buf, struct_base, cursor, string_offsets, child)?;
            }

            write_be_u32(buf, struct_base + *cursor, FDT_END_NODE)?;
            *cursor += 4;
            Ok(())
        }

        let mut cursor = 0usize;
        emit_node(
            &self,
            &mut buf,
            off_dt_struct,
            &mut cursor,
            &string_offsets,
            self.root,
        )?;
        write_be_u32(&mut buf, off_dt_struct + cursor, FDT_END)?;
        cursor += 4;

        if cursor != size_dt_struct {
            return Err("dtb: size_dt_struct mismatch");
        }

        Ok(buf)
    }
}

pub trait DeviceTreeQueryExt<'dtb, State = Owned> {
    fn node(&self, id: NodeId) -> Option<&Node<'dtb>>;
    fn find_node_by_path(&self, path: &str) -> Option<NodeId>;
}

impl<'dtb, State> DeviceTreeQueryExt<'dtb, State> for DeviceTree<'dtb, State> {
    fn node(&self, id: NodeId) -> Option<&Node<'dtb>> {
        self.nodes.get(id)
    }

    fn find_node_by_path(&self, path: &str) -> Option<NodeId> {
        if path == "/" {
            return Some(self.root);
        }
        if !path.starts_with('/') {
            return None;
        }

        let mut current = self.root;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            let node = self.node(current)?;
            let mut next = None;
            for &child_id in &node.children {
                let child = self.node(child_id)?;
                if child.name.as_str() == segment {
                    next = Some(child_id);
                    break;
                }
            }
            current = next?;
        }
        Some(current)
    }
}

pub trait DeviceTreeEditExt<'dtb> {
    fn node_mut(&mut self, id: NodeId) -> Option<&mut Node<'dtb>>;

    fn get_or_create_node_by_path(&mut self, path: &str) -> Result<NodeId, &'static str>;

    fn add_child(&mut self, parent: NodeId, name: NameRef<'dtb>) -> Result<NodeId, &'static str>;

    fn reparent_node(&mut self, node: NodeId, new_parent: NodeId) -> Result<(), &'static str>;

    fn detach_node(&mut self, node: NodeId) -> Result<(), &'static str>;
}

impl<'dtb> DeviceTreeEditExt<'dtb> for DeviceTree<'dtb, Owned> {
    fn node_mut(&mut self, id: NodeId) -> Option<&mut Node<'dtb>> {
        self.nodes.get_mut(id)
    }

    fn get_or_create_node_by_path(&mut self, path: &str) -> Result<NodeId, &'static str> {
        if path == "/" {
            return Ok(self.root);
        }
        if !path.starts_with('/') {
            return Err("dtb: path must start with '/'");
        }
        let mut current = self.root;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            let maybe_child = {
                let node = self
                    .node(current)
                    .ok_or("dtb: invalid node id in path walk")?;
                node.children.iter().copied().find(|&child_id| {
                    self.node(child_id)
                        .map(|child| child.name.as_str() == segment)
                        .unwrap_or(false)
                })
            };
            current = match maybe_child {
                Some(id) => id,
                None => self.add_child(current, NameRef::Owned(segment.to_string()))?,
            };
        }
        Ok(current)
    }

    fn add_child(&mut self, parent: NodeId, name: NameRef<'dtb>) -> Result<NodeId, &'static str> {
        if parent >= self.nodes.len() {
            return Err("dtb: invalid parent id");
        }
        let id = self.nodes.len();
        let mut node = Node::new(name);
        node.parent = Some(parent);
        self.nodes.push(node);
        self.nodes
            .get_mut(parent)
            .ok_or("dtb: invalid parent id")?
            .children
            .push(id);
        Ok(id)
    }

    fn reparent_node(&mut self, node: NodeId, new_parent: NodeId) -> Result<(), &'static str> {
        if node == self.root {
            return Err("dtb: cannot reparent root node");
        }
        if node >= self.nodes.len() {
            return Err("dtb: invalid node id");
        }
        if new_parent >= self.nodes.len() {
            return Err("dtb: invalid parent id");
        }

        let old_parent = self
            .node(node)
            .and_then(|n| n.parent)
            .ok_or("dtb: node has no parent")?;

        self.node_mut(old_parent)
            .ok_or("dtb: invalid old parent")?
            .children
            .retain(|&child| child != node);

        self.node_mut(new_parent)
            .ok_or("dtb: invalid new parent")?
            .children
            .push(node);

        self.node_mut(node).ok_or("dtb: invalid node id")?.parent = Some(new_parent);

        Ok(())
    }

    fn detach_node(&mut self, node: NodeId) -> Result<(), &'static str> {
        if node == self.root {
            return Err("dtb: cannot detach root node");
        }
        if node >= self.nodes.len() {
            return Err("dtb: invalid node id");
        }

        if let Some(parent_id) = self.node(node).and_then(|n| n.parent) {
            self.node_mut(parent_id)
                .ok_or("dtb: invalid parent")?
                .children
                .retain(|&child| child != node);
        }

        let children = self
            .node(node)
            .map(|n| n.children.clone())
            .ok_or("dtb: invalid node id")?;

        for child_id in children {
            if let Some(child) = self.node_mut(child_id) {
                child.parent = None;
            }
        }

        let node = self.node_mut(node).ok_or("dtb: invalid node id")?;
        node.children.clear();
        node.properties.clear();
        node.parent = None;
        node.name = NameRef::Owned("__removed".to_string());

        Ok(())
    }
}

pub trait NodeQueryExt<'dtb> {
    fn property(&self, name: &str) -> Option<&Property<'dtb>>;
}

impl<'dtb> NodeQueryExt<'dtb> for Node<'dtb> {
    fn property(&self, name: &str) -> Option<&Property<'dtb>> {
        self.properties
            .iter()
            .find(|prop| prop.name.as_str() == name)
    }
}

pub trait NodeEditExt<'dtb> {
    fn set_property(&mut self, name: NameRef<'dtb>, value: ValueRef<'dtb>);
    fn remove_property(&mut self, name: &str) -> bool;
}

impl<'dtb> NodeEditExt<'dtb> for Node<'dtb> {
    fn set_property(&mut self, name: NameRef<'dtb>, value: ValueRef<'dtb>) {
        if let Some(existing) = self
            .properties
            .iter_mut()
            .find(|prop| prop.name.as_str() == name.as_str())
        {
            existing.value = value;
        } else {
            self.properties.push(Property::new(name, value));
        }
    }

    fn remove_property(&mut self, name: &str) -> bool {
        let len_before = self.properties.len();
        self.properties.retain(|prop| prop.name.as_str() != name);
        len_before != self.properties.len()
    }
}

pub trait MmioCollectExt<'dtb> {}

impl<'dtb, State> MmioCollectExt<'dtb> for DeviceTree<'dtb, State> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct AlignedDtb<const N: usize>([u8; N]);

    static TEST_DTB: AlignedDtb<{ include_bytes!("../test/test.dtb").len() }> =
        AlignedDtb(*include_bytes!("../test/test.dtb"));

    fn aligned_fixture() -> &'static [u8] {
        &TEST_DTB.0
    }

    #[test]
    fn reparent_moves_node_between_parents() {
        let mut tree = DeviceTree::with_root(NameRef::Borrowed("/"));
        let pcie = tree
            .add_child(tree.root, NameRef::Borrowed("pcie"))
            .unwrap();
        let soc = tree.add_child(tree.root, NameRef::Borrowed("soc")).unwrap();
        let ep0 = tree.add_child(pcie, NameRef::Borrowed("ep0")).unwrap();
        let _ep1 = tree.add_child(pcie, NameRef::Borrowed("ep1")).unwrap();

        tree.reparent_node(ep0, soc).unwrap();

        let pcie_node = tree.node(pcie).unwrap();
        assert!(
            !pcie_node.children.contains(&ep0),
            "reparent should remove child from old parent"
        );

        let soc_node = tree.node(soc).unwrap();
        assert!(
            soc_node.children.contains(&ep0),
            "reparent should append to new parent"
        );

        let ep0_node = tree.node(ep0).unwrap();
        assert_eq!(ep0_node.parent, Some(soc));
    }

    #[test]
    fn detach_clears_links_and_properties() {
        let mut tree = DeviceTree::with_root(NameRef::Borrowed("/"));
        let pcie = tree
            .add_child(tree.root, NameRef::Borrowed("pcie"))
            .unwrap();
        let ep0 = tree.add_child(pcie, NameRef::Borrowed("ep0")).unwrap();
        tree.node_mut(pcie)
            .unwrap()
            .set_property(NameRef::Borrowed("compatible"), ValueRef::Borrowed(b"pcie"));
        tree.node_mut(ep0).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Borrowed(b"endpoint"),
        );

        tree.detach_node(pcie).unwrap();

        let root = tree.node(tree.root).unwrap();
        assert!(
            !root.children.contains(&pcie),
            "detaching should remove node from parent"
        );

        let pcie_node = tree.node(pcie).unwrap();
        assert!(pcie_node.children.is_empty());
        assert!(pcie_node.properties.is_empty());
        assert_eq!(pcie_node.parent, None);
        assert_eq!(pcie_node.name.as_str(), "__removed");
    }

    #[test]
    fn round_trip_simple_tree() {
        let mut tree = DeviceTree::with_root(NameRef::Borrowed("/"));
        tree.header.version = 17;
        tree.header.last_comp_version = 16;
        tree.node_mut(tree.root).unwrap().set_property(
            NameRef::Borrowed("compatible"),
            ValueRef::Borrowed(b"test\0"),
        );

        let child = tree
            .add_child(tree.root, NameRef::Borrowed("child"))
            .unwrap();
        tree.node_mut(child).unwrap().set_property(
            NameRef::Borrowed("value"),
            ValueRef::Borrowed(&[0x01, 0x02]),
        );

        let dtb = tree.into_dtb_box().expect("serialize dtb");
        let parsed = DeviceTree::from_dtb(&dtb).expect("parse serialized dtb");

        let root = parsed.node(parsed.root).unwrap();
        let compat = root.property("compatible").unwrap();
        assert_eq!(compat.value.as_slice(), b"test\0");

        let child_id = parsed.find_node_by_path("/child").expect("child exists");
        let child_node = parsed.node(child_id).unwrap();
        let prop = child_node.property("value").unwrap();
        assert_eq!(prop.value.as_slice(), &[0x01, 0x02]);
        assert_eq!(child_node.parent, Some(parsed.root));
    }

    #[test]
    fn parse_real_dtb_fixture() {
        let dtb = aligned_fixture();
        let tree = DeviceTree::from_dtb(dtb).expect("parse fixture dtb");

        assert!(tree.find_node_by_path("/cpus").is_some());
        assert!(tree.find_node_by_path("/clocks/clk-osc").is_some());

        let root = tree.node(tree.root).unwrap();
        let model = root.property("model").unwrap();
        assert!(core::str::from_utf8(model.value.as_slice()).is_ok());

        let cpus_id = tree.find_node_by_path("/cpus").unwrap();
        let cpus = tree.node(cpus_id).unwrap();
        let addr_cells = cpus.property("#address-cells").unwrap().value.as_slice();
        assert_eq!(addr_cells, &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn edit_and_reserialize_fixture() {
        let dtb = aligned_fixture();
        let mut tree = DeviceTree::from_dtb(dtb)
            .expect("parse fixture dtb")
            .into_owned();

        let chosen_id = tree
            .get_or_create_node_by_path("/chosen")
            .expect("chosen node");
        let stdout_value = b"serial0:115200\0".to_vec();
        tree.node_mut(chosen_id).unwrap().set_property(
            NameRef::Borrowed("stdout-path"),
            ValueRef::Owned(stdout_value.clone()),
        );
        tree.node_mut(chosen_id)
            .unwrap()
            .remove_property("linux,initrd-start");
        tree.node_mut(chosen_id)
            .unwrap()
            .remove_property("linux,initrd-end");

        let clk_osc_id = tree
            .find_node_by_path("/clocks/clk-osc")
            .expect("clk-osc node");
        let clk_freq_before = tree
            .node(clk_osc_id)
            .unwrap()
            .property("clock-frequency")
            .unwrap()
            .value
            .as_slice()
            .to_vec();

        let dtb_new = tree.into_dtb_box().expect("serialize edited dtb");
        let reparsed = DeviceTree::from_dtb(&dtb_new).expect("reparse edited dtb");

        let chosen_new = reparsed
            .find_node_by_path("/chosen")
            .expect("chosen node present");
        let stdout_prop = reparsed
            .node(chosen_new)
            .unwrap()
            .property("stdout-path")
            .unwrap();
        assert_eq!(stdout_prop.value.as_slice(), stdout_value.as_slice());
        assert!(
            reparsed
                .node(chosen_new)
                .unwrap()
                .property("linux,initrd-start")
                .is_none()
        );

        let clk_osc_new = reparsed
            .find_node_by_path("/clocks/clk-osc")
            .expect("clk-osc present");
        let clk_freq_after = reparsed
            .node(clk_osc_new)
            .unwrap()
            .property("clock-frequency")
            .unwrap()
            .value
            .as_slice();
        assert_eq!(clk_freq_after, clk_freq_before.as_slice());
    }
}
