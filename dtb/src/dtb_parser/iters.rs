use core::mem::size_of;

use super::types::read_regs_from_bytes;
use super::types::read_regs_from_bytes_u128;
use super::types::read_u32_be;
use super::view::DtbNodeView;

pub struct InterruptCellsIter<'a, const CELLS: usize> {
    data: &'a [u8],
    consumed: usize,
}

impl<'a, const CELLS: usize> InterruptCellsIter<'a, CELLS> {
    pub(crate) fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        let stride = CELLS
            .checked_mul(size_of::<u32>())
            .ok_or("interrupts: stride overflow")?;
        if stride == 0 {
            return Err("interrupts: zero cell stride");
        }
        if data.len() % stride != 0 {
            return Err("interrupts: length not multiple of cell count");
        }
        Ok(Self { data, consumed: 0 })
    }

    fn next_internal(&mut self) -> Result<Option<[u32; CELLS]>, &'static str> {
        if self.consumed == self.data.len() {
            return Ok(None);
        }
        let stride = CELLS
            .checked_mul(size_of::<u32>())
            .ok_or("interrupts: stride overflow")?;
        if self.consumed + stride > self.data.len() {
            return Err("interrupts: overrun");
        }

        let mut cells = [0u32; CELLS];
        for (i, cell) in cells.iter_mut().enumerate() {
            let base = self.consumed + i * size_of::<u32>();
            let chunk = &self.data[base..base + size_of::<u32>()];
            *cell = read_u32_be(chunk)?;
        }

        self.consumed += stride;
        Ok(Some(cells))
    }
}

impl<'a, const CELLS: usize> Iterator for InterruptCellsIter<'a, CELLS> {
    type Item = Result<[u32; CELLS], &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_internal().transpose()
    }
}

pub struct RangesEntry {
    pub child_base: usize,
    pub parent_base: usize,
    pub len: usize,
}

pub struct RangesIter<'a> {
    property: &'a [u8],
    consumed: usize,
    entry_stride: usize,
    child_address_cells: u32,
    parent_address_cells: u32,
    child_size_cells: u32,
}

impl<'a> RangesIter<'a> {
    pub(crate) fn new(
        child_address_cells: u32,
        parent_address_cells: u32,
        child_size_cells: u32,
        property: &'a [u8],
    ) -> Result<Self, &'static str> {
        let max_cells = size_of::<usize>() / size_of::<u32>();
        if child_address_cells as usize > max_cells
            || child_size_cells as usize > max_cells
            || parent_address_cells as usize > max_cells
        {
            return Err("ranges: address/size cells overflow usize");
        }

        let cell_count = child_address_cells
            .checked_add(parent_address_cells)
            .and_then(|v| v.checked_add(child_size_cells))
            .ok_or("ranges: stride overflow")?;
        let entry_stride = cell_count
            .checked_mul(size_of::<u32>() as u32)
            .ok_or("ranges: stride overflow")? as usize;

        if entry_stride == 0 {
            return Err("ranges: zero stride");
        }
        if property.len() % entry_stride != 0 {
            return Err("ranges: length not multiple of stride");
        }

        Ok(Self {
            property,
            consumed: 0,
            entry_stride,
            child_address_cells,
            parent_address_cells,
            child_size_cells,
        })
    }

    fn next_internal(&mut self) -> Result<Option<RangesEntry>, &'static str> {
        if self.consumed == self.property.len() {
            return Ok(None);
        }
        let base = self.consumed;

        let (child_base, c0) =
            read_regs_from_bytes(&self.property[base..], self.child_address_cells)?;
        let (parent_base, c1) =
            read_regs_from_bytes(&self.property[base + c0..], self.parent_address_cells)?;
        let (len, c2) =
            read_regs_from_bytes(&self.property[base + c0 + c1..], self.child_size_cells)?;

        let consumed = c0
            .checked_add(c1)
            .and_then(|v| v.checked_add(c2))
            .ok_or("ranges: overrun")?;
        if consumed != self.entry_stride {
            return Err("ranges: unexpected entry size");
        }
        self.consumed += consumed;

        Ok(Some(RangesEntry {
            child_base,
            parent_base,
            len,
        }))
    }
}

impl<'a> Iterator for RangesIter<'a> {
    type Item = Result<RangesEntry, &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_internal().transpose()
    }
}

pub(crate) struct RangesEntryWide {
    pub child_base: u128,
    pub parent_base: u128,
    pub len: u128,
}

pub(crate) struct RangesIterWide<'a> {
    property: &'a [u8],
    consumed: usize,
    entry_stride: usize,
    child_address_cells: u32,
    parent_address_cells: u32,
    child_size_cells: u32,
}

impl<'a> RangesIterWide<'a> {
    pub(crate) fn new(
        child_address_cells: u32,
        parent_address_cells: u32,
        child_size_cells: u32,
        property: &'a [u8],
    ) -> Result<Self, &'static str> {
        // Up to 4 cells => 128-bit.
        let max_cells = 4usize;
        if child_address_cells as usize > max_cells
            || child_size_cells as usize > max_cells
            || parent_address_cells as usize > max_cells
        {
            return Err("ranges: address/size cells overflow u128");
        }

        let cell_count = child_address_cells
            .checked_add(parent_address_cells)
            .and_then(|v| v.checked_add(child_size_cells))
            .ok_or("ranges: stride overflow")?;
        let entry_stride = cell_count
            .checked_mul(size_of::<u32>() as u32)
            .ok_or("ranges: stride overflow")? as usize;
        if entry_stride == 0 {
            return Err("ranges: zero stride");
        }
        if property.len() % entry_stride != 0 {
            return Err("ranges: length not multiple of stride");
        }

        Ok(Self {
            property,
            consumed: 0,
            entry_stride,
            child_address_cells,
            parent_address_cells,
            child_size_cells,
        })
    }

    fn next_internal(&mut self) -> Result<Option<RangesEntryWide>, &'static str> {
        if self.consumed == self.property.len() {
            return Ok(None);
        }
        let base = self.consumed;
        let (child_base, c0) =
            read_regs_from_bytes_u128(&self.property[base..], self.child_address_cells)?;
        let (parent_base, c1) =
            read_regs_from_bytes_u128(&self.property[base + c0..], self.parent_address_cells)?;
        let (len, c2) =
            read_regs_from_bytes_u128(&self.property[base + c0 + c1..], self.child_size_cells)?;
        let consumed = c0
            .checked_add(c1)
            .and_then(|v| v.checked_add(c2))
            .ok_or("ranges: overrun")?;
        if consumed != self.entry_stride {
            return Err("ranges: unexpected entry size");
        }
        self.consumed += consumed;
        Ok(Some(RangesEntryWide {
            child_base,
            parent_base,
            len,
        }))
    }
}

impl<'a> Iterator for RangesIterWide<'a> {
    type Item = Result<RangesEntryWide, &'static str>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_internal().transpose()
    }
}

pub struct RegRawIter<'a, 'dtb, 's> {
    property: &'a [u8],
    remaining: usize,
    stride: usize,
    parent_address_cells: u32,
    parent_size_cells: u32,
    _node: &'a DtbNodeView<'dtb, 's>,
}

impl<'a, 'dtb, 's> RegRawIter<'a, 'dtb, 's> {
    pub(crate) fn new(node: &'a DtbNodeView<'dtb, 's>) -> Result<Self, &'static str> {
        let reg = node.property_bytes("reg")?.ok_or("reg: missing property")?;
        if reg.is_empty() {
            return Err("reg: empty property");
        }

        let parent_address_cells = node.parent_address_cells()?;
        let parent_size_cells = node.parent_size_cells()?;

        let max_cells = size_of::<usize>() / size_of::<u32>();
        if parent_address_cells as usize > max_cells || parent_size_cells as usize > max_cells {
            return Err("reg: cells overflow usize");
        }

        let cell_count = parent_address_cells
            .checked_add(parent_size_cells)
            .ok_or("reg: stride overflow")?;
        let stride = cell_count
            .checked_mul(size_of::<u32>() as u32)
            .ok_or("reg: stride overflow")? as usize;

        if stride == 0 || reg.len() % stride != 0 {
            return Err("reg: length not multiple of stride");
        }

        Ok(Self {
            property: reg,
            remaining: reg.len(),
            stride,
            parent_address_cells,
            parent_size_cells,
            _node: node,
        })
    }

    fn next_internal(&mut self) -> Result<Option<(usize, usize)>, &'static str> {
        if self.remaining == 0 {
            return Ok(None);
        }

        let consumed = self.property.len() - self.remaining;
        let start = consumed;

        let (addr, a_len) =
            read_regs_from_bytes(&self.property[start..], self.parent_address_cells)?;
        let (len, l_len) =
            read_regs_from_bytes(&self.property[start + a_len..], self.parent_size_cells)?;

        let used = a_len.checked_add(l_len).ok_or("reg: overrun")?;
        if used != self.stride {
            return Err("reg: unexpected entry size");
        }

        self.remaining = self.remaining.checked_sub(used).ok_or("reg: overrun")?;
        Ok(Some((addr, len)))
    }
}

impl<'a, 'dtb, 's> Iterator for RegRawIter<'a, 'dtb, 's> {
    type Item = Result<(usize, usize), &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_internal().transpose()
    }
}

pub struct RegIter<'a, 'dtb, 's> {
    node: &'a DtbNodeView<'dtb, 's>,
    property: &'a [u8],
    remaining: usize,
    stride: usize,
    parent_address_cells: u32,
    parent_size_cells: u32,
}

impl<'a, 'dtb, 's> RegIter<'a, 'dtb, 's> {
    pub(crate) fn new(node: &'a DtbNodeView<'dtb, 's>) -> Result<Self, &'static str> {
        let reg = node.property_bytes("reg")?.ok_or("reg: missing property")?;
        if reg.is_empty() {
            return Err("reg: empty property");
        }

        let parent_address_cells = node.parent_address_cells()?;
        let parent_size_cells = node.parent_size_cells()?;

        let max_cells = size_of::<usize>() / size_of::<u32>();
        if parent_address_cells as usize > max_cells || parent_size_cells as usize > max_cells {
            return Err("reg: cells overflow usize");
        }

        let cell_count = parent_address_cells
            .checked_add(parent_size_cells)
            .ok_or("reg: stride overflow")?;
        let stride = cell_count
            .checked_mul(size_of::<u32>() as u32)
            .ok_or("reg: stride overflow")? as usize;

        if stride == 0 || reg.len() % stride != 0 {
            return Err("reg: length not multiple of stride");
        }

        Ok(Self {
            node,
            property: reg,
            remaining: reg.len(),
            stride,
            parent_address_cells,
            parent_size_cells,
        })
    }

    fn next_internal(&mut self) -> Result<Option<(usize, usize)>, &'static str> {
        if self.remaining == 0 {
            return Ok(None);
        }

        let consumed = self.property.len() - self.remaining;
        let start = consumed;

        let (addr, a_len) =
            read_regs_from_bytes(&self.property[start..], self.parent_address_cells)?;
        let (len, l_len) =
            read_regs_from_bytes(&self.property[start + a_len..], self.parent_size_cells)?;

        let used = a_len.checked_add(l_len).ok_or("reg: overrun")?;
        if used != self.stride {
            return Err("reg: unexpected entry size");
        }

        self.remaining = self.remaining.checked_sub(used).ok_or("reg: overrun")?;
        self.node
            .translate_reg_address_internal((addr, len))
            .map(Some)
    }
}

impl<'a, 'dtb, 's> Iterator for RegIter<'a, 'dtb, 's> {
    type Item = Result<(usize, usize), &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_internal().transpose()
    }
}
