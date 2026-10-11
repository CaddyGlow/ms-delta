//! Bounded, zero-copy CLI4 metadata layouts and native source normalization.
use super::{
    Bits,
    pe::PeLayout,
    rift::{IntFormat, RiftTable},
};
use crate::{Error, Limits, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Graph {
    Legacy,
    #[default]
    Cli4,
}

impl Graph {
    pub(super) fn read_maps(self, bits: &mut Bits<'_>, limits: &Limits) -> Result<CliMaps> {
        // Both native graphs serialize four shared IntFormats and all 64 maps.
        CliMaps::read(bits, limits)
    }
    fn schema(self, table: usize) -> &'static [Column] {
        if self == Self::Legacy && table == 42 {
            &[
                Column {
                    kind: 0,
                    argument: 0,
                },
                Column {
                    kind: 0,
                    argument: 0,
                },
                Column {
                    kind: 7,
                    argument: 12,
                },
                Column {
                    kind: 3,
                    argument: 0,
                },
                Column {
                    kind: 7,
                    argument: 0,
                },
            ]
        } else {
            schema(table)
        }
    }
}

#[derive(Debug)]
pub(super) struct MetadataInfo {
    pub graph: Graph,
    pub image_offset: usize,
    pub metadata_size: usize,
    pub base_rva: u32,
    pub stream_count: usize,
    pub stream_headers: usize,
    pub strings_offset: usize,
    pub strings_size: usize,
    pub user_strings_offset: usize,
    pub user_strings_size: usize,
    pub blob_offset: usize,
    pub blob_size: usize,
    pub guid_offset: usize,
    pub guid_size: usize,
    pub tables_offset: usize,
    pub tables_size: usize,
    pub rows: [u32; 64],
    pub table_offsets: [usize; 64],
    pub row_sizes: [usize; 64],
    pub column_offsets: [[usize; 16]; 64],
    pub column_widths: [[usize; 16]; 64],
    pub heap_widths: [bool; 3],
    pub valid_mask: u64,
}
impl Default for MetadataInfo {
    fn default() -> Self {
        Self {
            graph: Graph::Cli4,
            image_offset: 0,
            metadata_size: 0,
            base_rva: 0,
            stream_count: 0,
            stream_headers: 0,
            strings_offset: 0,
            strings_size: 0,
            user_strings_offset: 0,
            user_strings_size: 0,
            blob_offset: 0,
            blob_size: 0,
            guid_offset: 0,
            guid_size: 0,
            tables_offset: 0,
            tables_size: 0,
            rows: [0; 64],
            table_offsets: [0; 64],
            row_sizes: [0; 64],
            column_offsets: [[0; 16]; 64],
            column_widths: [[0; 16]; 64],
            heap_widths: [false; 3],
            valid_mask: 0,
        }
    }
}

impl MetadataInfo {
    pub(super) fn read_for_graph(
        bits: &mut Bits<'_>,
        limits: &Limits,
        graph: Graph,
    ) -> Result<Self> {
        if graph == Graph::Cli4 {
            Self::read(bits, limits)
        } else {
            Self::read_inner(bits, limits, graph)
        }
    }

    pub(super) fn parse_for_graph(
        source: &[u8],
        pe: &PeLayout,
        limits: &Limits,
        graph: Graph,
    ) -> Result<Self> {
        let parsed = if graph == Graph::Cli4 {
            Self::parse(source, pe, limits)
        } else {
            Self::parse_inner(source, pe, limits, graph)
        };
        match parsed {
            // Native source parsing recovers to an empty metadata dictionary
            // when modern GenericParam rows exceed the old five-column layout.
            Err(Error::Invalid("CLI table bounds")) if graph == Graph::Legacy => Ok(Self {
                graph,
                ..Self::default()
            }),
            other => other,
        }
    }

    pub(super) fn read(bits: &mut Bits<'_>, limits: &Limits) -> Result<Self> {
        Self::read_inner(bits, limits, Graph::Cli4)
    }
    fn read_inner(bits: &mut Bits<'_>, limits: &Limits, graph: Graph) -> Result<Self> {
        if bits.read(1)? == 0 {
            return Ok(Self {
                graph,
                ..Self::default()
            });
        }
        let mut fields = [0usize; 15];
        for value in &mut fields {
            *value =
                usize::try_from(bits.read(32)?).map_err(|_| Error::Limit("CLI metadata field"))?;
        }
        let mut result = Self::from_fields(fields);
        result.graph = graph;
        for width in &mut result.heap_widths {
            *width = bits.read(1)? != 0;
        }
        result.valid_mask = bits.read(32)? | (bits.read(32)? << 32);
        for table in 0..64 {
            if result.valid_mask & (1 << table) != 0 {
                result.rows[table] = bits.read(32)? as u32;
            }
        }
        result.init_layout(limits)?;
        Ok(result)
    }

    fn from_fields(f: [usize; 15]) -> Self {
        Self {
            image_offset: f[0],
            metadata_size: f[1],
            base_rva: f[2] as u32,
            stream_count: f[3],
            stream_headers: f[4],
            strings_offset: f[5],
            strings_size: f[6],
            user_strings_offset: f[7],
            user_strings_size: f[8],
            blob_offset: f[9],
            blob_size: f[10],
            guid_offset: f[11],
            guid_size: f[12],
            tables_offset: f[13],
            tables_size: f[14],
            ..Self::default()
        }
    }

    pub(super) fn parse(source: &[u8], pe: &PeLayout, limits: &Limits) -> Result<Self> {
        Self::parse_inner(source, pe, limits, Graph::Cli4)
    }
    fn parse_inner(source: &[u8], pe: &PeLayout, limits: &Limits, graph: Graph) -> Result<Self> {
        let Some((rva, size)) = pe.directory(14) else {
            return Ok(Self::default());
        };
        if size < 16 {
            return Err(Error::Invalid("CLI header size"));
        }
        let header = pe.offset(rva, 16)?;
        let base_rva = read32(source, header + 8)?;
        let metadata_size = read32(source, header + 12)? as usize;
        let image_offset = pe.offset(base_rva, metadata_size)?;
        let root = range(source, image_offset, metadata_size)?;
        if read32(root, 0)? != 0x424a5342 {
            return Err(Error::Invalid("CLI metadata signature"));
        }
        let version = read32(root, 12)? as usize;
        if version > 255 {
            return Err(Error::Invalid("CLI metadata version size"));
        }
        let streams = 16usize
            .checked_add(version.div_ceil(4) * 4)
            .ok_or(Error::Invalid("CLI stream header overflow"))?;
        let count = read16(root, streams + 2)? as usize;
        if count > 64 {
            return Err(Error::Limit("CLI stream count"));
        }
        let mut result = Self {
            graph,
            image_offset,
            metadata_size,
            base_rva: 0,
            stream_count: count,
            stream_headers: image_offset + streams + 4,
            ..Self::default()
        };
        let mut cursor = streams + 4;
        for _ in 0..count {
            let offset = read32(root, cursor)? as usize;
            let size = read32(root, cursor + 4)? as usize;
            range(root, offset, size)?;
            let name_start = cursor + 8;
            let tail = root
                .get(name_start..)
                .ok_or(Error::Invalid("CLI stream name"))?;
            let length = tail
                .iter()
                .take(32)
                .position(|b| *b == 0)
                .ok_or(Error::Invalid("CLI stream name terminator"))?;
            let absolute = image_offset + offset;
            let (destination, capacity) = match &tail[..length] {
                b"#Strings" => (&mut result.strings_offset, &mut result.strings_size),
                b"#US" => (
                    &mut result.user_strings_offset,
                    &mut result.user_strings_size,
                ),
                b"#Blob" => (&mut result.blob_offset, &mut result.blob_size),
                b"#GUID" => (&mut result.guid_offset, &mut result.guid_size),
                b"#~" | b"#-" => (&mut result.tables_offset, &mut result.tables_size),
                _ => {
                    cursor = (name_start + length + 1).div_ceil(4) * 4;
                    continue;
                }
            };
            if *destination != 0 {
                return Err(Error::Invalid("CLI duplicate stream"));
            }
            *destination = absolute;
            *capacity = size;
            cursor = (name_start + length + 1).div_ceil(4) * 4;
        }
        if result.tables_offset == 0 {
            return Err(Error::Invalid("CLI missing table stream"));
        }
        let tables = range(source, result.tables_offset, result.tables_size)?;
        range(tables, 0, 24)?;
        result.heap_widths = [tables[6] & 1 != 0, tables[6] & 2 != 0, tables[6] & 4 != 0];
        result.valid_mask = read64(tables, 8)?;
        let mut cursor = 24;
        for table in 0..64 {
            if result.valid_mask & (1 << table) != 0 {
                result.rows[table] = read32(tables, cursor)?;
                cursor += 4;
            }
        }
        result.init_layout(limits)?;
        Ok(result)
    }

    fn init_layout(&mut self, limits: &Limits) -> Result<()> {
        if self.metadata_size == 0 {
            return Ok(());
        }
        if self.metadata_size > limits.max_source_bytes.max(limits.max_output_bytes)
            || self.tables_size > self.metadata_size
        {
            return Err(Error::Limit("CLI metadata size"));
        }
        let mut cursor = 24usize + self.valid_mask.count_ones() as usize * 4;
        if cursor > self.tables_size {
            return Err(Error::Invalid("CLI table header bounds"));
        }
        let root_end = self
            .image_offset
            .checked_add(self.metadata_size)
            .ok_or(Error::Invalid("CLI metadata bounds"))?;
        if self.stream_count > 64
            || self.stream_headers < self.image_offset
            || self.stream_headers > root_end
        {
            return Err(Error::Invalid("CLI stream header bounds"));
        }
        for (offset, size) in [
            (self.strings_offset, self.strings_size),
            (self.user_strings_offset, self.user_strings_size),
            (self.blob_offset, self.blob_size),
            (self.guid_offset, self.guid_size),
            (self.tables_offset, self.tables_size),
        ] {
            if offset != 0
                && (offset < self.image_offset
                    || offset.checked_add(size).is_none_or(|end| end > root_end))
            {
                return Err(Error::Invalid("CLI stream bounds"));
            }
        }
        for table in 0..64 {
            if self.rows[table] == 0 {
                continue;
            }
            let columns = self.graph.schema(table);
            if columns.is_empty() {
                return Err(Error::Unsupported("CLI metadata table"));
            }
            let mut width = 0usize;
            for (index, column) in columns.iter().enumerate() {
                let long = match column.kind {
                    0 => false,
                    1 | 2 => true,
                    3 => self.heap_widths[0],
                    4 => self.heap_widths[2],
                    5 => self.heap_widths[1],
                    6 => self.rows[column.argument as usize] >= 65536,
                    7 => {
                        let (bits, tables) = coded(column.argument);
                        tables
                            .iter()
                            .filter(|t| **t < 64)
                            .any(|t| self.rows[*t as usize] >= (65536u32 >> bits))
                    }
                    _ => return Err(Error::Invalid("CLI column kind")),
                };
                self.column_offsets[table][index] = width;
                self.column_widths[table][index] = if long { 4 } else { 2 };
                width += self.column_widths[table][index];
            }
            self.row_sizes[table] = width;
            self.table_offsets[table] = self
                .tables_offset
                .checked_add(cursor)
                .ok_or(Error::Invalid("CLI table offset overflow"))?;
            let length = width
                .checked_mul(self.rows[table] as usize)
                .ok_or(Error::Limit("CLI table length"))?;
            cursor = cursor
                .checked_add(length)
                .ok_or(Error::Limit("CLI tables length"))?;
            if cursor > self.tables_size {
                return Err(Error::Invalid("CLI table bounds"));
            }
        }
        Ok(())
    }

    pub(super) fn method_rvas(&self, source: &[u8], limits: &Limits) -> Result<Vec<u32>> {
        let count = self.rows[6] as usize;
        if count > limits.max_parameter_bytes / 4 {
            return Err(Error::Limit("CLI method RVAs"));
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for row in 0..count {
            result.push(read32(
                source,
                self.table_offsets[6] + row * self.row_sizes[6],
            )?);
        }
        Ok(result)
    }
}

#[derive(Debug)]
pub(super) struct CliMaps {
    pub strings: RiftTable,
    pub user_strings: RiftTable,
    pub blob: RiftTable,
    pub guid: RiftTable,
    pub tables: [RiftTable; 64],
}
impl CliMaps {
    pub(super) fn read(bits: &mut Bits<'_>, limits: &Limits) -> Result<Self> {
        let empty = || RiftTable::from_entries(Vec::new(), limits);
        if bits.read(1)? == 0 {
            return Ok(Self {
                strings: empty()?,
                user_strings: empty()?,
                blob: empty()?,
                guid: empty()?,
                tables: std::array::from_fn(|_| RiftTable::default()),
            });
        }
        let a = IntFormat::read(bits)?;
        let b = IntFormat::read(bits)?;
        let c = IntFormat::read(bits)?;
        let d = IntFormat::read(bits)?;
        let mut retained = 0usize;
        let mut read_map = |left: &IntFormat, right: &IntFormat| -> Result<RiftTable> {
            let bounded = Limits {
                max_parameter_bytes: limits
                    .max_parameter_bytes
                    .checked_sub(retained)
                    .ok_or(Error::Limit("CLI maps workspace"))?,
                ..*limits
            };
            let table = RiftTable::read_with_formats(bits, left, right, &bounded)?;
            retained = retained
                .checked_add(
                    table
                        .entries()
                        .len()
                        .checked_mul(16)
                        .ok_or(Error::Limit("CLI maps workspace"))?,
                )
                .ok_or(Error::Limit("CLI maps workspace"))?;
            Ok(table)
        };
        let strings = read_map(&a, &b)?;
        let user_strings = read_map(&a, &b)?;
        let blob = read_map(&a, &b)?;
        let guid = read_map(&c, &d)?;
        let mut tables = std::array::from_fn(|_| RiftTable::default());
        for table in &mut tables {
            *table = read_map(&c, &d)?;
        }
        Ok(Self {
            strings,
            user_strings,
            blob,
            guid,
            tables,
        })
    }
    pub(super) fn map_token(&self, value: u32) -> u32 {
        let table = value >> 24;
        let row = value & 0xffffff;
        if table < 64 {
            (table << 24) | self.tables[table as usize].map(i64::from(row)) as u32
        } else if table == 0x70 {
            (table << 24) | self.user_strings.map(i64::from(row)) as u32
        } else {
            value
        }
    }
    pub(super) fn map_coded(&self, index: u32, value: u32) -> u32 {
        let (bits, tables) = coded(index);
        let tag = value & ((1 << bits) - 1);
        if let Some(table) = tables.get(tag as usize).filter(|t| **t < 64) {
            tag | ((self.tables[*table as usize].map(i64::from(value >> bits)) as u32) << bits)
        } else {
            value
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Column {
    pub kind: u32,
    pub argument: u32,
}
pub(super) fn schema(table: usize) -> &'static [Column] {
    match table {
        0 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 5,
                argument: 0,
            },
            Column {
                kind: 5,
                argument: 0,
            },
            Column {
                kind: 5,
                argument: 0,
            },
        ],
        1 => &[
            Column {
                kind: 7,
                argument: 11,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
        ],
        2 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 4,
            },
            Column {
                kind: 6,
                argument: 6,
            },
        ],
        3 => &[Column {
            kind: 6,
            argument: 4,
        }],
        4 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 3,
            },
        ],
        5 => &[Column {
            kind: 6,
            argument: 6,
        }],
        6 => &[
            Column {
                kind: 2,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 1,
            },
            Column {
                kind: 6,
                argument: 8,
            },
        ],
        7 => &[Column {
            kind: 6,
            argument: 8,
        }],
        8 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
        ],
        9 => &[
            Column {
                kind: 6,
                argument: 2,
            },
            Column {
                kind: 7,
                argument: 0,
            },
        ],
        10 => &[
            Column {
                kind: 7,
                argument: 5,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 2,
            },
        ],
        11 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 1,
            },
            Column {
                kind: 4,
                argument: 0,
            },
        ],
        12 => &[
            Column {
                kind: 7,
                argument: 2,
            },
            Column {
                kind: 7,
                argument: 10,
            },
            Column {
                kind: 4,
                argument: 6,
            },
        ],
        13 => &[
            Column {
                kind: 7,
                argument: 3,
            },
            Column {
                kind: 4,
                argument: 7,
            },
        ],
        14 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 4,
            },
            Column {
                kind: 4,
                argument: 8,
            },
        ],
        15 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 2,
            },
        ],
        16 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 4,
            },
        ],
        17 => &[Column {
            kind: 4,
            argument: 9,
        }],
        18 => &[
            Column {
                kind: 6,
                argument: 2,
            },
            Column {
                kind: 6,
                argument: 20,
            },
        ],
        19 => &[Column {
            kind: 6,
            argument: 20,
        }],
        20 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 0,
            },
        ],
        21 => &[
            Column {
                kind: 6,
                argument: 2,
            },
            Column {
                kind: 6,
                argument: 23,
            },
        ],
        22 => &[Column {
            kind: 6,
            argument: 23,
        }],
        23 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 4,
            },
        ],
        24 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 6,
            },
            Column {
                kind: 7,
                argument: 6,
            },
        ],
        25 => &[
            Column {
                kind: 6,
                argument: 2,
            },
            Column {
                kind: 7,
                argument: 7,
            },
            Column {
                kind: 7,
                argument: 7,
            },
        ],
        26 => &[Column {
            kind: 3,
            argument: 0,
        }],
        27 => &[Column {
            kind: 4,
            argument: 5,
        }],
        28 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 8,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 26,
            },
        ],
        29 => &[
            Column {
                kind: 2,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 4,
            },
        ],
        30 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
        ],
        31 => &[Column {
            kind: 1,
            argument: 0,
        }],
        32 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 10,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
        ],
        33 => &[Column {
            kind: 1,
            argument: 0,
        }],
        34 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
        ],
        35 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 11,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 12,
            },
        ],
        36 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 35,
            },
        ],
        37 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 6,
                argument: 35,
            },
        ],
        38 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 4,
                argument: 12,
            },
        ],
        39 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 9,
            },
        ],
        40 => &[
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 1,
                argument: 0,
            },
            Column {
                kind: 3,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 9,
            },
        ],
        41 => &[
            Column {
                kind: 6,
                argument: 2,
            },
            Column {
                kind: 6,
                argument: 2,
            },
        ],
        42 => &[
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 0,
                argument: 0,
            },
            Column {
                kind: 7,
                argument: 12,
            },
            Column {
                kind: 3,
                argument: 0,
            },
        ],
        43 => &[
            Column {
                kind: 7,
                argument: 7,
            },
            Column {
                kind: 4,
                argument: 0,
            },
        ],
        44 => &[
            Column {
                kind: 6,
                argument: 42,
            },
            Column {
                kind: 7,
                argument: 0,
            },
        ],
        _ => &[],
    }
}
fn coded(index: u32) -> (u32, &'static [u32]) {
    match index {
        0 => (2, &[2, 1, 27]),
        1 => (2, &[4, 8, 23]),
        2 => (
            5,
            &[
                6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
            ],
        ),
        3 => (1, &[4, 8]),
        4 => (2, &[2, 6, 32]),
        5 => (3, &[2, 1, 26, 6, 27]),
        6 => (1, &[20, 23]),
        7 => (1, &[6, 10]),
        8 => (1, &[4, 6]),
        9 => (2, &[38, 35, 39]),
        10 => (3, &[64, 64, 6, 10, 64]),
        11 => (2, &[0, 26, 35, 1]),
        12 => (1, &[2, 6]),
        _ => (0, &[]),
    }
}
fn range(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or(Error::Invalid("CLI range overflow"))?,
        )
        .ok_or(Error::Invalid("CLI truncated range"))
}
fn read16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, 2)?
            .try_into()
            .map_err(|_| Error::Invalid("CLI u16"))?,
    ))
}
fn read32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4)?
            .try_into()
            .map_err(|_| Error::Invalid("CLI u32"))?,
    ))
}
fn read64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        range(bytes, offset, 8)?
            .try_into()
            .map_err(|_| Error::Invalid("CLI u64"))?,
    ))
}

pub(super) fn normalize(
    bytes: &mut [u8],
    source: &MetadataInfo,
    target: &MetadataInfo,
    maps: &CliMaps,
    used: &RiftTable,
    limits: &Limits,
) -> Result<()> {
    if source.metadata_size == 0 {
        return Ok(());
    }
    let mut blobs: Vec<(u32, u32)> = Vec::new();
    let mut work = bytes.len().saturating_mul(4);
    for table in 0..64 {
        for (column_index, column) in source.graph.schema(table).iter().enumerate() {
            let width = source.column_widths[table][column_index];
            if width == 0 {
                continue;
            }
            for row in 0..source.rows[table] as usize {
                work = work
                    .checked_sub(width)
                    .ok_or(Error::Limit("CLI metadata work"))?;
                let offset = source.table_offsets[table]
                    + row * source.row_sizes[table]
                    + source.column_offsets[table][column_index];
                let value = if width == 4 {
                    read32(bytes, offset)?
                } else {
                    u32::from(read16(bytes, offset)?)
                };
                let mapped = match column.kind {
                    2 => (used.map(i64::from(value.wrapping_add(source.base_rva))) as u32)
                        .wrapping_sub(target.base_rva),
                    3 => maps.strings.map(i64::from(value)) as u32,
                    4 => {
                        if blobs.len()
                            >= limits.max_parameter_bytes / std::mem::size_of::<(u32, u32)>()
                        {
                            return Err(Error::Limit("CLI signature workspace"));
                        }
                        if blobs.len() == blobs.capacity() {
                            let maximum =
                                limits.max_parameter_bytes / std::mem::size_of::<(u32, u32)>();
                            let capacity = blobs.capacity().saturating_mul(2).max(4).min(maximum);
                            blobs
                                .try_reserve_exact(capacity - blobs.len())
                                .map_err(|_| Error::Allocation)?;
                        }
                        blobs.push((value, column.argument));
                        maps.blob.map(i64::from(value)) as u32
                    }
                    5 => maps.guid.map(i64::from(value)) as u32,
                    6 => maps.tables[column.argument as usize].map(i64::from(value)) as u32,
                    7 => maps.map_coded(column.argument, value),
                    _ => value,
                };
                write_column(bytes, offset, width, mapped)?;
            }
        }
    }
    blobs.sort_unstable_by_key(|entry| entry.0);
    let mut previous = 0;
    for (index, kind) in blobs {
        if index == 0 || index == previous {
            continue;
        }
        previous = index;
        if !matches!(kind, 1..=5 | 9) {
            continue;
        }
        let start = source
            .blob_offset
            .checked_add(index as usize)
            .ok_or(Error::Invalid("CLI blob offset"))?;
        let end = source
            .blob_offset
            .checked_add(source.blob_size)
            .ok_or(Error::Invalid("CLI blob heap"))?;
        if start >= end {
            return Err(Error::Invalid("CLI blob index"));
        }
        let mut cursor = start;
        let size = compressed(bytes, &mut cursor, end)?.0 as usize;
        let payload_end = cursor
            .checked_add(size)
            .filter(|stop| *stop <= end)
            .ok_or(Error::Invalid("CLI blob bounds"))?;
        range(bytes, cursor, size)?;
        work = work
            .checked_sub(size)
            .ok_or(Error::Limit("CLI signature work"))?;
        let mut walker = Signature {
            bytes: &mut bytes[cursor..payload_end],
            position: 0,
            maps,
            budget: size.saturating_mul(4),
        };
        walker.signature(kind)?;
    }
    Ok(())
}
fn write_column(bytes: &mut [u8], offset: usize, width: usize, value: u32) -> Result<()> {
    range(bytes, offset, width)?;
    if width == 4 {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    } else {
        bytes[offset..offset + 2].copy_from_slice(&(value as u16).to_le_bytes());
    }
    Ok(())
}
fn compressed(bytes: &[u8], position: &mut usize, end: usize) -> Result<(u32, usize)> {
    let start = *position;
    let first = *bytes
        .get(start)
        .filter(|_| start < end)
        .ok_or(Error::Invalid("CLI compressed integer"))?;
    let width = if first & 0x80 == 0 {
        1
    } else if first & 0xc0 == 0x80 {
        2
    } else if first & 0xe0 == 0xc0 {
        4
    } else {
        return Err(Error::Invalid("CLI compressed integer prefix"));
    };
    if start.checked_add(width).is_none_or(|stop| stop > end) {
        return Err(Error::Invalid("CLI compressed integer bounds"));
    }
    let tail = range(bytes, start, width)?;
    let value = match width {
        1 => u32::from(first),
        2 => (u32::from(first & 0x3f) << 8) | u32::from(tail[1]),
        _ => {
            (u32::from(first & 0x1f) << 24)
                | (u32::from(tail[1]) << 16)
                | (u32::from(tail[2]) << 8)
                | u32::from(tail[3])
        }
    };
    *position += width;
    Ok((value, width))
}
struct Signature<'a> {
    bytes: &'a mut [u8],
    position: usize,
    maps: &'a CliMaps,
    budget: usize,
}
impl Signature<'_> {
    fn integer(&mut self) -> Result<u32> {
        self.budget = self
            .budget
            .checked_sub(1)
            .ok_or(Error::Limit("CLI signature work"))?;
        Ok(compressed(self.bytes, &mut self.position, self.bytes.len())?.0)
    }
    fn byte(&mut self) -> Result<u8> {
        let result = *self
            .bytes
            .get(self.position)
            .ok_or(Error::Invalid("CLI signature truncated"))?;
        self.position += 1;
        Ok(result)
    }
    fn mapped_type(&mut self) -> Result<()> {
        let start = self.position;
        let value = self.integer()?;
        let width = self.position - start;
        let tag = value & 3;
        // Pinned CLI4 native normalization uses the TypeDef map for tags 0/1.
        let table = match tag {
            0 | 1 => 2,
            2 => 27,
            _ => return Ok(()),
        };
        let value = ((self.maps.tables[table].map(i64::from(value >> 2)) as u32) << 2) | tag;
        // Native preserves the old slot; shrinking does not clear leftover bytes.
        if value < 0x80 {
            self.bytes[start] = value as u8;
        } else if value < 0x4000 && width >= 2 {
            self.bytes[start] = (value >> 8) as u8 | 0x80;
            self.bytes[start + 1] = value as u8;
        } else if value < 0x20000000 && width >= 4 {
            self.bytes[start] = (value >> 24) as u8 | 0xc0;
            self.bytes[start + 1] = (value >> 16) as u8;
            self.bytes[start + 2] = (value >> 8) as u8;
            self.bytes[start + 3] = value as u8;
        }
        Ok(())
    }
    fn signature(&mut self, kind: u32) -> Result<()> {
        self.signature_at(kind, 0)
    }

    fn signature_at(&mut self, kind: u32, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(Error::Limit("CLI signature depth"));
        }
        match kind {
            3 => {
                self.byte()?;
                self.ty(depth + 1)?;
            }
            5 => self.ty(depth + 1)?,
            1 | 2 | 4 | 9 => {
                let convention = self.byte()?;
                if convention & 15 == 6 {
                    self.ty(depth + 1)?;
                } else if kind == 9 && convention & 15 == 7 {
                    // Native StandAloneSig normalization consumes the local
                    // count but transforms only the first local type.
                    self.integer()?;
                    self.ty(depth + 1)?;
                } else if matches!(convention & 15, 7 | 10) {
                    let count = self.integer()?;
                    for _ in 0..count {
                        self.ty(depth + 1)?;
                    }
                } else {
                    if convention & 0x10 != 0 && !matches!(kind, 1 | 2) {
                        self.integer()?;
                    }
                    let count = self.integer()?;
                    // Native MethodDef/MemberRef iteration leaves a void or
                    // typed-by-ref return at the cursor while counting types;
                    // consequently it never reaches this signature's parameters.
                    // A zero element also terminates the native walk. Generic
                    // arity is intentionally read as the first count by this
                    // graph; it does not have a separate generic-arity skip.
                    if matches!(kind, 1 | 2)
                        && matches!(self.bytes.get(self.position), Some(0 | 1 | 0x16))
                    {
                        return Ok(());
                    }
                    self.ty(depth + 1)?;
                    for _ in 0..count {
                        if self.bytes.get(self.position) == Some(&0x41) {
                            self.position += 1;
                        }
                        self.ty(depth + 1)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn ty(&mut self, depth: usize) -> Result<()> {
        if depth > 64 {
            return Err(Error::Limit("CLI signature depth"));
        }
        self.budget = self
            .budget
            .checked_sub(1)
            .ok_or(Error::Limit("CLI signature work"))?;
        let element = self.byte()?;
        match element {
            1..=14 | 0x16 | 0x18 | 0x19 | 0x1c => {}
            0x11 | 0x12 => self.mapped_type()?,
            0x13 | 0x1e => {
                self.integer()?;
            }
            0x0f | 0x10 | 0x1d | 0x45 => self.ty(depth + 1)?,
            0x1f | 0x20 => {
                self.mapped_type()?;
                self.ty(depth + 1)?;
            }
            0x14 => {
                self.ty(depth + 1)?;
                self.integer()?;
                let sizes = self.integer()?;
                for _ in 0..sizes {
                    self.integer()?;
                }
                let bounds = self.integer()?;
                for _ in 0..bounds {
                    self.integer()?;
                }
            }
            0x15 => {
                self.ty(depth + 1)?;
                // Native CLI4 walks only the generic base type here; argument
                // count and argument signatures are not consumed by this type.
            }
            0x1b => self.signature_at(1, depth + 1)?,
            _ => return Err(Error::Unsupported("CLI signature element")),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn maps() -> CliMaps {
        CliMaps {
            strings: RiftTable::default(),
            user_strings: RiftTable::default(),
            blob: RiftTable::default(),
            guid: RiftTable::default(),
            tables: std::array::from_fn(|_| RiftTable::default()),
        }
    }
    #[test]
    fn original_managed_layout_is_zero_copy_and_rejects_every_root_truncation() {
        let source = include_bytes!("../../docs/fixtures/pa30-cli-native/source.dll");
        let pe = PeLayout::parse(source).unwrap();
        let limits = Limits::default();
        let metadata = MetadataInfo::parse(source, &pe, &limits).unwrap();
        assert_eq!(metadata.base_rva, 0);
        assert!(metadata.rows[6] > 1);
        assert_eq!(
            metadata.method_rvas(source, &limits).unwrap().len(),
            metadata.rows[6] as usize
        );
        for end in metadata.image_offset..metadata.image_offset + metadata.metadata_size {
            assert!(
                MetadataInfo::parse(&source[..end], &pe, &limits).is_err(),
                "end {end}"
            );
        }
        let bounded = Limits {
            max_parameter_bytes: 3,
            ..limits
        };
        assert!(matches!(
            metadata.method_rvas(source, &bounded),
            Err(Error::Limit("CLI method RVAs"))
        ));
    }
    #[test]
    fn compressed_integer_prefixes_and_bounds_are_checked() {
        for bytes in [&[0x7f][..], &[0x80, 0x80], &[0xc0, 0, 0x40, 0]] {
            let mut p = 0;
            let (_, width) = compressed(bytes, &mut p, bytes.len()).unwrap();
            assert_eq!(width, bytes.len());
            assert_eq!(p, bytes.len());
            for end in 0..bytes.len() {
                assert!(compressed(&bytes[..end], &mut 0, end).is_err());
            }
        }
        for prefix in 0xe0..=0xff {
            assert!(compressed(&[prefix, 0, 0, 0], &mut 0, 4).is_err());
        }
    }
    #[test]
    fn signature_mapping_uses_native_type_tags_and_preserves_shrunk_tail() {
        let mut maps = maps();
        maps.tables[2] = RiftTable::from_entries(vec![(1, 2)], &Limits::default()).unwrap();
        maps.tables[1] = RiftTable::from_entries(vec![(1, 10)], &Limits::default()).unwrap();
        let mut signature = [0x12, 0x80, 0x05];
        Signature {
            bytes: &mut signature,
            position: 0,
            maps: &maps,
            budget: 12,
        }
        .signature(5)
        .unwrap();
        assert_eq!(signature, [0x12, 0x09, 0x05]);
        assert_eq!(maps.map_coded(0, 5), 41);
    }
    #[test]
    fn native_local_signature_transforms_only_first_local() {
        let mut maps = maps();
        maps.tables[2] =
            RiftTable::from_entries(vec![(0, 0), (2, 7), (3, 3)], &Limits::default()).unwrap();
        let mut bytes = [7, 3, 0x12, 8, 0x12, 8, 0x12, 8];
        Signature {
            bytes: &mut bytes,
            position: 0,
            maps: &maps,
            budget: 32,
        }
        .signature(9)
        .unwrap();
        assert_eq!(bytes, [7, 3, 0x12, 28, 0x12, 8, 0x12, 8]);
    }
    #[test]
    fn malformed_table_and_heap_geometries_fail_before_column_traversal() {
        let limits = Limits::default();
        let mut metadata = MetadataInfo {
            image_offset: 100,
            metadata_size: 100,
            stream_headers: 100,
            tables_offset: 150,
            tables_size: 10,
            ..MetadataInfo::default()
        };
        assert!(metadata.init_layout(&limits).is_err());
        metadata.tables_size = 24;
        metadata.blob_offset = 199;
        metadata.blob_size = 2;
        assert!(metadata.init_layout(&limits).is_err());
        metadata.blob_offset = 0;
        metadata.blob_size = 0;
        metadata.rows[6] = u32::MAX;
        assert!(metadata.init_layout(&limits).is_err());
    }
    #[test]
    fn recursive_function_pointer_signatures_are_depth_bounded() {
        let maps = maps();
        let mut bytes = Vec::new();
        for _ in 0..70 {
            bytes.extend_from_slice(&[0x1b, 0, 0]);
        }
        bytes.push(1);
        let len = bytes.len();
        assert!(matches!(
            Signature {
                bytes: &mut bytes,
                position: 0,
                maps: &maps,
                budget: len * 4
            }
            .signature(5),
            Err(Error::Limit("CLI signature depth"))
        ));
    }

    #[test]
    fn native_void_typedref_and_generic_prefixes_preserve_parameter_tokens() {
        let mut maps = maps();
        maps.tables[2] = RiftTable::from_entries(vec![(1, 9)], &Limits::default()).unwrap();
        for original in [
            vec![0x20, 1, 1, 0x12, 5],
            vec![0x20, 1, 0x16, 0x12, 5],
            vec![0x10, 1, 0, 0x12, 5],
        ] {
            let mut bytes = original.clone();
            Signature {
                bytes: &mut bytes,
                position: 0,
                maps: &maps,
                budget: 32,
            }
            .signature(1)
            .unwrap();
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn native_generic_instance_maps_only_the_base_type() {
        let mut maps = maps();
        maps.tables[2] = RiftTable::from_entries(vec![(1, 2)], &Limits::default()).unwrap();
        let mut bytes = [0x15, 0x12, 4, 1, 0x12, 4];
        Signature {
            bytes: &mut bytes,
            position: 0,
            maps: &maps,
            budget: 32,
        }
        .signature(5)
        .unwrap();
        assert_eq!(bytes, [0x15, 0x12, 8, 1, 0x12, 4]);
    }

    #[test]
    fn legacy_schema_adds_generic_param_constraint_and_recovers_exhausted_source() {
        assert_eq!(Graph::Cli4.schema(42).len(), 4);
        assert_eq!(Graph::Legacy.schema(42).len(), 5);
        assert_eq!(Graph::Legacy.schema(42)[4].kind, 7);
        let source = include_bytes!("../../docs/fixtures/pa30-cli-native/signatures/source.dll");
        let pe = PeLayout::parse(source).unwrap();
        let modern =
            MetadataInfo::parse_for_graph(source, &pe, &Limits::default(), Graph::Cli4).unwrap();
        let legacy =
            MetadataInfo::parse_for_graph(source, &pe, &Limits::default(), Graph::Legacy).unwrap();
        assert!(modern.rows[42] > 0);
        assert_eq!(legacy.metadata_size, 0);
    }

    #[test]
    fn legacy_and_cli4_layouts_agree_without_generic_param_rows() {
        let source = include_bytes!("../../docs/fixtures/pa30-cli-native/source.dll");
        let pe = PeLayout::parse(source).unwrap();
        let modern =
            MetadataInfo::parse_for_graph(source, &pe, &Limits::default(), Graph::Cli4).unwrap();
        let legacy =
            MetadataInfo::parse_for_graph(source, &pe, &Limits::default(), Graph::Legacy).unwrap();
        assert_eq!(legacy.row_sizes, modern.row_sizes);
        assert_eq!(legacy.table_offsets, modern.table_offsets);
        assert_eq!(legacy.rows, modern.rows);
    }

    #[test]
    fn original_five_column_generic_param_source_parses_complete_legacy_layout() {
        for (source, item_rid) in [
            (
                include_bytes!("../../docs/fixtures/pa30-pe32-native/legacy-schema/source.dll")
                    .as_slice(),
                6,
            ),
            (
                include_bytes!("../../docs/fixtures/pa30-pe32-native/legacy-schema/target.dll")
                    .as_slice(),
                2,
            ),
        ] {
            let pe = PeLayout::parse(source).unwrap();
            let legacy =
                MetadataInfo::parse_for_graph(source, &pe, &Limits::default(), Graph::Legacy)
                    .unwrap();
            assert!(legacy.metadata_size > 0);
            assert_eq!(legacy.rows[42], 3);
            assert_eq!(legacy.row_sizes[42], 10);
            assert_eq!(legacy.column_widths[42][4], 2);
            for row in 0..legacy.rows[42] as usize {
                let cell = legacy.table_offsets[42]
                    + row * legacy.row_sizes[42]
                    + legacy.column_offsets[42][4];
                assert_eq!(read16(source, cell).unwrap(), item_rid << 2);
            }
            assert!(legacy.table_offsets[43] > legacy.table_offsets[42]);
        }
    }
}
