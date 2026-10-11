//! Rift-table generation for PE-aware PA19 creation.
//!
//! A PA19 rift is a staircase map from old RVAs to new RVAs: the shift of an RVA is
//! `new - old` of the last entry whose old RVA is at or below it (identity before the first
//! entry). `mspatcha.dll` uses it to rewrite relocations, imports, exports, resources and relative
//! branches of the old image so that the old file looks like the new one before LZX matching.
//! Any sorted table yields a valid patch because the transform is a deterministic function of
//! (old file, options, rift); the table only decides how good the history is. The generator here
//! (INFERRED, not `mspatchc.dll`'s algorithm) pairs the sections of the two images, finds
//! unique 8-byte anchors common to a section pair, keeps the longest increasing chain of them and
//! emits an entry wherever the new-minus-old shift of the chain changes persistently.

use super::pe::nt_header;
use std::collections::HashMap;

const WINDOW: usize = 8;
/// A run of anchors must cover at least this many matching bytes to change the shift.
const MIN_RUN_BYTES: usize = 16;
/// An anchor is extended until the bytes differ; shorter extensions are noise.
const MIN_ANCHOR: usize = 12;
/// Hard cap on emitted entries (the header stores the count as a `uvar`).
const MAX_ENTRIES: usize = 4096;

struct Section {
    name: [u8; 8],
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
}

fn rd16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn rd32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

fn sections(buf: &[u8]) -> Option<Vec<Section>> {
    let nt = nt_header(buf)?;
    let count = usize::from(rd16(buf, nt + 6)?);
    let first = nt + usize::from(rd16(buf, nt + 20)?) + 24;
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let at = first + 40 * index;
        let name: [u8; 8] = buf.get(at..at + 8)?.try_into().ok()?;
        let raw_size = rd32(buf, at + 16)?;
        let raw_offset = rd32(buf, at + 20)?;
        // Skip sections without usable raw data.
        if raw_size == 0 || (raw_offset as usize).checked_add(raw_size as usize)? > buf.len() {
            continue;
        }
        out.push(Section {
            name,
            virtual_address: rd32(buf, at + 12)?,
            raw_size,
            raw_offset,
        });
    }
    Some(out)
}

fn window_key(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..WINDOW].try_into().expect("eight bytes"))
}

/// An anchor: `old[i..i + length] == new[j..j + length]`, offsets relative to the section.
#[derive(Clone, Copy)]
struct Anchor {
    old: usize,
    new: usize,
    length: usize,
}

/// Unique-window anchors between one section of each image.
fn anchors(old: &[u8], new: &[u8]) -> Vec<Anchor> {
    if old.len() < WINDOW || new.len() < WINDOW {
        return Vec::new();
    }
    // `u32::MAX` marks a window that occurs more than once in the old section.
    let mut table: HashMap<u64, u32> = HashMap::with_capacity(old.len() / 2);
    for index in 0..=old.len() - WINDOW {
        table
            .entry(window_key(&old[index..]))
            .and_modify(|slot| *slot = u32::MAX)
            .or_insert(index as u32);
    }
    let mut seen_new: HashMap<u64, u32> = HashMap::new();
    for index in 0..=new.len() - WINDOW {
        let key = window_key(&new[index..]);
        if table.contains_key(&key) {
            seen_new
                .entry(key)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    let mut out = Vec::new();
    let mut j = 0;
    while j + WINDOW <= new.len() {
        let key = window_key(&new[j..]);
        match (table.get(&key), seen_new.get(&key)) {
            (Some(&i), Some(&1)) if i != u32::MAX => {
                let i = i as usize;
                let mut length = 0;
                while i + length < old.len()
                    && j + length < new.len()
                    && old[i + length] == new[j + length]
                {
                    length += 1;
                }
                if length >= MIN_ANCHOR {
                    out.push(Anchor {
                        old: i,
                        new: j,
                        length,
                    });
                    j += length;
                    continue;
                }
            }
            _ => {}
        }
        j += 1;
    }
    out
}

/// Longest chain (by covered bytes) with both coordinates strictly increasing.
fn chain(anchors: &[Anchor]) -> Vec<Anchor> {
    // Anchors are sorted by `new`; keep the heaviest chain increasing in `old` with a
    // Fenwick-free O(n log n) patience variant over cumulative weight.
    let n = anchors.len();
    if n == 0 {
        return Vec::new();
    }
    let mut best = vec![0usize; n];
    let mut previous = vec![usize::MAX; n];
    // tails[k] = (old end of the chain's last anchor, cumulative weight, index) kept sorted by
    // old end with strictly increasing weight.
    let mut tails: Vec<(usize, usize, usize)> = Vec::new();
    for (index, anchor) in anchors.iter().enumerate() {
        let start = anchor.old;
        let count = tails.partition_point(|&(end, _, _)| end <= start);
        let (base, parent) = if count == 0 {
            (0, usize::MAX)
        } else {
            (tails[count - 1].1, tails[count - 1].2)
        };
        best[index] = base + anchor.length;
        previous[index] = parent;
        let end = anchor.old + anchor.length;
        let position = tails.partition_point(|&(e, _, _)| e < end);
        if position > 0 && tails[position - 1].1 >= best[index] {
            continue;
        }
        let mut cut = position;
        while cut < tails.len() && tails[cut].1 <= best[index] {
            cut += 1;
        }
        tails.splice(position..cut, [(end, best[index], index)]);
    }
    let mut index = tails.last().map(|tail| tail.2).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    while index != usize::MAX {
        out.push(anchors[index]);
        index = previous[index];
    }
    out.reverse();
    out
}

/// Rift entries `(old_rva, new_rva)` for one section pair.
fn section_entries(
    old: &Section,
    old_data: &[u8],
    new: &Section,
    new_data: &[u8],
    divisor: usize,
) -> Vec<(u32, u32)> {
    let chain = chain(&anchors(old_data, new_data));
    let min_run = MIN_RUN_BYTES.max(new_data.len().checked_div(divisor).unwrap_or(0));
    let mut entries = vec![(old.virtual_address, new.virtual_address)];
    let mut shift = i64::from(new.virtual_address) - i64::from(old.virtual_address);
    // Group consecutive anchors by shift and require a run to cover enough bytes before it
    // becomes a new step.
    let mut index = 0;
    while index < chain.len() {
        let run_shift = chain[index].new as i64 - chain[index].old as i64;
        let mut covered = 0;
        let mut end = index;
        while end < chain.len() && chain[end].new as i64 - chain[end].old as i64 == run_shift {
            covered += chain[end].length;
            end += 1;
        }
        let section_shift =
            run_shift + i64::from(new.virtual_address) - i64::from(old.virtual_address);
        if covered >= min_run && section_shift != shift {
            let first = chain[index];
            let old_rva = i64::from(old.virtual_address) + first.old as i64;
            let new_rva = i64::from(new.virtual_address) + first.new as i64;
            if let (Ok(old_rva), Ok(new_rva)) = (u32::try_from(old_rva), u32::try_from(new_rva)) {
                entries.push((old_rva, new_rva));
                shift = section_shift;
            }
        }
        index = end;
    }
    entries
}

/// Generates a rift for the PE32 pair; empty when no useful table can be built. A run of
/// matching bytes with a different shift becomes a step only if it covers at least
/// `section_length / divisor` bytes (at least [`MIN_RUN_BYTES`]; `divisor == 0` means just the
/// minimum), so larger divisors keep more steps.
pub(super) fn generate(old: &[u8], new: &[u8], divisor: usize) -> Vec<(u32, u32)> {
    let (Some(old_sections), Some(new_sections)) = (sections(old), sections(new)) else {
        return Vec::new();
    };
    let mut entries: Vec<(u32, u32)> = Vec::new();
    for old_section in &old_sections {
        let Some(new_section) = new_sections
            .iter()
            .find(|candidate| candidate.name == old_section.name)
        else {
            continue;
        };
        let slice = |section: &Section, buf: &[u8]| -> Vec<u8> {
            let start = section.raw_offset as usize;
            buf[start..start + section.raw_size as usize].to_vec()
        };
        let (old_data, new_data) = (slice(old_section, old), slice(new_section, new));
        for entry in section_entries(old_section, &old_data, new_section, &new_data, divisor) {
            // Entries must be strictly increasing in the old RVA.
            if entries.last().is_none_or(|last| entry.0 > last.0) {
                entries.push(entry);
            }
        }
    }
    entries.truncate(MAX_ENTRIES);
    // An all-identity table carries no information.
    if entries.iter().all(|&(old_rva, new_rva)| old_rva == new_rva) {
        return Vec::new();
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_picks_the_heaviest_increasing_run() {
        let anchors = [
            Anchor {
                old: 100,
                new: 0,
                length: 20,
            },
            Anchor {
                old: 10,
                new: 30,
                length: 16,
            },
            Anchor {
                old: 130,
                new: 60,
                length: 40,
            },
        ];
        let picked = chain(&anchors);
        assert_eq!(picked.len(), 2);
        assert_eq!((picked[0].old, picked[1].old), (100, 130));
    }

    #[test]
    fn anchors_find_a_shifted_block() {
        let old: Vec<u8> = (0..4000u32)
            .flat_map(|i| (i.wrapping_mul(2654435761)).to_le_bytes())
            .collect();
        let mut new = vec![7u8; 48];
        new.extend_from_slice(&old);
        let found = anchors(&old, &new);
        assert!(found.iter().any(|a| a.new as i64 - a.old as i64 == 48));
    }
}
