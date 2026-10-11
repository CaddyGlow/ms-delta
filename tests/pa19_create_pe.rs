#![cfg(feature = "pa19")]

//! PA19 creation with Intel `E8` translation and PE32 awareness. Every patch is applied with
//! `apply_pa19`; the real `mspatcha.dll` also applied our PE and `E8` patches on a Windows guest
//! (see the module documentation of `pa19`). The images here are synthetic and need no Microsoft
//! files.

use ms_delta::{
    Limits,
    pa19::{Pa19CreateOptions, Pa19E8, Pa19Pe, apply_pa19, create_pa19_with, inspect_pa19},
};

struct Random(u64);

impl Random {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 16) as u32
    }
}

fn limits() -> Limits {
    Limits::default()
}

fn put16(buffer: &mut [u8], at: usize, value: u16) {
    buffer[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(buffer: &mut [u8], at: usize, value: u32) {
    buffer[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

const FUNCTION: usize = 64;

/// A synthetic image: `functions` 64-byte functions, each a random 40-byte body, `E8 rel32` to the
/// next function, `A1 abs32` pointing at the next function, `CC` padding; one HIGHLOW relocation
/// per absolute pointer. `bodies` supplies the random bodies so that two images can share them.
fn image(bodies: &[[u8; 40]], image_base: u32, time: u32, pe32_plus: bool) -> Vec<u8> {
    let functions = bodies.len();
    let text_size = functions * FUNCTION;
    let text_raw = text_size.div_ceil(0x200) * 0x200;
    let mut text = vec![0xcc; text_raw];
    let mut relocations = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        let at = index * FUNCTION;
        text[at..at + 40].copy_from_slice(body);
        let next = ((index + 1) % functions) * FUNCTION;
        text[at + 40] = 0xe8;
        let relative = next as i64 - (at + 45) as i64;
        text[at + 41..at + 45].copy_from_slice(&(relative as i32).to_le_bytes());
        text[at + 45] = 0xa1;
        let absolute = image_base.wrapping_add(0x1000 + next as u32);
        text[at + 46..at + 50].copy_from_slice(&absolute.to_le_bytes());
        relocations.push(0x1000 + (at + 46) as u32);
    }
    // One relocation block per 4 KiB page.
    let mut reloc = Vec::new();
    let mut page = u32::MAX;
    let mut block: Vec<u16> = Vec::new();
    let flush = |reloc: &mut Vec<u8>, page: u32, block: &mut Vec<u16>| {
        if block.is_empty() {
            return;
        }
        if block.len() % 2 == 1 {
            block.push(0);
        }
        reloc.extend_from_slice(&page.to_le_bytes());
        reloc.extend_from_slice(&(8 + 2 * block.len() as u32).to_le_bytes());
        for entry in block.iter() {
            reloc.extend_from_slice(&entry.to_le_bytes());
        }
        block.clear();
    };
    for rva in relocations {
        if rva & !0xfff != page {
            flush(&mut reloc, page, &mut block);
            page = rva & !0xfff;
        }
        block.push(0x3000 | (rva & 0xfff) as u16);
    }
    flush(&mut reloc, page, &mut block);
    let reloc_raw = reloc.len().div_ceil(0x200) * 0x200;
    let reloc_rva = 0x1000 + text_size.next_multiple_of(0x1000) as u32;
    let size_of_image = reloc_rva + (reloc.len() as u32).next_multiple_of(0x1000);

    let mut file = vec![0u8; 0x400];
    file[0] = b'M';
    file[1] = b'Z';
    put32(&mut file, 0x3c, 0x80);
    let nt = 0x80;
    file[nt..nt + 4].copy_from_slice(b"PE\0\0");
    put16(&mut file, nt + 4, if pe32_plus { 0x8664 } else { 0x14c });
    put16(&mut file, nt + 6, 2);
    put32(&mut file, nt + 8, time);
    put16(&mut file, nt + 20, if pe32_plus { 0xf0 } else { 0xe0 });
    put16(&mut file, nt + 22, 0x2102);
    let optional = nt + 24;
    put16(&mut file, optional, if pe32_plus { 0x20b } else { 0x10b });
    if pe32_plus {
        file[optional + 24..optional + 32].copy_from_slice(&u64::from(image_base).to_le_bytes());
        put32(&mut file, optional + 32, 0x1000);
        put32(&mut file, optional + 36, 0x200);
        put32(&mut file, optional + 56, size_of_image);
        put32(&mut file, optional + 60, 0x400);
        put32(&mut file, optional + 108, 16);
    } else {
        put32(&mut file, optional + 28, image_base);
        put32(&mut file, optional + 32, 0x1000);
        put32(&mut file, optional + 36, 0x200);
        put32(&mut file, optional + 56, size_of_image);
        put32(&mut file, optional + 60, 0x400);
        put32(&mut file, optional + 92, 16);
    }
    let directories = optional + if pe32_plus { 112 } else { 96 };
    put32(&mut file, directories + 5 * 8, reloc_rva);
    put32(&mut file, directories + 5 * 8 + 4, reloc.len() as u32);
    let sections = optional + if pe32_plus { 0xf0 } else { 0xe0 };
    for (index, (name, virtual_size, rva, raw, offset, flags)) in [
        (
            b".text\0\0\0",
            text_size as u32,
            0x1000u32,
            text_raw as u32,
            0x400u32,
            0x6000_0020u32,
        ),
        (
            b".reloc\0\0",
            reloc.len() as u32,
            reloc_rva,
            reloc_raw as u32,
            0x400 + text_raw as u32,
            0x4200_0040,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let at = sections + 40 * index;
        file[at..at + 8].copy_from_slice(name);
        put32(&mut file, at + 8, virtual_size);
        put32(&mut file, at + 12, rva);
        put32(&mut file, at + 16, raw);
        put32(&mut file, at + 20, offset);
        put32(&mut file, at + 36, flags);
    }
    file.extend_from_slice(&text);
    file.extend_from_slice(&reloc);
    file.resize(0x400 + text_raw + reloc_raw, 0);
    file
}

fn bodies(random: &mut Random, count: usize) -> Vec<[u8; 40]> {
    (0..count)
        .map(|_| std::array::from_fn(|_| random.next() as u8))
        .collect()
}

/// An old/new pair: the new image has a function inserted in the middle, a different ImageBase and
/// timestamp, and every absolute pointer and the relocation table follow.
fn pair(pe32_plus: bool) -> (Vec<u8>, Vec<u8>) {
    let mut random = Random(0x1234_5678_9abc_def1);
    let old_bodies = bodies(&mut random, 600);
    let mut new_bodies = old_bodies.clone();
    new_bodies.insert(250, bodies(&mut random, 1)[0]);
    new_bodies[400][3] ^= 0x77;
    (
        image(&old_bodies, 0x40_0000, 0x5a00_0000, pe32_plus),
        image(&new_bodies, 0x1000_0000, 0x6a00_0000, pe32_plus),
    )
}

fn raw(old: &[u8], new: &[u8]) -> Vec<u8> {
    create_pa19_with(old, new, &Pa19CreateOptions::default(), &limits()).unwrap()
}

fn with(pe: Pa19Pe, e8: Pa19E8) -> Pa19CreateOptions {
    Pa19CreateOptions {
        pe,
        e8,
        ..Default::default()
    }
}

#[test]
fn pe32_creation_round_trips_and_beats_raw_data() {
    let (old, new) = pair(false);
    let plain = raw(&old, &new);
    let patch = create_pa19_with(&old, &new, &with(Pa19Pe::Auto, Pa19E8::Off), &limits()).unwrap();
    assert_eq!(apply_pa19(&old, &patch, &limits()).unwrap(), new);
    let info = inspect_pa19(&patch, &limits()).unwrap();
    assert_eq!(info.coff_base, 0x1000_0000);
    assert_eq!(info.coff_time, 0x6a00_0000);
    assert!(info.sources[0].rift_entries > 0);
    assert!(
        patch.len() * 2 < plain.len(),
        "PE patch {} should be well below raw {}",
        patch.len(),
        plain.len()
    );
    // `On` takes the PE path without trying raw and reaches the same result here.
    let forced = create_pa19_with(&old, &new, &with(Pa19Pe::On, Pa19E8::Off), &limits()).unwrap();
    assert_eq!(apply_pa19(&old, &forced, &limits()).unwrap(), new);
    assert_eq!(forced, patch);
}

#[test]
fn pe32_creation_with_e8_round_trips_for_each_policy() {
    let (old, new) = pair(false);
    for e8 in [Pa19E8::Off, Pa19E8::On, Pa19E8::Auto] {
        let patch = create_pa19_with(&old, &new, &with(Pa19Pe::Auto, e8), &limits()).unwrap();
        assert_eq!(apply_pa19(&old, &patch, &limits()).unwrap(), new, "{e8:?}");
    }
}

#[test]
fn pe32_plus_images_use_the_raw_path() {
    // `mspatcha.dll` transforms PE32 only: a PE32+ pair must produce exactly the raw patch and
    // carry no COFF fields or rift.
    let (old, new) = pair(true);
    let plain = raw(&old, &new);
    for pe in [Pa19Pe::Auto, Pa19Pe::On] {
        let patch = create_pa19_with(&old, &new, &with(pe, Pa19E8::Off), &limits()).unwrap();
        assert_eq!(patch, plain, "{pe:?}");
    }
    let info = inspect_pa19(&plain, &limits()).unwrap();
    assert_eq!((info.coff_base, info.coff_time), (0, 0));
    assert_eq!(info.sources[0].rift_entries, 0);
    assert_eq!(apply_pa19(&old, &plain, &limits()).unwrap(), new);
}

#[test]
fn mixed_pe32_and_raw_inputs_fall_back_to_raw() {
    let (old, new) = pair(false);
    let junk: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
    for (a, b) in [(&old, &junk), (&junk, &new)] {
        let patch = create_pa19_with(a, b, &with(Pa19Pe::On, Pa19E8::Off), &limits()).unwrap();
        assert_eq!(patch, raw(a, b));
        assert_eq!(&apply_pa19(a, &patch, &limits()).unwrap(), b);
    }
}

/// x86-like data: pseudo-random bytes with `E8 rel32` calls whose operands are in range, plus `E8`
/// bytes placed at every offset around the 32768-byte chunk boundaries (including the last ten
/// bytes of a chunk, where the translation must leave them alone).
fn code(random: &mut Random, size: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..size).map(|_| random.next() as u8).collect();
    for _ in 0..size / 300 {
        let from = random.next() as usize % size.max(1);
        let to = random.next() as usize % size.max(1);
        let length = 64.min(size - from.max(to));
        data.copy_within(from..from + length, to);
    }
    let mut at = 0;
    while at + 8 < size {
        data[at] = 0xe8;
        let operand = (random.next() as usize % size) as i32 - at as i32;
        data[at + 1..at + 5].copy_from_slice(&operand.to_le_bytes());
        at += 8 + random.next() as usize % 50;
    }
    let mut boundary = 32768;
    while boundary < size {
        for offset in 0..17 {
            let at = boundary - 14 + offset;
            if at + 5 <= size {
                data[at] = 0xe8;
                let operand = (random.next() as usize % size) as i32;
                data[at + 1..at + 5].copy_from_slice(&operand.to_le_bytes());
            }
        }
        boundary += 32768;
    }
    data
}

fn edited(random: &mut Random, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for _ in 0..data.len() / 5000 + 3 {
        if out.len() < 400 {
            break;
        }
        let at = random.next() as usize % (out.len() - 300);
        match random.next() % 3 {
            0 => out[at] ^= 0x5a,
            1 => {
                out.drain(at..at + 20);
            }
            _ => {
                let insert: Vec<u8> = (0..40).map(|_| random.next() as u8).collect();
                out.splice(at..at, insert);
            }
        }
    }
    out
}

#[test]
fn e8_translation_round_trips_around_chunk_boundaries() {
    let mut random = Random(0xe8e8_1357);
    for size in [
        12usize, 100, 32757, 32758, 32767, 32768, 32769, 32778, 32779, 65526, 65535, 65536, 65537,
        65546, 65547, 98305, 131081, 200_000,
    ] {
        let new = code(&mut random, size);
        let old = edited(&mut random, &new);
        for e8 in [Pa19E8::On, Pa19E8::Auto] {
            let patch = create_pa19_with(&old, &new, &with(Pa19Pe::Off, e8), &limits()).unwrap();
            assert_eq!(
                apply_pa19(&old, &patch, &limits()).unwrap(),
                new,
                "size {size} {e8:?}"
            );
        }
    }
}

/// The first LZX chunk starts with the `E8` flag bit (bit 15 of its first 16-bit word).
fn e8_flag(patch: &[u8]) -> bool {
    let info = inspect_pa19(patch, &limits()).unwrap();
    let start = patch.len() - 4 - info.sources[0].patch_size;
    patch[start + 3] & 0x80 != 0
}

#[test]
fn e8_flag_follows_the_policy() {
    let mut random = Random(99);
    let new = code(&mut random, 70_000);
    let old = edited(&mut random, &new);
    let off = create_pa19_with(&old, &new, &with(Pa19Pe::Off, Pa19E8::Off), &limits()).unwrap();
    let on = create_pa19_with(&old, &new, &with(Pa19Pe::Off, Pa19E8::On), &limits()).unwrap();
    assert!(!e8_flag(&off));
    assert!(e8_flag(&on));
    // With almost no E8 bytes, Auto keeps translation off.
    let plain: Vec<u8> = (0..5000u32).map(|i| (i % 200) as u8).collect();
    let auto =
        create_pa19_with(&plain, &plain, &with(Pa19Pe::Off, Pa19E8::Auto), &limits()).unwrap();
    assert!(!e8_flag(&auto));
}

#[test]
fn e8_with_interleave_groups_round_trips() {
    use ms_delta::pa19::plan_interleave;
    let mut random = Random(4242);
    let new = code(&mut random, 600_000);
    let old = edited(&mut random, &new);
    let options = Pa19CreateOptions {
        window_order: Some(17),
        interleave: plan_interleave(old.len(), new.len(), 17, 131_072),
        e8: Pa19E8::On,
        ..Default::default()
    };
    let patch = create_pa19_with(&old, &new, &options, &limits()).unwrap();
    assert_eq!(apply_pa19(&old, &patch, &limits()).unwrap(), new);
}
