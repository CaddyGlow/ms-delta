#![cfg(feature = "pa19")]

//! PA19 creation: patches made by `create_pa19`/`create_pa19_with` must be accepted by
//! `apply_pa19`. The real `mspatcha.dll` also applied 30 such patches on a Windows guest (see
//! the module documentation of `pa19`).

use ms_delta::{
    Error, Limits,
    pa19::{
        Pa19CreateOptions, Pa19InterleaveGroup, apply_pa19, create_pa19, create_pa19_with,
        inspect_pa19, plan_interleave,
    },
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

fn text(random: &mut Random, size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        match random.next() % 3 {
            0 => data
                .extend((0..(10 + random.next() % 50)).map(|_| b'a' + (random.next() % 26) as u8)),
            1 => data.extend((0..(5 + random.next() % 40)).map(|_| random.next() as u8)),
            _ => data.extend(std::iter::repeat_n(
                random.next() as u8,
                20 + (random.next() % 200) as usize,
            )),
        }
    }
    data.truncate(size);
    data
}

fn edited(random: &mut Random, data: &[u8], edits: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    for _ in 0..edits {
        let position = random.next() as usize % (out.len() - 100);
        match random.next() % 3 {
            0 => out[position] ^= 0x5a,
            1 => {
                out.drain(position..position + 30);
            }
            _ => {
                let insert = text(random, 50);
                out.splice(position..position, insert);
            }
        }
    }
    out
}

fn limits() -> Limits {
    Limits::default()
}

#[test]
fn default_patches_round_trip_for_text_binary_and_edge_sizes() {
    let mut random = Random(7);
    let old = text(&mut random, 150_000);
    let new = edited(&mut random, &old, 25);
    let patch = create_pa19(&old, &new, &limits()).unwrap();
    let info = inspect_pa19(&patch, &limits()).unwrap();
    assert_eq!(info.sources.len(), 1);
    assert_eq!(info.target_size, new.len());
    assert_eq!(apply_pa19(&old, &patch, &limits()).unwrap(), new);
    // empty source, empty target, identical files, one byte
    for (old, new) in [
        (Vec::new(), new.clone()),
        (old.clone(), Vec::new()),
        (new.clone(), new.clone()),
        (vec![1], vec![2]),
        (Vec::new(), Vec::new()),
    ] {
        let patch = create_pa19(&old, &new, &limits()).unwrap();
        assert_eq!(apply_pa19(&old, &patch, &limits()).unwrap(), new);
    }
}

#[test]
fn explicit_window_orders_round_trip_even_when_the_old_file_exceeds_the_window() {
    let mut random = Random(9);
    let old = text(&mut random, 300_000);
    let new = edited(&mut random, &old, 30);
    for order in [17u8, 18, 19, 21, 25] {
        let options = Pa19CreateOptions {
            window_order: Some(order),
            ..Default::default()
        };
        let patch = create_pa19_with(&old, &new, &options, &limits()).unwrap();
        let info = inspect_pa19(&patch, &limits()).unwrap();
        assert_eq!(info.window_size, Some(1usize << order));
        assert_eq!(info.options & 0x1_0000, 0x1_0000);
        assert_eq!(
            apply_pa19(&old, &patch, &limits()).unwrap(),
            new,
            "order {order}"
        );
    }
    let bad = Pa19CreateOptions {
        window_order: Some(16),
        ..Default::default()
    };
    assert!(create_pa19_with(&old, &new, &bad, &limits()).is_err());
}

#[test]
fn interleaved_patches_round_trip_with_planned_and_explicit_groups() {
    let mut random = Random(11);
    let old = text(&mut random, 700_000);
    let new = edited(&mut random, &old, 40);
    for group_bytes in [65_536usize, 131_072, 200_000] {
        let groups = plan_interleave(old.len(), new.len(), 17, group_bytes);
        assert!(groups.len() > 2);
        let options = Pa19CreateOptions {
            window_order: Some(17),
            interleave: groups.clone(),
            ..Default::default()
        };
        let patch = create_pa19_with(&old, &new, &options, &limits()).unwrap();
        let info = inspect_pa19(&patch, &limits()).unwrap();
        assert_eq!(info.flags & 0x4000_0000, 0x4000_0000);
        assert_eq!(info.sources[0].interleave_groups, groups.len());
        assert_eq!(info.sources[0].interleave.len(), groups.len());
        let total: u64 = info.sources[0]
            .interleave
            .iter()
            .map(|g| u64::from(g.new_length))
            .sum();
        assert_eq!(total, new.len() as u64);
        assert_eq!(
            apply_pa19(&old, &patch, &limits()).unwrap(),
            new,
            "group {group_bytes}"
        );
    }
    // explicit, overlapping and out-of-order slices
    let explicit = vec![
        Pa19InterleaveGroup {
            old_offset: 300_000,
            old_length: 100_000,
            new_length: 262_144,
        },
        Pa19InterleaveGroup {
            old_offset: 0,
            old_length: 120_000,
            new_length: 131_072,
        },
        Pa19InterleaveGroup {
            old_offset: 250_000,
            old_length: 50_000,
            new_length: 0,
        },
    ];
    let options = Pa19CreateOptions {
        window_order: Some(18),
        interleave: explicit,
        ..Default::default()
    };
    let patch = create_pa19_with(&old, &new, &options, &limits()).unwrap();
    assert_eq!(apply_pa19(&old, &patch, &limits()).unwrap(), new);
}

#[test]
fn invalid_creation_requests_are_rejected() {
    let old = vec![0u8; 100_000];
    let new = vec![1u8; 100_000];
    let beyond = Pa19CreateOptions {
        window_order: Some(17),
        interleave: vec![Pa19InterleaveGroup {
            old_offset: 90_000,
            old_length: 20_000,
            new_length: 0,
        }],
        ..Default::default()
    };
    assert!(matches!(
        create_pa19_with(&old, &new, &beyond, &limits()),
        Err(Error::Invalid(_))
    ));
    let unaligned = Pa19CreateOptions {
        window_order: Some(17),
        interleave: vec![
            Pa19InterleaveGroup {
                old_offset: 0,
                old_length: 1000,
                new_length: 1000,
            },
            Pa19InterleaveGroup {
                old_offset: 0,
                old_length: 1000,
                new_length: 0,
            },
        ],
        ..Default::default()
    };
    assert!(matches!(
        create_pa19_with(&old, &new, &unaligned, &limits()),
        Err(Error::Invalid(_))
    ));
    let small = Limits {
        max_output_bytes: 10,
        ..Limits::default()
    };
    assert!(create_pa19(&old, &new, &small).is_err());
}

#[test]
fn a_created_patch_rejects_the_wrong_old_file_and_damage() {
    let mut random = Random(13);
    let old = text(&mut random, 50_000);
    let new = edited(&mut random, &old, 5);
    let patch = create_pa19(&old, &new, &limits()).unwrap();
    let mut wrong = old.clone();
    wrong[10] ^= 1;
    assert!(apply_pa19(&wrong, &patch, &limits()).is_err());
    let mut damaged = patch.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    assert!(apply_pa19(&old, &damaged, &limits()).is_err());
}
