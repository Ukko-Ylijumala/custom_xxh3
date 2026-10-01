// Copyright (c) 2026 Mikko Tanner. All rights reserved.
// License: MIT OR Apache-2.0

/*!
Microbenchmarks behind the README's timings, comparing std's SipHash with
this crate's hashers:
- `per_value`: hashing one value per hasher, as `Hash` and `HashMap` do, for
  the values in the README's Performance table; the time is per value
- `hashmap`: inserting keys into a `HashMap` and looking each one up, with
  each `BuildHasher`; the time is per key

Run with `cargo bench`, a part with e.g. `cargo bench -- per_value/str`. The
values are the same on every run. Pinning the run to one core, e.g. with
`taskset -c 2 cargo bench`, steadies the numbers.
*/

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, Bencher, BenchmarkGroup, Criterion,
};
use custom_xxh3::{CustomXxh3Hasher, QuickXxh3Builder, QuickXxh3Hasher, RandomXxh3Builder};
use std::{
    collections::HashMap,
    hash::{BuildHasher, DefaultHasher, Hash, Hasher, RandomState},
    hint::black_box,
    time::{Duration, Instant},
};

/// Number of values in each `per_value` benchmark, hashed in turn, over and over.
const VALUES: usize = 4096;
/// Number of keys in the `hashmap/u64` benchmark.
const MAP_U64_KEYS: usize = 50_000;
const RNG_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const WARM_UP_TIME: Duration = Duration::from_secs(1);
const MEASUREMENT_TIME: Duration = Duration::from_secs(3);

/// splitmix64, for the same values on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z: u64 = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn u64s(&mut self, count: usize) -> Vec<u64> {
        (0..count).map(|_| self.next()).collect()
    }

    /// `count` strings of lowercase letters, `min..=max` of them each.
    fn strings(&mut self, count: usize, min: usize, max: usize) -> Vec<String> {
        (0..count)
            .map(|_| {
                let len: usize = min + (self.next() as usize) % (max - min + 1);
                (0..len)
                    .map(|_| (b'a' + (self.next() % 26) as u8) as char)
                    .collect()
            })
            .collect()
    }
}

/* ----- per value ----- */

/**
Time hashing one of `values` per iteration, with a new hasher each, going
through them in order. Only the slice is hidden from the optimizer, once per
pass: hiding each value skews the timings, by up to ~7 ns per value, and
unevenly between hashers (see the README's notes on hashing short inputs).
*/
fn hash_each<T: Hash, H: Hasher>(b: &mut Bencher, values: &[T], new: impl Fn() -> H) {
    b.iter_custom(|iters: u64| {
        let mut acc: u64 = 0;
        let mut left: u64 = iters;
        let start: Instant = Instant::now();
        while left > 0 {
            let count: usize = (left as usize).min(values.len());
            for value in black_box(&values[..count]) {
                let mut hasher: H = new();
                value.hash(&mut hasher);
                acc = acc.wrapping_add(hasher.finish());
            }
            left -= count as u64;
        }
        let elapsed: Duration = start.elapsed();
        black_box(acc);
        elapsed
    });
}

/// Benchmark `values` with SipHash and the crate's hashers, as `per_value/name`.
fn per_value_group<T: Hash>(c: &mut Criterion, name: &str, values: &[T]) {
    let mut group: BenchmarkGroup<WallTime> = c.benchmark_group(format!("per_value/{name}"));
    group.bench_function("DefaultHasher", |b: &mut Bencher| {
        hash_each(b, values, DefaultHasher::new)
    });
    group.bench_function("QuickXxh3Hasher", |b: &mut Bencher| {
        hash_each(b, values, QuickXxh3Hasher::new)
    });
    group.bench_function("CustomXxh3Hasher", |b: &mut Bencher| {
        hash_each(b, values, CustomXxh3Hasher::new)
    });
    group.finish();
}

fn per_value(c: &mut Criterion) {
    let mut rng: Rng = Rng(RNG_SEED);
    let ints: Vec<u64> = rng.u64s(VALUES);
    let pairs: Vec<(u32, u16)> = ints
        .iter()
        .map(|&i: &u64| (i as u32, (i >> 40) as u16))
        .collect();
    let triples: Vec<(u64, u64, u32)> = ints
        .iter()
        .map(|&i: &u64| (i, i.rotate_left(17), i as u32))
        .collect();
    let short: Vec<String> = rng.strings(VALUES, 5, 15);
    let mixed: Vec<(String, u64)> = short.iter().cloned().zip(ints.iter().copied()).collect();

    per_value_group(c, "u64", &ints);
    per_value_group(c, "u32_u16", &pairs);
    per_value_group(c, "u64_u64_u32", &triples);
    per_value_group(c, "str_5-15", &short);
    per_value_group(c, "str_16-31", &rng.strings(VALUES, 16, 31));
    per_value_group(c, "str_32-50", &rng.strings(VALUES, 32, 50));
    per_value_group(c, "str_60-150", &rng.strings(VALUES, 60, 150));
    per_value_group(c, "str_5-15_u64", &mixed);
    per_value_group(c, "str_1KiB", &rng.strings(64, 1024, 1024));
    per_value_group(c, "str_1MiB", &rng.strings(4, 1 << 20, 1 << 20));
}

/* ----- HashMap ----- */

/**
Time inserting `keys` into a new `HashMap` with `builder`, and looking each
one up, per key. A map holds at most all of `keys`; it is created, with the
capacity for them, and dropped outside the timing.
*/
fn insert_and_get<K: Copy + Hash + Eq, S: BuildHasher + Clone>(
    b: &mut Bencher,
    keys: &[K],
    builder: &S,
) {
    b.iter_custom(|iters: u64| {
        let mut elapsed: Duration = Duration::ZERO;
        let mut left: u64 = iters;
        while left > 0 {
            let count: usize = (left as usize).min(keys.len());
            let mut map: HashMap<K, usize, S> =
                HashMap::with_capacity_and_hasher(keys.len(), builder.clone());
            let mut acc: usize = 0;
            let start: Instant = Instant::now();
            for (i, key) in keys[..count].iter().enumerate() {
                map.insert(*key, i);
            }
            for key in &keys[..count] {
                acc = acc.wrapping_add(map[key]);
            }
            elapsed += start.elapsed();
            black_box(acc);
            left -= count as u64;
        }
        elapsed
    });
}

/// Benchmark a `HashMap` of `keys` with `RandomState` and the crate's builders, as `hashmap/name`.
fn hashmap_group<K: Copy + Hash + Eq>(c: &mut Criterion, name: &str, keys: &[K]) {
    let mut group: BenchmarkGroup<WallTime> = c.benchmark_group(format!("hashmap/{name}"));
    group.bench_function("RandomState", |b: &mut Bencher| {
        insert_and_get(b, keys, &RandomState::new())
    });
    group.bench_function("QuickXxh3Builder", |b: &mut Bencher| {
        insert_and_get(b, keys, &QuickXxh3Builder::default())
    });
    group.bench_function("RandomXxh3Builder", |b: &mut Bencher| {
        insert_and_get(b, keys, &RandomXxh3Builder::new())
    });
    group.finish();
}

fn hashmap(c: &mut Criterion) {
    let mut rng: Rng = Rng(RNG_SEED);
    let ints: Vec<u64> = rng.u64s(MAP_U64_KEYS);
    let short: Vec<String> = rng.strings(VALUES, 5, 50);
    let long: Vec<String> = rng.strings(VALUES, 60, 150);

    hashmap_group(c, "u64", &ints);
    hashmap_group(
        c,
        "str_5-50",
        &short.iter().map(String::as_str).collect::<Vec<&str>>(),
    );
    hashmap_group(
        c,
        "str_60-150",
        &long.iter().map(String::as_str).collect::<Vec<&str>>(),
    );
}

/* ----- main ----- */

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(WARM_UP_TIME)
        .measurement_time(MEASUREMENT_TIME)
}

criterion_group! {
    name = benches;
    config = config();
    targets = per_value, hashmap
}
criterion_main!(benches);
