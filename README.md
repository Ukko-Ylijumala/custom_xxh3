# Customized XXH3 Hasher

A customized hasher built on the high-performance Rust XXH3 hashing algorithm that serves as a drop-in replacement for Rust's standard `DefaultHasher`. This implementation provides both stable (deterministic) and randomized hashing capabilities, with some additional features on top.

## Features

- **Drop-in Replacement**: For std's `DefaultHasher`, `RandomState`, `HashMap` and `HashSet` (see below)
- **State Resetting**: Unlike standard hashers, state can be reset without recreation
- **Configurable hashing**: Support for both custom seeds and secrets
- **Stable Output**: Deterministic by default with optional randomization (see below on what is stable)

Please note that Xxh3 hashes are *not* cryptographically safe and it should *not* be used for anything
even remotely related to cryptography. The main selling points are performance and repeatable hashing.
Nor is the randomized `RandomXxh3Builder` a defence against collisions crafted by an attacker (HashDoS),
as std's SipHash is designed to be.

Stable output means that the same bytes always hash the same, on any platform. Values hashed through
their `Hash` impls (`hash_item()`, or `value.hash(&mut hasher)`) depend on the bytes those feed the hasher,
which differ between platforms (endianness, `usize` width) and may change between Rust versions. For a
hash that must not change, e.g. one that is stored, hash the bytes with `hash_bytes()` or `write()`.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
custom_xxh3 = { git = "https://github.com/Ukko-Ylijumala/custom_xxh3" }
```

## Usage

### Replacing std's Hashing

| std                                 | this crate                                                          |
|-------------------------------------|---------------------------------------------------------------------|
| `DefaultHasher`                     | `QuickXxh3Hasher`, or `CustomXxh3Hasher` for its extras             |
| `RandomState`                       | `RandomXxh3Builder` (its hasher is a seeded `QuickXxh3Hasher<true>`) |
| `BuildHasherDefault<DefaultHasher>` | `QuickXxh3Builder`                                                  |
| `HashMap`, `HashSet`                | `Xxh3HashMap`, `Xxh3HashSet`; randomized: `RandomXxh3HashMap`, `RandomXxh3HashSet` |

`QuickXxh3Hasher` and `CustomXxh3Hasher` hash the same. `QuickXxh3Hasher` is the quicker one for hashing
values one at a time, e.g. `HashMap` keys; `CustomXxh3Hasher` can also be reset and reseeded and take a custom
secret, but it takes ~15 ns to set up and is 832 bytes large. Create the maps and sets with `::default()`, as
`::new()` exists for std's `RandomState` only.

```rust
use custom_xxh3::{QuickXxh3Hasher, Xxh3HashMap};
use std::hash::{Hash, Hasher};

let mut hasher = QuickXxh3Hasher::new(); // was DefaultHasher::new()
"file.txt".hash(&mut hasher);
let digest = hasher.finish();

let mut map: Xxh3HashMap<&str, u64> = Xxh3HashMap::default(); // was HashMap::new()
map.insert("file.txt", digest);
```

### Basic Usage

```rust
use custom_xxh3::CustomXxh3Hasher;
use std::hash::Hasher;

let mut hasher = CustomXxh3Hasher::new();
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### With Custom Seed

```rust
use custom_xxh3::CustomXxh3Hasher;
use std::hash::Hasher;

let mut hasher = CustomXxh3Hasher::with_seed(12345);
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### With Custom Secret

The secret must be 192 bytes that look random: derive it from a seed of your own as below (this needs
`xxhash-rust` with its `const_xxh3` feature as a dependency), or generate it with a proper random number
generator. A patterned secret weakens the hash badly: with `[42; 192]`, for one, any 8 bytes of `*`
(0x2a) in the input make the hash ignore the 8 bytes after them.

```rust
use custom_xxh3::CustomXxh3Hasher;
use std::hash::Hasher;
use xxhash_rust::const_xxh3::const_custom_default_secret;

const SECRET: [u8; 192] = const_custom_default_secret(0x0123_4567_89AB_CDEF);
let mut hasher = CustomXxh3Hasher::with_secret(&SECRET).unwrap();
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### Randomized Hashing

```rust
use custom_xxh3::RandomXxh3Builder;
use std::hash::Hasher;

let builder = RandomXxh3Builder::new();
let mut hasher = builder.build_hasher();
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### HashMaps

`QuickXxh3Builder` builds a `QuickXxh3Hasher` per map operation, with stable hashes, while
`RandomXxh3Builder` does the same with a random seed per builder. Both beat std's `RandomState`,
by ~2.5x for `u64` keys and ~1.3x for string keys (see Performance). `Xxh3HashMap` and
`Xxh3HashSet` are `HashMap` and `HashSet` with `QuickXxh3Builder`, `RandomXxh3HashMap` and
`RandomXxh3HashSet` with `RandomXxh3Builder`.

```rust
use custom_xxh3::{QuickXxh3Builder, RandomXxh3HashSet, Xxh3HashMap};
use std::collections::HashMap;

let mut stable: HashMap<&str, u32, QuickXxh3Builder> = HashMap::default();
stable.insert("key", 1);
let mut same: Xxh3HashMap<&str, u32> = Xxh3HashMap::default();
same.insert("key", 1);
let random: RandomXxh3HashSet<u64> = (0..100).collect();
```

### Batch Processing

```rust
use custom_xxh3::CustomXxh3Hasher;

let data = vec!["item1", "item2", "item3"];
let mut hasher = CustomXxh3Hasher::default();
let hash = hasher.hash_batch(&data);
```

### Hashing Many Small Items

Setting up a streaming hasher costs more than hashing a few bytes. For one digest per item, e.g.
per element of a collection, `hash_item()` uses a `QuickXxh3Hasher`, which buffers up to 240 bytes
of input and hashes them in one go (~1 ns for a `u64` vs ~15 ns with a new `CustomXxh3Hasher`).
The hashes are identical to those of the default `CustomXxh3Hasher`.

```rust
use custom_xxh3::{hash_item, QuickXxh3Hasher};
use std::hash::{Hash, Hasher};

let digest = hash_item(&("file.txt", 42u64));

let mut hasher = QuickXxh3Hasher::default();
"file.txt".hash(&mut hasher);
assert_eq!(hasher.finish(), hash_item(&"file.txt"));
```

### State Reset

```rust
use custom_xxh3::CustomXxh3Hasher;
use std::hash::Hasher;

let mut hasher = CustomXxh3Hasher::default();
hasher.write(b"First data");
let hash1 = hasher.reset(); // Get hash and reset state
hasher.write(b"Second data");
let hash2 = hasher.finish();
```

## Performance

The XXH3 algorithm is designed for high performance, particularly when dealing with large amounts of data. This implementation maintains those performance characteristics while adding useful features like state management and batch processing.

Hashing one value per hasher with `Hash`, as `HashMap` keys or a digest per item do (ns per value, on an
AMD Zen 3 machine; see the notes on hashing short inputs below):

| Value                      | `DefaultHasher` | `QuickXxh3Hasher` | `CustomXxh3Hasher` |
|----------------------------|----------------:|------------------:|-------------------:|
| `u64`                      |             4.7 |               1.2 |               15.0 |
| `(u32, u16)`               |             3.9 |               1.6 |               24.5 |
| `(u64, u64, u32)`          |             5.9 |               1.9 |               25.7 |
| `String`, 5-15 chars       |             6.5 |               5.0 |               24.1 |
| `String`, 16-31 chars      |             8.3 |               8.3 |               23.8 |
| `String`, 32-50 chars      |            10.7 |              12.5 |               23.9 |
| `String`, 60-150 chars     |            25.7 |              16.9 |               28.7 |
| `(String 5-15, u64)`       |            10.3 |               7.8 |               26.3 |
| `String`, 1 KiB            |           153.5 |              85.0 |               70.9 |
| `String`, 1 MiB            |          151 µs |             34 µs |              35 µs |

Inserting each key into a `HashMap` and looking it up (ns per key):

| Keys                         | `RandomState` | `QuickXxh3Builder` | `RandomXxh3Builder` |
|------------------------------|--------------:|-------------------:|--------------------:|
| 50K `u64`                    |          30.8 |               11.8 |                12.2 |
| 4096 `&str`, 5-50 chars      |          52.4 |               40.6 |                42.9 |
| 4096 `&str`, 60-150 chars    |          89.9 |               66.9 |                70.2 |

These are the medians of the Criterion benchmarks in `benches/hashing.rs`, which `cargo bench` runs, or a
group of them with e.g. `cargo bench -- per_value` or `cargo bench -- hashmap/u64`. Pinning the run to one
core, e.g. with `taskset -c 2 cargo bench`, steadies the numbers, and Criterion reports how each one changed
since the previous run.

## Optional Features

### Size Tracking

Enable the `size_of` feature to track memory usage:

```toml
[dependencies]
custom_xxh3 = { git = "https://github.com/Ukko-Ylijumala/custom_xxh3", features = ["size_of"] }
```

## Implementation Details

The hasher is built around these core components:

- `CustomXxh3Hasher`: Main hasher implementation
- `QuickXxh3Hasher`: Buffered one-shot hasher for short inputs, with the same results
- `QuickXxh3Builder`: `BuildHasher` of `QuickXxh3Hasher`s, for `HashMap` and friends
- `RandomXxh3Builder`: Randomization capability provider
- `Xxh3HashMap`, `Xxh3HashSet`, `RandomXxh3HashMap`, `RandomXxh3HashSet`: `HashMap` and `HashSet` with the builders
- `Xxh3Hashable`: Trait for self-hashing types

The default configuration uses a custom secret generated with `0xDEAD_BEEF_FEED_F00D` as seed for consistent hashing across instances.

## Notes on Hashing Short Inputs

How `QuickXxh3Hasher` hashes short inputs came out of measuring a number of approaches, on an AMD Zen 3 CPU
with Rust 1.97 (LLVM 22). The effects below depend on the CPU's store-to-load forwarding and on LLVM's
inlining heuristics, so another CPU or compiler version may well behave differently: these notes are for
re-checking, not settled facts. The timings are per value, one hasher each, over 4096 varied values, the
best of 11-15 runs pinned to one core, against v0.4.3. The counters are the CPU's, with `perf stat -e
instructions:u,ls_stlf,ls_bad_status2.stli_other` (store-forwarded loads, and loads blocked from it). As
the variants' code layout shifts timings by up to ~20% between benchmark builds, they were compared within
one binary, interleaved. The `per_value` benchmarks (`cargo bench -- per_value`) cover the same values for
re-checking. Note that hiding each value from the optimizer with `black_box()`, rather than the slice of
them, skews the timings, and unevenly: SipHash's `u64` went from 4.7 to 8.4 ns, `QuickXxh3Hasher`'s from 1.2
to 1.7 ns, and its `(u64, u64, u32)` from 1.9 to 8.6 ns, no longer folding.

### The problem: reads straddling writes

xxh3 hashes up to 240 bytes in one pass over the whole input, so a hasher fed by several `write()`s has to
collect the input first. Collected in a memory buffer and hashed right after, short inputs are slow: xxh3
reads them as overlapping 8-byte words from both ends, and these reads straddle the stores that just
wrote the bytes. The CPU cannot forward stored bytes to a load spanning several stores, so the load waits
for the stores to reach the cache, some 20-30 cycles. Hashing 26 bytes this way took ~8 ns more than
hashing them in place (1.8 ns), with the counters showing the blocked loads. How the bytes were copied
(`memcpy`, 8- or 16-byte chunks, overlapping front and back copies as xxh3 reads them) made no difference.

### What works: the input in registers

Up to 32 bytes, `QuickXxh3Hasher` keeps the input in two `u128`s, which writes are shifted into, and hashes
it with xxh3's 0-32 byte paths ported to work on them (`xxh3_small()`). Nothing is read back from memory,
so nothing waits, and for input of a fixed size, e.g. a `u64` or a tuple of integers, the hash folds down to
a few dozen instructions. This hinges on what the compiler inlines, which LLVM gets wrong on its own:
- `finish()` is `#[inline(always)]`: LLVM rated it too costly (cost 3070 vs a threshold of 325), not
  foreseeing that a known input length folds most of it away. Out of line, the input goes through memory.
- `write()` is `#[inline(always)]` too, but holds the path for up to 16 bytes only; the rest is in
  `write_long()`, which LLVM leaves out of line. Any more inlined code slows down the shortest inputs.
- `write_u8()` appends a byte straight into the registers, so the 0xff that ends every `str` stays out of
  `write_long()`.
- The hasher is built field by field: from a struct literal of constants, rustc writes the whole value with
  one memset, which zeroes the uninitialized 240-byte buffer as well.

### What did not work

1. **A buffer of 8-byte words**: the input stored as whole aligned words plus a partial word in a register,
   with xxh3's 17-240 byte paths ported to read back the whole words and build their unaligned windows with
   shifts, so that no read straddles a write. The word handling made `write()` too big for LLVM to inline, and
   with the hasher's state passed through memory between functions, it was 2-4x slower everywhere (a `u64`
   5.7 ns vs 1.1); with `write()` split to stay inlined, still 1.6-2.5x slower for strings of 16-150 chars.
   Blocked loads went up rather than down (8.4 vs 5.0 per 26-byte string), with 324 instructions vs 93.
2. **32-byte registers, all handled in the inlined `write()`**: strings of 16-31 chars got faster (10.7 to
   8.1 ns), but those of 5-15 chars slower (4.9 to 7.9 ns). The bigger inlined code made LLVM spill the
   hasher's state to the stack: 142 instructions per short string vs 96, store-forwarded loads 5 vs 2.
3. **The same with a separate path for up to 16 bytes in `write()`**: short strings still slower (7.2 ns),
   the 32-byte code being inlined next to it.
4. **The 17-32 byte code in out-of-line functions taking the registers by value**, not `&self`, to keep the
   state out of memory: the calls cost more than they saved (297 instructions per 16-31 char string vs
   172), and fixed-size values no longer folded.
5. **v0.4.3's `write()`, plus an out-of-line function taking `&mut self` for writes of 17-32 bytes**: a
   reference to the hasher passed to a function that isn't inlined puts its state in memory. A `(u32, u16)`
   went from 1.5 to 2.9 ns, strings of 16-31 chars to 13.3 ns.
6. **`write()` with a mere `#[inline]`**: LLVM then inlines it depending on the call site, and fixed-size
   values lose their folding where it doesn't (260 instructions for a `(u64, u64, u32)` vs 29).
7. **More cases in the inlined `write()`**, e.g. a first write of 17-32 bytes, or one landing wholly in the
   upper `u128`: ~130 instructions per short string vs ~80.
8. **`write_long()` forced inline, or kept from inlining**: inlined, short strings took 7.2 ns, and a
   `(u64, u64, u32)` 4.9 ns vs 1.9; never inlined, more instructions for everything past 16 bytes (217 vs
   165 per 16-31 char string).
9. **More cases in `write_u8()`**: a full `match` on the length, or appending to the buffer past 32 bytes,
   made short strings slower (6.4 and 7.3 ns, vs 4.4 and 4.9 without). Only the register cases pay off.

### What is left

Strings of 32-50 chars are hashed from the buffer and still hit the stalls: ~11-12 ns, against ~10.6 ns with
SipHash. Longer ones are 3-10% slower than in v0.4.3 (up to 20% in one benchmark build), for the extra
call to `write_long()` per string, but still ~1.6x faster than SipHash. Every way found to avoid the stalls
for them added inlined code, which slowed down the shorter inputs.

## Safety and Validation

The implementation includes some error handling and validation:
- Secret size validation
- Some test coverage

## License

Copyright (c) 2024-2026 Mikko Tanner. All rights reserved.

License: MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Version History

- 0.4.4: Faster hashing of 17-32 byte inputs, and benchmarks
    - `QuickXxh3Hasher` keeps inputs of up to 32 bytes in registers (was 16): ~4x faster for values of 17-32 bytes,
      e.g. a few integer fields, ~25% for strings of 16-31 chars, same hashes. Strings past 32 chars ~3-10% slower
    - Notes in the README on the approaches tried for hashing short inputs, and why most did not work
    - Criterion benchmarks behind the README's timings: `cargo bench`
- 0.4.3: Drop-in replacement for std's hashing
    - `new()` builds the default hasher, as `DefaultHasher::new()` does. **API change:** the seeded constructors are
      now `with_seed(seed)`, on `CustomXxh3Hasher` and `QuickXxh3Hasher`
    - `QuickXxh3Hasher` hashes inputs of up to 16 bytes from a register: ~5x faster for small multi-field values,
      ~2x for strings of up to 15 chars, same hashes
    - `Xxh3HashMap`, `Xxh3HashSet`, `RandomXxh3HashMap` and `RandomXxh3HashSet` aliases
    - Docs on which type replaces which of std's, with timings against `DefaultHasher`
- 0.4.2: Docs and tests, no changes in behavior
    - Known-answer tests: the hashes match the reference C implementation of xxh3
    - The README examples are fixed and run as doctests; the custom secret example no longer uses a weak secret
    - The docs say what stable output covers (bytes, not values hashed through their `Hash` impls)
- 0.4.1: Faster hashing
    - `QuickXxh3Hasher` hashes up to 240 bytes in one go (was 64): ~2.7x faster for items of 65-240 bytes, ~2x for a
      `u64`, same hashes
    - `QuickXxh3Hasher::new(seed)`, a seeded mode hashing as `CustomXxh3Hasher::new(seed)`
    - `RandomXxh3Builder` draws its seed once and builds quick hashers: ~40x faster per hash, same hashes. A `HashMap`
      with it is now ~2-2.5x faster than with std's `RandomState` for `u64` keys. **API change:** `build_hasher()`
      returns a `QuickXxh3Hasher<true>` instead of a `CustomXxh3Hasher`
    - `QuickXxh3Builder`, a `BuildHasher` of `QuickXxh3Hasher`s with stable hashes
    - `hash_batch()` hashes a slice of integers in one write: ~16x faster, same hashes
    - Requires Rust 1.93
- 0.4.0: Correctness fixes
    - `with_secret_and_seed()`: both the secret and the seed now affect every input; the secret used to be ignored for
      inputs up to 240 bytes, the seed for longer ones. **Changes its hashes for non-zero seeds**
    - `change_seed()` on a default hasher keeps the crate's custom secret. **Changes the hashes after it**
    - A `CustomXxh3Hasher` used as a `BuildHasher` builds hashers with its own seed and secret, not the defaults
    - `Xxh3Wrapper` can be built outside the crate, hashes via `Xxh3Hashable::xxh3()` and works as a `HashMap` key
    - `SizeOf` no longer counts a `CustomXxh3Hasher` twice
    - `Xxh3Error` implements `Display` and `Error`, `RandomXxh3Builder` is `Clone`
- 0.3.1: Faster hashing of small items
    - `QuickXxh3Hasher` for short inputs, used by `hash_item()`: ~6x faster for small items, same hashes
- 0.3.0: Initial library version
    - Basic XXH3 implementation
    - Custom seed and secret support
    - Randomization capabilities
    - Batch processing
    - Optional size tracking

This library started its life as a component of a larger application, but at some point it made more sense to
separate the code into its own little project and here we are.
