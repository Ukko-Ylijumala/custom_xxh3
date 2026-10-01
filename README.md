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
by ~2-2.5x for `u64` keys and ~1.1-1.5x for string keys in benchmarks. `Xxh3HashMap` and
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
| `u64`                      |             4.8 |               1.2 |               14.2 |
| `(u32, u16)`               |             4.0 |               1.5 |               24.6 |
| `(u64, u64, u32)`          |             5.5 |               2.0 |               25.1 |
| `String`, 5-15 chars       |             6.3 |               4.8 |               23.8 |
| `String`, 16-31 chars      |             8.1 |               7.9 |               23.6 |
| `String`, 32-50 chars      |            10.6 |              11.9 |               23.9 |
| `String`, 60-150 chars     |            25.9 |              15.5 |               28.3 |
| `(String 5-15, u64)`       |            10.4 |               7.5 |               26.1 |
| `String`, 1 KiB            |           174.7 |              81.6 |               68.3 |
| `String`, 1 MiB            |          174 µs |             33 µs |              33 µs |

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
