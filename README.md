# Customized XXH3 Hasher

A customized hasher built on the high-performance Rust XXH3 hashing algorithm that serves as a drop-in replacement for Rust's standard `DefaultHasher`. This implementation provides both stable (deterministic) and randomized hashing capabilities, with some additional features on top.

## Features

- **Drop-in Replacement**: Should work as a direct replacement of the standard `DefaultHasher`
- **State Resetting**: Unlike standard hashers, state can be reset without recreation
- **Configurable hashing**: Support for both custom seeds and secrets
- **Stable Output**: Deterministic by default with optional randomization

Please note that Xxh3 hashes are *not* cryptographically safe and it should *not* be used for anything
even remotely related to cryptography. The main selling points are performance and repeatable hashing.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
custom_xxh3 = { git = "https://github.com/Ukko-Ylijumala/custom_xxh3" }
```

## Usage

### Basic Usage

```rust
use custom_xxh3::CustomXxh3Hasher;
use std::hash::Hasher;

let mut hasher = CustomXxh3Hasher::default();
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### With Custom Seed

```rust
let mut hasher = CustomXxh3Hasher::new(12345);
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### With Custom Secret

```rust
const SECRET_SIZE: usize = 192;
let secret = [42u8; SECRET_SIZE];
let mut hasher = CustomXxh3Hasher::with_secret(&secret).unwrap();
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### Randomized Hashing

```rust
use xxh3_hasher::RandomXxh3Builder;
use std::hash::BuildHasher;

let builder = RandomXxh3Builder::new();
let mut hasher = builder.build_hasher();
hasher.write(b"Hello, world!");
let hash = hasher.finish();
```

### HashMaps

`QuickXxh3Builder` builds a `QuickXxh3Hasher` per map operation, with stable hashes, while
`RandomXxh3Builder` does the same with a random seed per builder. Both beat std's `RandomState`,
by ~2-2.5x for `u64` keys and ~1.1-1.5x for string keys in benchmarks.

```rust
use custom_xxh3::{QuickXxh3Builder, RandomXxh3Builder};
use std::collections::HashMap;

let mut stable: HashMap<&str, u32, QuickXxh3Builder> = HashMap::default();
stable.insert("key", 1);
let mut random: HashMap<&str, u32, RandomXxh3Builder> = HashMap::default();
random.insert("key", 1);
```

### Batch Processing

```rust
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
let mut hasher = CustomXxh3Hasher::default();
hasher.write(b"First data");
let hash1 = hasher.reset(); // Get hash and reset state
hasher.write(b"Second data");
let hash2 = hasher.finish();
```

## Performance

The XXH3 algorithm is designed for high performance, particularly when dealing with large amounts of data. This implementation maintains those performance characteristics while adding useful features like state management and batch processing.

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
- `RandomXxh3Builder`: Randomization capability provider
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
