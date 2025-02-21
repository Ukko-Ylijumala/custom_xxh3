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

### Batch Processing

```rust
let data = vec!["item1", "item2", "item3"];
let mut hasher = CustomXxh3Hasher::default();
let hash = hasher.hash_batch(&data);
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
- `RandomXxh3Builder`: Randomization capability provider
- `Xxh3Hashable`: Trait for self-hashing types

The default configuration uses a custom secret generated with `0xDEAD_BEEF_FEED_F00D` as seed for consistent hashing across instances.

## Safety and Validation

The implementation includes some error handling and validation:
- Secret size validation
- Some test coverage

## License

Copyright (c) 2024-2025 Mikko Tanner. All rights reserved.

License: MIT OR Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Version History

- 0.3.0: Initial library version
    - Basic XXH3 implementation
    - Custom seed and secret support
    - Randomization capabilities
    - Batch processing
    - Optional size tracking

This library started its life as a component of a larger application, but at some point it made more sense to
separate the code into its own little project and here we are.
