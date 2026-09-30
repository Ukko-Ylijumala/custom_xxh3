// Copyright (c) 2024-2025 Mikko Tanner. All rights reserved.
// License: MIT OR Apache-2.0

use std::{
    fmt::{self, Debug, Formatter},
    hash::{BuildHasher, Hash, Hasher, RandomState},
    ops::{Deref, DerefMut},
};
use xxhash_rust::{
    const_xxh3::const_custom_default_secret,
    xxh3::{xxh3_64, xxh3_64_with_secret, Xxh3, Xxh3Builder},
};

#[cfg(feature = "size_of")]
use {
    size_of::{Context, SizeOf},
    std::mem::size_of,
};

const XXH3_SECRET_SIZE: usize = 192;
const XXH3_SECRET_SEED: u64 = 0xDEAD_BEEF_FEED_F00D;
const XXH3_SECRET: [u8; XXH3_SECRET_SIZE] = const_custom_default_secret(XXH3_SECRET_SEED);
/**
Input size up to which [QuickXxh3Hasher] hashes in one go. Its buffer is
zeroed for every hasher, so a larger one costs extra time even for short
inputs: ~3 ns per `u64` with 64 bytes vs ~4 ns with 128.
*/
const QUICK_BUF_SIZE: usize = 64;

#[derive(Debug)]
pub enum Xxh3Error {
    InvalidSecretSize(usize),
}

/// Build a new [Xxh3] hasher with a given seed and Xxh3 default secret.
#[inline]
fn build_xxh3_with_seed(seed: u64) -> Xxh3 {
    Xxh3Builder::new().with_seed(seed).build()
}

/// Build a new [Xxh3] hasher with a given secret (`seed = 0` in this case).
/// Secret size must be exactly [XXH3_SECRET_SIZE] bytes (192).
#[inline]
fn build_xxh3_with_secret(secret: [u8; XXH3_SECRET_SIZE]) -> Xxh3 {
    Xxh3Builder::new().with_secret(secret).build()
}

/// Build a new [Xxh3] hasher with a given seed and secret.
/// Secret size must be exactly [XXH3_SECRET_SIZE] bytes (192).
fn build_xxh3_with_secret_and_seed(secret: [u8; XXH3_SECRET_SIZE], seed: u64) -> Xxh3 {
    Xxh3Builder::new()
        .with_secret(secret)
        .with_seed(seed)
        .build()
}

/// Build a new [Xxh3] hasher with our custom [XXH3_SECRET].
#[inline]
pub fn build_xxh3_with_custom_secret() -> Xxh3 {
    Xxh3Builder::new().with_secret(XXH3_SECRET).build()
}

/* --------------------------------- */

/**
A custom [Xxh3] hasher with a configurable seed (non-zero default
seed is also provided).

This hasher can be used as a drop-in replacement for the standard
[std::hash::DefaultHasher], with these notable differences:
- it uses the `xxHash3` algorithm instead of `SipHash` (obviously)
- its state can be reset without having to recreate the full hasher
- it can be used as a [BuildHasher] for [HashMap] and friends
- the hash output is stable by default (no randomization)
- `xxHash3` is extremely fast for hashing large amounts of data
*/
#[derive(Clone)]
pub struct CustomXxh3Hasher {
    xxh: Xxh3,
    seed: u64,
    custom_secret: Option<[u8; XXH3_SECRET_SIZE]>,
}

impl CustomXxh3Hasher {
    /// Create a new [CustomXxh3Hasher] with a given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            xxh: build_xxh3_with_seed(seed),
            seed,
            custom_secret: None,
        }
    }

    /// Create a new [CustomXxh3Hasher] with Xxh3 defaults.
    pub fn new_xxh3_defaults() -> Self {
        Self {
            xxh: Xxh3Builder::new().build(),
            seed: 0,
            custom_secret: None,
        }
    }

    /// Build a Xxh3 hasher with a custom secret
    pub fn with_secret(secret: &[u8]) -> Result<Self, Xxh3Error> {
        if let Some(value) = validate_secret_size(secret) {
            return value;
        }
        let mut arr = [0u8; XXH3_SECRET_SIZE];
        arr.copy_from_slice(secret);
        Ok(Self {
            xxh: build_xxh3_with_secret(arr),
            seed: 0,
            custom_secret: Some(arr),
        })
    }

    /// Build a Xxh3 hasher with a custom secret and seed
    pub fn with_secret_and_seed(secret: &[u8], seed: u64) -> Result<Self, Xxh3Error> {
        if let Some(value) = validate_secret_size(secret) {
            return value;
        }
        let mut arr = [0u8; XXH3_SECRET_SIZE];
        arr.copy_from_slice(secret);
        Ok(Self {
            xxh: build_xxh3_with_secret_and_seed(arr, seed),
            seed,
            custom_secret: Some(arr),
        })
    }

    /// Get the seed value used by this hasher.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Get the secret value used by this hasher, if it's not the default.
    fn secret(&self) -> Option<&[u8; XXH3_SECRET_SIZE]> {
        self.custom_secret.as_ref()
    }

    /// Return the current hash digest and reset the hasher to its initial state.
    #[inline]
    pub fn reset(&mut self) -> u64 {
        let state: u64 = self.finish();
        self.xxh.reset();
        state
    }

    /// Change the seed value used by this hasher.
    ///
    /// NOTE: all current state **will** be lost.
    pub fn change_seed(&mut self, seed: u64) {
        if self.secret().is_some() {
            *self = Self::with_secret_and_seed(self.secret().unwrap(), seed).unwrap();
        } else {
            *self = Self::new(seed);
        }
    }

    /// Combine this hash with another hash value
    pub fn combine(&mut self, other: u64) {
        self.write_u64(other);
    }

    /// Hash multiple items efficiently
    pub fn hash_batch<T: Hash>(&mut self, items: &[T]) -> u64 {
        for item in items {
            item.hash(self);
        }
        self.finish()
    }
}

/* --------------------------------- */

impl Default for CustomXxh3Hasher {
    /// A [CustomXxh3Hasher] with the default seed (0) and secret [XXH3_SECRET].
    fn default() -> Self {
        Self {
            xxh: build_xxh3_with_secret(XXH3_SECRET),
            seed: 0,
            custom_secret: None,
        }
    }
}

impl Hasher for CustomXxh3Hasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.xxh.write(bytes);
    }

    /**
    Returns the hash value for the values written so far.

    Despite the name, the method does not reset the hasher’s internal state.
    Additional `write()`s will continue from the current value. If you need
    to start a fresh hash value, you will have to `reset()` the hasher.
    */
    #[inline]
    fn finish(&self) -> u64 {
        self.xxh.finish()
    }
}

impl BuildHasher for CustomXxh3Hasher {
    type Hasher = CustomXxh3Hasher;

    /// Build a [CustomXxh3Hasher] with the default seed.
    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

/* --------------------------------- */

impl Deref for CustomXxh3Hasher {
    type Target = Xxh3;

    fn deref(&self) -> &Self::Target {
        &self.xxh
    }
}

impl DerefMut for CustomXxh3Hasher {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.xxh
    }
}

/* --------------------------------- */

impl Debug for CustomXxh3Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CustomXxh3Hasher(hash: {}, seed: {})",
            self.finish(),
            self.seed
        )
    }
}

#[cfg(feature = "size_of")]
impl SizeOf for CustomXxh3Hasher {
    fn size_of_children(&self, context: &mut Context) {
        context
            .add(size_of::<CustomXxh3Hasher>())
            .add_distinct_allocation();
    }
}

/* --------------------------------- */

/**
A [Hasher] for hashing one short item at a time, e.g. a digest per element
of a collection. Setting up a streaming [Xxh3] (as in [CustomXxh3Hasher])
costs far more than hashing a few bytes, so this hasher collects the input
in a buffer and hashes it in one go with [hash_bytes]: ~3 ns for a `u64`,
where setting up a [CustomXxh3Hasher] takes ~18 ns. Inputs longer than 64
bytes spill over into a [CustomXxh3Hasher].

For the same input, the hash is identical to that of the default
[CustomXxh3Hasher], as the one-shot and streaming forms of xxh3 agree.
*/
#[derive(Clone)]
pub struct QuickXxh3Hasher {
    buf: [u8; QUICK_BUF_SIZE],
    len: usize,
    /// Set once the input no longer fits in `buf`.
    spill: Option<Box<CustomXxh3Hasher>>,
}

impl QuickXxh3Hasher {
    /// Move the input so far over to a streaming hasher, and continue there.
    #[cold]
    fn spill(&mut self, bytes: &[u8]) {
        let mut hasher: Box<CustomXxh3Hasher> = Box::default();
        hasher.write(&self.buf[..self.len]);
        hasher.write(bytes);
        self.spill = Some(hasher);
    }
}

impl Default for QuickXxh3Hasher {
    fn default() -> Self {
        Self {
            buf: [0; QUICK_BUF_SIZE],
            len: 0,
            spill: None,
        }
    }
}

impl Hasher for QuickXxh3Hasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let end: usize = self.len + bytes.len();
        if let Some(hasher) = &mut self.spill {
            hasher.write(bytes);
        } else if end <= QUICK_BUF_SIZE {
            self.buf[self.len..end].copy_from_slice(bytes);
            self.len = end;
        } else {
            self.spill(bytes);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        match &self.spill {
            Some(hasher) => hasher.finish(),
            None => hash_bytes(&self.buf[..self.len]),
        }
    }
}

impl Debug for QuickXxh3Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "QuickXxh3Hasher(hash: {})", self.finish())
    }
}

#[cfg(feature = "size_of")]
impl SizeOf for QuickXxh3Hasher {
    fn size_of_children(&self, context: &mut Context) {
        if self.spill.is_some() {
            context
                .add(size_of::<CustomXxh3Hasher>())
                .add_distinct_allocation();
        }
    }
}

/* --------------------------------- */

/**
A trait for types which can hash themselves using the [Xxh3] algorithm.

A recommended way to implement this trait is to use the [CustomXxh3Hasher]
(or for short inputs, the faster [QuickXxh3Hasher]) internally for more
complex types, and [hash_bytes] for simple types which can be represented
as byte slices.
*/
pub trait Xxh3Hashable {
    /// Calculates the xxHash3 value for this item using the provided hasher.
    fn xxh3<H: Hasher>(&self, state: &mut H);
    /// Calculates the xxHash3 value for this item in whichever way
    /// the item / implementation chooses to.
    fn xxh3_digest(&self) -> u64;
}

/**
A wrapper struct for hashing a value that implements [Xxh3Hashable] using
the standard [Hash] trait.

Example:
```ignore
let mut map = HashMap::new();
map.insert(Xxh3Wrapper(my_structure), value);
*/
pub struct Xxh3Wrapper<T>(T);

impl<T: Hash + Xxh3Hashable> Hash for Xxh3Wrapper<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/* --------------------------------- */

/// Add randomized state initialization similar to SipHash
pub struct RandomXxh3Builder(RandomState);

impl RandomXxh3Builder {
    pub fn new() -> Self {
        Self(RandomState::new())
    }

    pub fn build_hasher(&self) -> CustomXxh3Hasher {
        // Use the RandomState to generate a seed
        let seed = {
            let mut hasher = self.0.build_hasher();
            hasher.write(&[0; 64]); // Some input to hash
            hasher.finish()
        };
        CustomXxh3Hasher::new(seed)
    }
}

impl Default for RandomXxh3Builder {
    fn default() -> Self {
        Self::new()
    }
}

// Allow using this as a BuildHasher for HashMap
impl BuildHasher for RandomXxh3Builder {
    type Hasher = CustomXxh3Hasher;

    fn build_hasher(&self) -> Self::Hasher {
        self.build_hasher()
    }
}

/* --------------------------------- */

pub trait Xxh3OptimizedHash {
    /// Provide specialized hashing for specific types
    fn hash_optimized<H: Hasher>(&self, state: &mut H);
}

impl CustomXxh3Hasher {
    /// Fast path for types with optimized implementation
    #[inline]
    pub fn hash_optimized<T: Xxh3OptimizedHash>(&mut self, value: &T) {
        value.hash_optimized(self)
    }
}

/* ########################## UTILITY FUNCTIONS ############################ */

/// Hash a byte slice using [Xxh3] "oneshot" `xxh3_64_with_secret()` and a
/// custom secret generated from constant [XXH3_SEED].
#[inline]
pub fn hash_bytes(bytes: &[u8]) -> u64 {
    xxh3_64_with_secret(bytes, &XXH3_SECRET)
}

/// Hash a byte slice using [Xxh3] "oneshot" `xxh3_64()` and Xxh3 default seed.
#[inline]
pub fn hash_bytes_default(bytes: &[u8]) -> u64 {
    xxh3_64(bytes)
}

/**
A function to hash an item using [Xxh3] as the hasher. The item in
question must implement the [Hash] trait, obviously.

The result is the same as with a default [CustomXxh3Hasher], but as this
uses a [QuickXxh3Hasher], short items (up to 64 bytes of input) are
hashed without setting up a streaming `Xxh3` for each call.
If the item can be represented as a byte slice, [hash_bytes] is still the
most direct way.
*/
#[inline]
pub fn hash_item<T>(item: &T) -> u64
where
    T: Hash,
{
    let mut hasher: QuickXxh3Hasher = QuickXxh3Hasher::default();
    item.hash(&mut hasher);
    hasher.finish()
}

/// Validate the secret size for [CustomXxh3Hasher]
#[inline]
fn validate_secret_size(secret: &[u8]) -> Option<Result<CustomXxh3Hasher, Xxh3Error>> {
    if secret.len() != XXH3_SECRET_SIZE {
        return Some(Err(Xxh3Error::InvalidSecretSize(secret.len())));
    }
    None
}

/* ######################################################################### */

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &[u8] = b"Hello, world!";

    #[test]
    fn test_default_hash_stability() {
        let mut hasher1 = CustomXxh3Hasher::new_xxh3_defaults();
        let mut hasher2 = CustomXxh3Hasher::new_xxh3_defaults();

        hasher1.write(&TEST_DATA);
        hasher2.write(&TEST_DATA);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Default XXH3 hashes should match"
        );
    }

    #[test]
    fn test_custom_hash_stability() {
        let mut hasher1 = CustomXxh3Hasher::default();
        let mut hasher2 = CustomXxh3Hasher::default();

        hasher1.write(&TEST_DATA);
        hasher2.write(&TEST_DATA);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Custom XXH3 hashes should match"
        );
    }

    #[test]
    fn test_quick_hasher_matches_streaming() {
        let data: Vec<u8> = (0..3 * QUICK_BUF_SIZE)
            .map(|i: usize| (i * 7 + 3) as u8)
            .collect();
        for len in 0..data.len() {
            let input: &[u8] = &data[..len];
            let mut streaming: CustomXxh3Hasher = CustomXxh3Hasher::default();
            streaming.write(input);
            let expected: u64 = streaming.finish();

            let mut quick: QuickXxh3Hasher = QuickXxh3Hasher::default();
            quick.write(input);
            assert_eq!(quick.finish(), expected, "one write of {len} bytes");

            // several writes, crossing the buffer size at different points
            let mut quick: QuickXxh3Hasher = QuickXxh3Hasher::default();
            input.chunks(13).for_each(|chunk: &[u8]| quick.write(chunk));
            assert_eq!(
                quick.finish(),
                expected,
                "writes of 13 bytes, {len} in total"
            );
        }
    }

    #[test]
    fn test_hash_item() {
        let items: [&str; 3] = ["", "short", &"long ".repeat(QUICK_BUF_SIZE)];
        for item in items {
            let mut hasher: CustomXxh3Hasher = CustomXxh3Hasher::default();
            item.hash(&mut hasher);
            assert_eq!(hash_item(&item), hasher.finish(), "{} bytes", item.len());
        }
        assert_eq!(hash_item(&42u64), hash_bytes(&42u64.to_ne_bytes()), "u64");
    }

    #[test]
    fn test_random_hashes() {
        let mut hasher1 = RandomXxh3Builder::new().build_hasher();
        let mut hasher2 = RandomXxh3Builder::new().build_hasher();

        hasher1.write(&TEST_DATA);
        hasher2.write(&TEST_DATA);

        assert_ne!(
            hasher1.finish(),
            hasher2.finish(),
            "Random hashes should differ"
        );
    }
}
