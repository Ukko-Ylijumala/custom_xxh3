// Copyright (c) 2024-2026 Mikko Tanner. All rights reserved.
// License: MIT OR Apache-2.0

use std::{
    error::Error,
    fmt::{self, Debug, Display, Formatter},
    hash::{BuildHasher, BuildHasherDefault, Hash, Hasher, RandomState},
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use xxhash_rust::{
    const_xxh3::const_custom_default_secret,
    xxh3::{xxh3_64, xxh3_64_with_secret, xxh3_64_with_seed, Xxh3, Xxh3Builder},
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
Input size up to which [QuickXxh3Hasher] hashes in one go: the most xxh3
hashes in a single pass, as it processes longer inputs in stripes. The
buffer is left uninitialized, so its size costs nothing up front.
*/
const QUICK_BUF_SIZE: usize = 240;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Xxh3Error {
    /// The secret is not 192 bytes long; holds its actual length.
    InvalidSecretSize(usize),
}

impl Display for Xxh3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretSize(len) => write!(
                f,
                "invalid secret size: {len} bytes, expected {XXH3_SECRET_SIZE}"
            ),
        }
    }
}

impl Error for Xxh3Error {}

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

/**
Build a new [Xxh3] hasher with a given seed and secret.
Secret size must be exactly [XXH3_SECRET_SIZE] bytes (192).

The seed is applied to the secret ([seeded_secret]) instead of being handed
to [Xxh3]: given both, [Xxh3] hashes inputs of up to 240 bytes with its own
default secret, and longer ones without the seed.
*/
fn build_xxh3_with_secret_and_seed(secret: [u8; XXH3_SECRET_SIZE], seed: u64) -> Xxh3 {
    build_xxh3_with_secret(seeded_secret(&secret, seed))
}

/**
Apply `seed` to `secret` the way xxh3 derives a secret from a seed: add it
to the first and subtract it from the second `u64` of each 16-byte block.
A seed of 0 leaves the secret as is.
*/
fn seeded_secret(secret: &[u8; XXH3_SECRET_SIZE], seed: u64) -> [u8; XXH3_SECRET_SIZE] {
    let mut derived: [u8; XXH3_SECRET_SIZE] = *secret;
    let (words, _) = derived.as_chunks_mut::<8>();
    for (i, word) in words.iter_mut().enumerate() {
        let value: u64 = u64::from_le_bytes(*word);
        let value: u64 = match i % 2 {
            0 => value.wrapping_add(seed),
            _ => value.wrapping_sub(seed),
        };
        *word = value.to_le_bytes();
    }
    derived
}

/// Build a new [Xxh3] hasher with our custom secret (`XXH3_SECRET`).
#[inline]
pub fn build_xxh3_with_custom_secret() -> Xxh3 {
    Xxh3Builder::new().with_secret(XXH3_SECRET).build()
}

/* --------------------------------- */

/**
A custom [Xxh3] hasher with a configurable seed and secret. The default
is seed 0 with our custom secret, itself derived from a non-zero seed.

This hasher can be used as a drop-in replacement for the standard
[std::hash::DefaultHasher], with these notable differences:
- it uses the `xxHash3` algorithm instead of `SipHash` (obviously)
- its state can be reset without having to recreate the full hasher
- it can be used as a [BuildHasher] for [HashMap](std::collections::HashMap) and friends
- the hash output is stable by default (no randomization)
- `xxHash3` is extremely fast for hashing large amounts of data

Stable output means that the same bytes always hash the same, on any
platform. Values hashed through their [Hash] impls depend on the bytes
those feed the hasher, which differ between platforms (endianness, `usize`
width) and may change between Rust versions. For a hash that must not
change, e.g. one that is stored, hash the bytes with [hash_bytes] or
[Hasher::write].
*/
#[derive(Clone)]
pub struct CustomXxh3Hasher {
    xxh: Xxh3,
    seed: u64,
    secret: Xxh3Secret,
}

/// The secret a [CustomXxh3Hasher] is built with, kept for [CustomXxh3Hasher::change_seed].
#[derive(Clone)]
enum Xxh3Secret {
    /// Xxh3's own default secret, with any seed applied by [Xxh3] itself.
    Xxh3Default,
    /// [XXH3_SECRET], referred to rather than copied into every hasher.
    Crate,
    Custom([u8; XXH3_SECRET_SIZE]),
}

impl CustomXxh3Hasher {
    /// Create a new [CustomXxh3Hasher] with a given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            xxh: build_xxh3_with_seed(seed),
            seed,
            secret: Xxh3Secret::Xxh3Default,
        }
    }

    /// Create a new [CustomXxh3Hasher] with Xxh3 defaults.
    pub fn new_xxh3_defaults() -> Self {
        Self {
            xxh: Xxh3Builder::new().build(),
            seed: 0,
            secret: Xxh3Secret::Xxh3Default,
        }
    }

    /// Build a Xxh3 hasher with a custom secret
    pub fn with_secret(secret: &[u8]) -> Result<Self, Xxh3Error> {
        let secret: [u8; XXH3_SECRET_SIZE] = validate_secret_size(secret)?;
        Ok(Self {
            xxh: build_xxh3_with_secret(secret),
            seed: 0,
            secret: Xxh3Secret::Custom(secret),
        })
    }

    /// Build a Xxh3 hasher with a custom secret and seed. Both of them
    /// affect the hash of every input, short or long.
    pub fn with_secret_and_seed(secret: &[u8], seed: u64) -> Result<Self, Xxh3Error> {
        let secret: [u8; XXH3_SECRET_SIZE] = validate_secret_size(secret)?;
        Ok(Self {
            xxh: build_xxh3_with_secret_and_seed(secret, seed),
            seed,
            secret: Xxh3Secret::Custom(secret),
        })
    }

    /// Get the seed value used by this hasher.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Get the secret value used by this hasher, if it's not Xxh3's default.
    fn secret(&self) -> Option<&[u8; XXH3_SECRET_SIZE]> {
        match &self.secret {
            Xxh3Secret::Xxh3Default => None,
            Xxh3Secret::Crate => Some(&XXH3_SECRET),
            Xxh3Secret::Custom(secret) => Some(secret),
        }
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

    /**
    Hash multiple items efficiently, continuing from the current state, and
    return the digest. The items go in with [Hash::hash_slice], which feeds
    e.g. a slice of integers to the hasher as one write of all its bytes.
    */
    pub fn hash_batch<T: Hash>(&mut self, items: &[T]) -> u64 {
        T::hash_slice(items, self);
        self.finish()
    }
}

/* --------------------------------- */

impl Default for CustomXxh3Hasher {
    /// A [CustomXxh3Hasher] with the default seed (0) and our custom secret (`XXH3_SECRET`).
    fn default() -> Self {
        Self {
            xxh: build_xxh3_with_secret(XXH3_SECRET),
            seed: 0,
            secret: Xxh3Secret::Crate,
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

    /// Build a fresh [CustomXxh3Hasher] with this one's seed and secret.
    fn build_hasher(&self) -> Self::Hasher {
        let mut hasher: CustomXxh3Hasher = self.clone();
        hasher.xxh.reset();
        hasher
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
            "CustomXxh3Hasher(hash: {}, seed: {}, custom secret: {})",
            self.finish(),
            self.seed,
            self.secret().is_some()
        )
    }
}

#[cfg(feature = "size_of")]
impl SizeOf for CustomXxh3Hasher {
    /// Nothing to add: all of the hasher's state is inline, none on the heap.
    fn size_of_children(&self, _context: &mut Context) {}
}

/* --------------------------------- */

/**
A [Hasher] for hashing one short item at a time, e.g. a digest per element
of a collection. Setting up a streaming [Xxh3] (as in [CustomXxh3Hasher])
costs far more than hashing a few bytes, so this hasher collects the input
in a buffer and hashes it in one go with [hash_bytes]: ~1 ns for a `u64`,
where setting up a [CustomXxh3Hasher] takes ~15 ns. Inputs longer than 240
bytes, which xxh3 can't hash in one pass anyway, spill over into a
[CustomXxh3Hasher].

For the same input, the hash is identical to that of the default
[CustomXxh3Hasher], as the one-shot and streaming forms of xxh3 agree.
With `SEEDED`, made by [QuickXxh3Hasher::new], it is identical to that of
[CustomXxh3Hasher::new] with the same seed. The mode is a type parameter
so that the unused one costs nothing, not even a branch.
*/
#[derive(Clone)]
pub struct QuickXxh3Hasher<const SEEDED: bool = false> {
    /// The input so far; `buf[..len]` is always initialized.
    buf: [MaybeUninit<u8>; QUICK_BUF_SIZE],
    len: usize,
    /// Only used with `SEEDED`.
    seed: u64,
    /// Set once the input no longer fits in `buf`.
    spill: Option<Box<CustomXxh3Hasher>>,
}

impl QuickXxh3Hasher<true> {
    /// Create a new [QuickXxh3Hasher] hashing as [CustomXxh3Hasher::new] with `seed`.
    #[inline]
    pub fn new(seed: u64) -> Self {
        Self::build(seed)
    }
}

impl<const SEEDED: bool> QuickXxh3Hasher<SEEDED> {
    /**
    Built field by field so that `buf` stays uninitialized. From a struct
    literal, whose fields are all constants, the compiler writes the whole
    value with one memset, zeroing `buf` as well.
    */
    #[inline]
    fn build(seed: u64) -> Self {
        let mut hasher: MaybeUninit<Self> = MaybeUninit::uninit();
        let ptr: *mut Self = hasher.as_mut_ptr();
        // SAFETY: every field but buf is written, and buf may be uninitialized
        unsafe {
            (&raw mut (*ptr).len).write(0);
            (&raw mut (*ptr).seed).write(seed);
            (&raw mut (*ptr).spill).write(None);
            hasher.assume_init()
        }
    }

    /// The input written so far, as long as it fits in `buf`.
    #[inline]
    fn buffered(&self) -> &[u8] {
        // SAFETY: write() initializes buf[..len] before extending len over it
        unsafe { self.buf[..self.len].assume_init_ref() }
    }

    /// Move the input so far over to a streaming hasher, and continue there.
    #[cold]
    fn spill(&mut self, bytes: &[u8]) {
        let mut hasher: Box<CustomXxh3Hasher> = Box::new(match SEEDED {
            true => CustomXxh3Hasher::new(self.seed),
            false => CustomXxh3Hasher::default(),
        });
        hasher.write(self.buffered());
        hasher.write(bytes);
        self.spill = Some(hasher);
    }
}

impl Default for QuickXxh3Hasher {
    /// A [QuickXxh3Hasher] hashing as the default [CustomXxh3Hasher].
    #[inline]
    fn default() -> Self {
        Self::build(0)
    }
}

impl<const SEEDED: bool> Hasher for QuickXxh3Hasher<SEEDED> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let end: usize = self.len + bytes.len();
        if let Some(hasher) = &mut self.spill {
            hasher.write(bytes);
        } else if end <= QUICK_BUF_SIZE {
            self.buf[self.len..end].write_copy_of_slice(bytes);
            self.len = end;
        } else {
            self.spill(bytes);
        }
    }

    /**
    Always inlined: for input of a fixed size, e.g. a `u64`, the hash then
    folds down to a few instructions with no buffer at all. LLVM's inliner
    doesn't foresee that, and often keeps it out of line otherwise.
    */
    #[inline(always)]
    fn finish(&self) -> u64 {
        match &self.spill {
            Some(hasher) => hasher.finish(),
            None if SEEDED => xxh3_64_with_seed(self.buffered(), self.seed),
            None => hash_bytes(self.buffered()),
        }
    }
}

impl<const SEEDED: bool> Debug for QuickXxh3Hasher<SEEDED> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "QuickXxh3Hasher(hash: {})", self.finish())
    }
}

#[cfg(feature = "size_of")]
impl<const SEEDED: bool> SizeOf for QuickXxh3Hasher<SEEDED> {
    fn size_of_children(&self, context: &mut Context) {
        if self.spill.is_some() {
            context
                .add(size_of::<CustomXxh3Hasher>())
                .add_distinct_allocation();
        }
    }
}

/**
A [BuildHasher] for `HashMap` and friends, building a [QuickXxh3Hasher]
per operation. The hashes are stable, the same as those of the default
[CustomXxh3Hasher]; for randomized ones, see [RandomXxh3Builder].
*/
pub type QuickXxh3Builder = BuildHasherDefault<QuickXxh3Hasher>;

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
the standard [Hash] trait, e.g. as a `HashMap` key: hashing the wrapper
feeds the value to the hasher with [Xxh3Hashable::xxh3]. As with [Hash],
values equal by [Eq] must feed the hasher the same input.

Example:
```
use custom_xxh3::{QuickXxh3Hasher, Xxh3Hashable, Xxh3Wrapper};
use std::collections::HashMap;
use std::hash::Hasher;

#[derive(PartialEq, Eq)]
struct Point {
    x: u32,
    y: u32,
}

impl Xxh3Hashable for Point {
    fn xxh3<H: Hasher>(&self, state: &mut H) {
        state.write_u32(self.x);
        state.write_u32(self.y);
    }

    fn xxh3_digest(&self) -> u64 {
        let mut hasher = QuickXxh3Hasher::default();
        self.xxh3(&mut hasher);
        hasher.finish()
    }
}

let mut map = HashMap::new();
map.insert(Xxh3Wrapper(Point { x: 1, y: 2 }), "a");
assert_eq!(map[&Xxh3Wrapper(Point { x: 1, y: 2 })], "a");
```
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Xxh3Wrapper<T>(pub T);

impl<T: Xxh3Hashable> Hash for Xxh3Wrapper<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.xxh3(state);
    }
}

/* --------------------------------- */

/**
Randomized hashing, like std's [RandomState]: each builder draws a random
seed once, and builds [QuickXxh3Hasher]s hashing as [CustomXxh3Hasher::new]
with that seed. Unlike SipHash, though, xxh3 is not designed to resist
collisions crafted by an attacker (HashDoS), seeded or not.
*/
#[derive(Clone)]
pub struct RandomXxh3Builder {
    seed: u64,
}

impl RandomXxh3Builder {
    pub fn new() -> Self {
        // Use a RandomState to generate a seed
        let seed: u64 = {
            let mut hasher = RandomState::new().build_hasher();
            hasher.write(&[0; 64]); // Some input to hash
            hasher.finish()
        };
        Self { seed }
    }

    #[inline]
    pub fn build_hasher(&self) -> QuickXxh3Hasher<true> {
        QuickXxh3Hasher::new(self.seed)
    }
}

impl Debug for RandomXxh3Builder {
    /// Leaves the seed out, as [RandomState] does with its keys.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandomXxh3Builder").finish_non_exhaustive()
    }
}

impl Default for RandomXxh3Builder {
    fn default() -> Self {
        Self::new()
    }
}

// Allow using this as a BuildHasher for HashMap
impl BuildHasher for RandomXxh3Builder {
    type Hasher = QuickXxh3Hasher<true>;

    #[inline]
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

/// Hash a byte slice using [Xxh3] "oneshot" `xxh3_64_with_secret()` and our
/// custom secret, generated from the constant seed `0xDEAD_BEEF_FEED_F00D`.
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
uses a [QuickXxh3Hasher], short items (up to 240 bytes of input) are
hashed without setting up a streaming `Xxh3` for each call.
If the item can be represented as a byte slice, [hash_bytes] is still the
most direct way. Note that the hash depends on the item's [Hash] impl; see
[CustomXxh3Hasher] on what stable output covers.
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

/// Validate the secret size for [CustomXxh3Hasher], returning the secret as an array.
#[inline]
fn validate_secret_size(secret: &[u8]) -> Result<[u8; XXH3_SECRET_SIZE], Xxh3Error> {
    secret
        .try_into()
        .map_err(|_| Xxh3Error::InvalidSecretSize(secret.len()))
}

/* ######################################################################### */

/// The README's examples, compiled and run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "size_of")]
    use size_of::TotalSize;

    const TEST_DATA: &[u8] = b"Hello, world!";
    const TEST_SECRET: [u8; XXH3_SECRET_SIZE] = const_custom_default_secret(1);
    /// Input lengths covering each of xxh3's size tiers.
    const TEST_LENGTHS: [usize; 9] = [0, 3, 8, 16, 100, 200, 240, 241, 1000];

    /**
    Hashes of `test_input(len)` by the reference C implementation of xxh3
    (xxHash 0.8.3), to catch any change in them, e.g. with an xxhash-rust
    upgrade. Columns: the default [CustomXxh3Hasher], xxh3's defaults,
    seed 42, [TEST_SECRET], and [TEST_SECRET] with seed 7 (as derived by
    [seeded_secret]).
    */
    #[rustfmt::skip]
    const KNOWN_HASHES: [(usize, [u64; 5]); 9] = [
        (0,    [0x80822ed4294443e6, 0x2d06800538d394c2, 0xb029411ff43d84d2, 0x63b572f6de50a057, 0x5580fbcd07d0887a]),
        (3,    [0x95831261638fd6b6, 0xa9088dda485b481c, 0x3a6eb7a191052c81, 0x962ee7d551766d62, 0x6b010b97f3e3a63b]),
        (8,    [0xc5aac67c7fb41165, 0x60539db630471163, 0x53a895ca319fab31, 0x1f6e9fdca1201186, 0x89d1787ae5f84d83]),
        (16,   [0xf58d560ef36dc2be, 0xb8c859b0f030b585, 0x6b1b54f65d114c69, 0x5e0054478767b7ec, 0x3a51e136ad54394d]),
        (100,  [0xcf601930ae62ddc5, 0xb5937857f0d78c9f, 0x223ce4409957d0ce, 0x8d31013832bcb124, 0x6d498d361ad18589]),
        (200,  [0x4cabd59b24723b7d, 0x746cd0025327bf5b, 0xb04cc37ae5a4a48d, 0x63a59acfaaa20856, 0xa65863891e5c72c6]),
        (240,  [0x3c49c036e345306f, 0x64556dc6b462a6cf, 0x722964f8a7f16de3, 0xe1b013642eaa19d6, 0x66cdc2a808362c40]),
        (241,  [0x56008eff81269e60, 0x8beadd3a8874fe17, 0x59fdc74e63a7aee7, 0x35969643e9fd05d4, 0x87b93dfa8fa26869]),
        (1000, [0x89c60f53be59f9c2, 0x6c4f14bd97bd9e82, 0xf0f163846cbf0c33, 0xed03350ea6a70c2d, 0x6807f2033fa614bc]),
    ];

    fn test_input(len: usize) -> Vec<u8> {
        (0..len).map(|i: usize| (i * 7 + 3) as u8).collect()
    }

    fn digest(mut hasher: CustomXxh3Hasher, input: &[u8]) -> u64 {
        hasher.write(input);
        hasher.finish()
    }

    /// An [Xxh3Hashable] without a [Hash] impl, hashing as its raw bytes.
    struct TestBytes(&'static [u8]);

    impl Xxh3Hashable for TestBytes {
        fn xxh3<H: Hasher>(&self, state: &mut H) {
            state.write(self.0);
        }

        fn xxh3_digest(&self) -> u64 {
            hash_bytes(self.0)
        }
    }

    #[test]
    fn test_default_hash_stability() {
        let mut hasher1 = CustomXxh3Hasher::new_xxh3_defaults();
        let mut hasher2 = CustomXxh3Hasher::new_xxh3_defaults();

        hasher1.write(TEST_DATA);
        hasher2.write(TEST_DATA);

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

        hasher1.write(TEST_DATA);
        hasher2.write(TEST_DATA);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Custom XXH3 hashes should match"
        );
    }

    #[test]
    fn test_known_hashes() {
        for (len, expected) in KNOWN_HASHES {
            let input: Vec<u8> = test_input(len);
            let streaming: [u64; 5] = [
                digest(CustomXxh3Hasher::default(), &input),
                digest(CustomXxh3Hasher::new_xxh3_defaults(), &input),
                digest(CustomXxh3Hasher::new(42), &input),
                digest(CustomXxh3Hasher::with_secret(&TEST_SECRET).unwrap(), &input),
                digest(
                    CustomXxh3Hasher::with_secret_and_seed(&TEST_SECRET, 7).unwrap(),
                    &input,
                ),
            ];
            assert_eq!(streaming, expected, "streaming, {len} bytes");
            assert_eq!(hash_bytes(&input), expected[0], "hash_bytes, {len} bytes");
            assert_eq!(
                hash_bytes_default(&input),
                expected[1],
                "hash_bytes_default, {len} bytes"
            );

            let mut quick: QuickXxh3Hasher = QuickXxh3Hasher::default();
            quick.write(&input);
            assert_eq!(quick.finish(), expected[0], "quick, {len} bytes");
            let mut quick: QuickXxh3Hasher<true> = QuickXxh3Hasher::new(42);
            quick.write(&input);
            assert_eq!(quick.finish(), expected[2], "seeded quick, {len} bytes");
        }
    }

    #[test]
    fn test_seeded_secret_matches_xxh3() {
        let default_secret: [u8; XXH3_SECRET_SIZE] = const_custom_default_secret(0);
        for seed in [0, 1, XXH3_SECRET_SEED, u64::MAX] {
            assert_eq!(
                seeded_secret(&default_secret, seed),
                const_custom_default_secret(seed),
                "seed {seed:#x}"
            );
        }
    }

    #[test]
    fn test_secret_and_seed_both_matter() {
        let other_secret: [u8; XXH3_SECRET_SIZE] = const_custom_default_secret(2);
        let with = |secret: &[u8], seed: u64| -> CustomXxh3Hasher {
            CustomXxh3Hasher::with_secret_and_seed(secret, seed).unwrap()
        };
        for len in TEST_LENGTHS {
            let input: Vec<u8> = test_input(len);
            let expected: u64 = digest(with(&TEST_SECRET, 7), &input);
            assert_ne!(
                digest(with(&other_secret, 7), &input),
                expected,
                "secret ignored, {len} bytes"
            );
            assert_ne!(
                digest(with(&TEST_SECRET, 8), &input),
                expected,
                "seed ignored, {len} bytes"
            );
            assert_eq!(
                digest(with(&TEST_SECRET, 0), &input),
                digest(CustomXxh3Hasher::with_secret(&TEST_SECRET).unwrap(), &input),
                "seed 0 should equal no seed, {len} bytes"
            );
        }
    }

    #[test]
    fn test_change_seed_keeps_secret() {
        let seeded = |secret: &[u8]| -> CustomXxh3Hasher {
            CustomXxh3Hasher::with_secret_and_seed(secret, 5).unwrap()
        };
        // (original, expected after change_seed(5))
        let cases: [(CustomXxh3Hasher, CustomXxh3Hasher); 4] = [
            (CustomXxh3Hasher::default(), seeded(&XXH3_SECRET)),
            (
                CustomXxh3Hasher::with_secret(&TEST_SECRET).unwrap(),
                seeded(&TEST_SECRET),
            ),
            (CustomXxh3Hasher::new(1), CustomXxh3Hasher::new(5)),
            (
                CustomXxh3Hasher::new_xxh3_defaults(),
                CustomXxh3Hasher::new(5),
            ),
        ];
        for (i, (original, expected)) in cases.into_iter().enumerate() {
            let mut changed: CustomXxh3Hasher = original.clone();
            changed.change_seed(5);
            let mut restored: CustomXxh3Hasher = changed.clone();
            restored.change_seed(original.seed());
            for len in TEST_LENGTHS {
                let input: Vec<u8> = test_input(len);
                assert_eq!(
                    digest(changed.clone(), &input),
                    digest(expected.clone(), &input),
                    "case {i}: seed changed, {len} bytes"
                );
                assert_eq!(
                    digest(restored.clone(), &input),
                    digest(original.clone(), &input),
                    "case {i}: seed restored, {len} bytes"
                );
            }
        }
    }

    #[test]
    fn test_build_hasher_keeps_config() {
        let configs: [fn() -> CustomXxh3Hasher; 4] = [
            CustomXxh3Hasher::default,
            || CustomXxh3Hasher::new(42),
            || CustomXxh3Hasher::with_secret(&TEST_SECRET).unwrap(),
            || CustomXxh3Hasher::with_secret_and_seed(&TEST_SECRET, 42).unwrap(),
        ];
        for (i, config) in configs.iter().enumerate() {
            let mut expected: CustomXxh3Hasher = config();
            TEST_DATA.hash(&mut expected);
            // input written to the builder must not carry over to built hashers
            let mut builder: CustomXxh3Hasher = config();
            builder.write(&test_input(300));
            assert_eq!(builder.hash_one(TEST_DATA), expected.finish(), "config {i}");
        }
    }

    #[test]
    fn test_invalid_secret_size() {
        let error: Xxh3Error = CustomXxh3Hasher::with_secret(&[0; 10]).unwrap_err();
        assert_eq!(error, Xxh3Error::InvalidSecretSize(10));
        let error: Box<dyn Error> = Box::new(error);
        assert_eq!(
            error.to_string(),
            "invalid secret size: 10 bytes, expected 192"
        );
    }

    #[test]
    fn test_random_builder_is_consistent() {
        let builder: RandomXxh3Builder = RandomXxh3Builder::new();
        let cloned: RandomXxh3Builder = builder.clone();
        assert_eq!(builder.hash_one(TEST_DATA), builder.hash_one(TEST_DATA));
        assert_eq!(cloned.hash_one(TEST_DATA), builder.hash_one(TEST_DATA));

        // the hashes of CustomXxh3Hasher::new() with the builder's seed
        let mut expected: CustomXxh3Hasher = CustomXxh3Hasher::new(builder.seed);
        TEST_DATA.hash(&mut expected);
        assert_eq!(builder.hash_one(TEST_DATA), expected.finish());
    }

    /// Check that hash_batch() hashes as hashing the items one by one.
    fn check_hash_batch<T: Hash>(items: &[T]) {
        let mut expected: CustomXxh3Hasher = CustomXxh3Hasher::default();
        items.iter().for_each(|item: &T| item.hash(&mut expected));
        let mut hasher: CustomXxh3Hasher = CustomXxh3Hasher::default();
        assert_eq!(hasher.hash_batch(items), expected.finish());
    }

    #[test]
    fn test_hash_batch_matches_items() {
        check_hash_batch(&test_input(1000));
        check_hash_batch(&(0..1000u64).collect::<Vec<u64>>());
        check_hash_batch(&[(1u32, 'a'), (2, 'b')]);
        check_hash_batch(&["", "short", "long ".repeat(100).as_str()]);
    }

    #[test]
    fn test_quick_builder_matches_default() {
        let builder: QuickXxh3Builder = QuickXxh3Builder::default();
        for len in TEST_LENGTHS {
            let input: Vec<u8> = test_input(len);
            let mut expected: CustomXxh3Hasher = CustomXxh3Hasher::default();
            input.hash(&mut expected);
            assert_eq!(builder.hash_one(&input), expected.finish(), "{len} bytes");
        }
    }

    #[test]
    fn test_xxh3_wrapper_uses_xxh3() {
        let wrapped: Xxh3Wrapper<TestBytes> = Xxh3Wrapper(TestBytes(TEST_DATA));
        assert_eq!(hash_item(&wrapped), wrapped.0.xxh3_digest());
    }

    #[cfg(feature = "size_of")]
    #[test]
    fn test_size_of() {
        let size: TotalSize = CustomXxh3Hasher::default().size_of();
        assert_eq!(size.total_bytes(), size_of::<CustomXxh3Hasher>());
        assert_eq!(size.distinct_allocations(), 0);

        let mut quick: QuickXxh3Hasher = QuickXxh3Hasher::default();
        quick.write(&test_input(2 * QUICK_BUF_SIZE));
        let size: TotalSize = quick.size_of();
        assert_eq!(
            size.total_bytes(),
            size_of::<QuickXxh3Hasher>() + size_of::<CustomXxh3Hasher>()
        );
        assert_eq!(size.distinct_allocations(), 1);
    }

    /// Check that the quick hasher hashes as the streaming one, for every length up to 3 buffers.
    fn check_quick_matches_streaming<const SEEDED: bool>(
        new_quick: impl Fn() -> QuickXxh3Hasher<SEEDED>,
        new_streaming: impl Fn() -> CustomXxh3Hasher,
    ) {
        let data: Vec<u8> = test_input(3 * QUICK_BUF_SIZE);
        for len in 0..data.len() {
            let input: &[u8] = &data[..len];
            let expected: u64 = digest(new_streaming(), input);

            let mut quick: QuickXxh3Hasher<SEEDED> = new_quick();
            quick.write(input);
            assert_eq!(
                quick.finish(),
                expected,
                "seeded: {SEEDED}, one write of {len} bytes"
            );

            // several writes, crossing the buffer size at different points
            let mut quick: QuickXxh3Hasher<SEEDED> = new_quick();
            input.chunks(13).for_each(|chunk: &[u8]| quick.write(chunk));
            assert_eq!(
                quick.finish(),
                expected,
                "seeded: {SEEDED}, writes of 13 bytes, {len} in total"
            );
        }
    }

    #[test]
    fn test_quick_hasher_matches_streaming() {
        check_quick_matches_streaming(QuickXxh3Hasher::default, CustomXxh3Hasher::default);
        check_quick_matches_streaming(|| QuickXxh3Hasher::new(42), || CustomXxh3Hasher::new(42));
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

        hasher1.write(TEST_DATA);
        hasher2.write(TEST_DATA);

        assert_ne!(
            hasher1.finish(),
            hasher2.finish(),
            "Random hashes should differ"
        );
    }
}
