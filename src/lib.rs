//! # POW Account
//!
//! This library generates leading-zero hashes for password-less authentication and DDoS protection.
//!
//! ## Key Features
//! - Password-less authentication.
//! - No identity disclosure (no email, phone numbers, etc.).
//! - Protection from DDoS attacks using proof-of-work.
//!
//! ## Example Usage
//! ```rust
//! use pow_account::HashFinder;
//!
//! fn main() {
//!     let hash = HashFinder::new(4).find();
//!     let hash_hex = hex::encode(hash);
//!
//!     assert!(hash_hex.starts_with("0000"));
//!     println!("Generated hash with 4 leading zeros: {}", hash_hex);
//!
//!     if let Ok(mathc_result) = HashFinder::new(4).check(hash_hex) {
//!         println!("Result of match: {}", mathc_result);
//!     }
//! }
//! ```
//!
//! ## Additional Information
//! For more details, refer to the [README](https://github.com/1prefix/pow-account/blob/main/README.md).

use blake2::{Blake2s256, Digest};
use rand_core::{OsRng, RngCore};

struct Hasher {
    hash: [u8; 32],
}

impl Hasher {
    fn new() -> Self {
        Hasher { hash: [0u8; 32] }
    }

    fn get(self) -> [u8; 32] {
        self.hash
    }

    fn fill(mut self) -> Self {
        self.hash = self.new_hash();
        self
    }

    fn new_hash(&self) -> [u8; 32] {
        let mut hash = Blake2s256::new();
        let entropy = Entropy::new().get();
        let _ = hash.update(entropy);
        hash.finalize().into()
    }
}

struct Entropy {
    entropy: [u8; 32],
}

impl Entropy {
    fn new() -> Self {
        let mut entropy = [0u8; 32];
        OsRng::default().fill_bytes(&mut entropy);

        Entropy { entropy }
    }

    fn get(self) -> [u8; 32] {
        self.entropy
    }
}

struct HashPrefix {
    zero_bits: u8,
}

impl Default for HashPrefix {
    fn default() -> Self {
        HashPrefix { zero_bits: 20u8 }
    }
}

impl HashPrefix {
    fn new(leading_zeros: u8) -> Self {
        HashPrefix {
            zero_bits: 8 / 2 * leading_zeros,
        }
    }
}

impl HashPrefix {
    fn get(&self) -> u8 {
        self.zero_bits
    }

    fn target(&self) -> [u8; 32] {
        let target: [u8; 16] = self.target_u128().to_be_bytes();
        let mut array: [u8; 32] = [255u8; 32];
        array[0..16].copy_from_slice(target.as_slice());
        array
    }

    fn target_u128(&self) -> u128 {
        let total_bits = 128;
        let remaining_bits = total_bits - self.get();

        match self.get() < total_bits {
            true => (1u128 << remaining_bits) - 1,
            false => 1,
        }
    }
}

/// `HashFinder` is a Structure for finding cryptographic hashes that meet a specified difficulty target, defined by a number of leading zeros.
/// The core idea is to search for a hash that is lower than a computed target value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashFinder {
    target: [u8; 32],
}

impl Default for HashFinder {
    fn default() -> Self {
        HashFinder {
            target: HashPrefix::default().target(),
        }
    }
}

impl HashFinder {
    /// Returns a hash with a custom number of leading zeros
    /// # Example
    /// ```
    /// use pow_account::HashFinder;
    ///
    /// let hash = HashFinder::new(4).find();
    /// let hash_hex = hex::encode(hash);
    ///
    /// assert!(hash_hex.starts_with("0000"));
    /// ```
    pub fn new(leading_zeros: u8) -> Self {
        HashFinder {
            target: HashPrefix::new(leading_zeros).target(),
        }
    }

    /// Generates a hash with a specific number of leading zeros.
    ///
    /// This function attempts to find a cryptographic hash with a number of leading
    /// zeros specified by the `leading_zeros` argument.
    ///
    /// # Parameters
    ///
    /// - `leading_zeros`: The number of leading zeros to generate in the hash.
    ///
    /// # Returns
    ///
    /// This function returns a 32-byte array containing the generated hash.
    ///
    /// # Example
    ///
    /// ```rust
    /// use pow_account::HashFinder;
    ///
    /// let hash_finder = HashFinder::new(4);
    /// let hash = hash_finder.find();
    /// let hash_hex = hex::encode(hash);
    /// assert!(hash_hex.starts_with("0000"));
    /// ```
    pub fn find(&self) -> [u8; 32] {
        loop {
            let hash = Hasher::new().fill().get();
            match hash < self.target {
                true => return hash,
                false => continue,
            }
        }
    }

    /// Verifies whether a given hash meets the required number of leading zeros.
    ///
    /// This function takes a hexadecimal string representing a hash and checks if
    /// it satisfies the leading zero requirement specified by the `leading_zeros` value.
    ///
    /// # Parameters
    ///
    /// - `hash`: A string containing the hexadecimal representation of the hash to check.
    ///
    /// # Returns
    ///
    /// This function returns `Ok(true)` if the hash meets the requirement, otherwise
    /// it returns `Ok(false)`. If the input string is not a valid hexadecimal representation,
    /// it returns an `Err` with a description of the error.
    ///
    /// # Errors
    ///
    /// This function returns an error if the provided hash string is not a valid
    /// hexadecimal representation.
    ///
    /// # Examples
    /// ```
    /// use pow_account::HashFinder;
    ///
    /// let hash = String::from("000129a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe678");
    /// let result = HashFinder::new(3).check(hash);
    /// assert!(result.unwrap());
    ///
    /// let hash = String::from("000009a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe678");
    /// let result = HashFinder::default().check(hash);
    /// assert!(result.unwrap());
    /// ```
    pub fn check(&self, hash: String) -> Result<bool, hex::FromHexError> {
        let mut buffer: [u8; 32] = [0u8; 32];
        let _ = hex::decode_to_slice(hash, &mut buffer)?;

        Ok(buffer < self.target)
    }
}

#[cfg(test)]
mod pow_account {

    use hex::FromHexError;

    use super::*;

    #[test]
    fn new_hash_has_a_length_of_32_bytes() {
        let hasher = Hasher::new();
        assert!(hasher.get().len().eq(&32))
    }

    #[test]
    fn fills_the_empty_hash() {
        let hasher = Hasher::new().fill();
        assert!(hasher.get().len() > 0)
    }

    #[test]
    fn generated_hashes_are_unique() {
        let hasher_a = Hasher::new().fill();
        let hasher_b = Hasher::new().fill();

        assert_ne!(hasher_a.get(), hasher_b.get())
    }

    #[test]
    fn new_entropy_has_a_length_of_32() {
        let entropy = Entropy::new().get();
        assert!(entropy.len().eq(&32))
    }

    #[test]
    fn new_entropy_is_unique() {
        let entropy_a = Entropy::new().get();
        let entropy_b = Entropy::new().get();
        assert_ne!(entropy_a, entropy_b)
    }

    #[test]
    fn new_hash_prefix_has_non_zero_number_of_bits() {
        let hash_prefix = HashPrefix::default();
        assert!(hash_prefix.get() > 0)
    }

    #[test]
    fn default_target_matches_max_value() {
        let target = HashPrefix::default().target();
        let max_target: [u8; 32] = [
            0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];

        assert_eq!(target, max_target)
    }

    #[test]
    fn can_find_a_hash_which_starts_from_a_specific_pattern() {
        let hash = HashFinder::new(4).find();
        let hash_hex = hex::encode(hash);

        assert!(hash_hex.starts_with("0000"))
    }

    #[test]
    fn checks_the_hash_for_the_required_number_of_leading_zeros() {
        let hash = String::from("000009a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe678");
        assert!(HashFinder::new(4).check(hash).unwrap());

        let hash = String::from("002129a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe678");
        assert_eq!(HashFinder::new(4).check(hash).unwrap(), false);

        let hash = String::from("00+129a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe678");
        let err = HashFinder::new(4).check(hash).unwrap_err();
        assert_eq!(err, FromHexError::InvalidHexCharacter { c: '+', index: 2 });

        let hash = String::from("002129a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe67");
        let err = HashFinder::new(4).check(hash).unwrap_err();
        assert_eq!(err, FromHexError::OddLength);

        let hash =
            String::from("002129a152773d97be21a10987653c1ac45dd774f0a7814584a0c13baf2fe672fe67");
        let err = HashFinder::new(4).check(hash).unwrap_err();
        assert_eq!(err, FromHexError::InvalidStringLength)
    }
}
