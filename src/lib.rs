//! # POW Account
//!
//! This library generates a cryptographic hash and performs a second round of hashing to produce a hash with a configurable number of leading zeros.
//! It is designed for applications requiring proof-of-work-like functionality or hash-based validation with adjustable difficulty.
//!
//!
//! ## Example Usage
//! ```rust
//! use pow_account::HashFinder;
//!
//! fn main() {
//!     let origin_hash = HashFinder::new(4).find();
//!     let origin_hash_hex = hex::encode(origin_hash);
//!
//!     if let Ok(target_hash_match_result) = HashFinder::new(4).check(origin_hash_hex) {
//!         println!("Result of match: {}", target_hash_match_result);
//!     }
//! }
//! ```
//!
//! ## Additional Information
//! For more details, refer to the [README](https://github.com/1prefix/pow-account/blob/main/README.md).

use blake2::{Blake2s256, Digest};
use rand_core::{OsRng, RngCore};

struct Entropy {
    entropy: [u8; 32],
}

impl Entropy {
    fn new() -> Self {
        let mut entropy = [0u8; 32];
        OsRng::default().fill_bytes(&mut entropy);

        Entropy { entropy }
    }

    fn from(entropy: [u8; 32]) -> Self {
        Entropy { entropy }
    }

    fn hash(&self) -> [u8; 32] {
        let mut hash = Blake2s256::new();
        let _ = hash.update(self.entropy);
        hash.finalize().into()
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
    /// Returns a HashFinder struct with a specified number of target leading zeros
    /// # Example
    /// ```
    /// use pow_account::HashFinder;
    ///
    /// let hash_finder = HashFinder::new(4);
    ///
    /// ```
    pub fn new(leading_zeros: u8) -> Self {
        HashFinder {
            target: HashPrefix::new(leading_zeros).target(),
        }
    }

    /// Finds an origin hash
    ///
    /// This function attempts to find a cryptographic hash that is an origin for a target hash that has a specific number of leading zeroes
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
    /// use blake2::{Blake2s256, Digest};
    ///
    /// let origin_hash = HashFinder::new(4).find();
    ///
    /// let mut hasher = Blake2s256::new();
    /// hasher.update(&origin_hash);
    /// let target_hash: [u8; 32] = hasher.finalize().into();
    ///
    /// let target_hash_hex = hex::encode(target_hash);
    ///
    /// assert!(target_hash_hex.starts_with("0000"));
    /// ```
    pub fn find(&self) -> [u8; 32] {
        loop {
            let origin_hash = Entropy::new().hash();
            let target_hash = Entropy::from(origin_hash).hash();
            match target_hash < self.target {
                true => return origin_hash,
                false => continue,
            }
        }
    }

    /// Determines whether a given hash serves as the origin for a target hash that satisfies a specified number of leading zeros.
    ///
    /// This function takes a hexadecimal string representing an origin hash and checks if
    /// its hash satisfies the leading zero requirement specified by the `leading_zeros` value.
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
    /// let origin_hash = HashFinder::new(4).find();
    /// let origin_hash_hex = hex::encode(origin_hash);
    /// let result = HashFinder::new(3).check(origin_hash_hex);
    /// assert!(result.unwrap());
    ///
    /// let origin_hash = String::from("3ca727c7fefed674268797882ff4b26c8e28873ee6fbfae71d9ccc35e24444d4");
    /// let result = HashFinder::new(3).check(origin_hash);
    /// assert!(result.unwrap());
    ///
    /// let origin_hash = String::from("51ad0600f06b0d57300a37952cea658410488748400628c8a2e7d712892d806e");
    /// let result = HashFinder::default().check(origin_hash);
    /// assert!(result.unwrap());
    /// ```
    pub fn check(&self, origin_hash: String) -> Result<bool, hex::FromHexError> {
        let mut origin_hash_bytes: [u8; 32] = [0u8; 32];
        let _ = hex::decode_to_slice(origin_hash, &mut origin_hash_bytes)?;

        let target_hash_bytes = Entropy::from(origin_hash_bytes).hash();

        Ok(target_hash_bytes < self.target)
    }
}

#[cfg(test)]
mod pow_account {

    use super::*;
    use hex::FromHexError;

    #[test]
    fn new_entropy_has_a_length_of_32() {
        let entropy = Entropy::new().entropy;
        assert!(entropy.len().eq(&32))
    }

    #[test]
    fn new_entropy_is_unique() {
        let entropy_a = Entropy::new().entropy;
        let entropy_b = Entropy::new().entropy;
        assert_ne!(entropy_a, entropy_b)
    }

    #[test]
    fn entropy_generates_256bit_hash() {
        let hash = Entropy::new().hash();
        assert!(hash.len().eq(&32))
    }

    #[test]
    fn entropy_created_from_a_set_of_bytes() {
        let entropy_a = Entropy::new().entropy;
        let entropy_b = Entropy::from(entropy_a);
        assert_eq!(entropy_b.entropy, entropy_a)
    }

    #[test]
    fn blake2s_hash_can_be_validated() {
        let origin_hash = "c37289b48949a7d172346cb3e5600da905f53e7c022d364836dcf57db4de33fa";
        let target_hash = "7478987293e1864fd833ae3607bc99b9b22e7ca39bced21c3b0428bd9c7218ba";

        let origin_hash_vec = hex::decode(origin_hash).unwrap();
        let origin_hash_bytes: [u8; 32] = origin_hash_vec.try_into().unwrap();

        let entropy = Entropy::from(origin_hash_bytes);
        let origin_hash_hex = hex::encode(entropy.hash()).to_string();
        assert_eq!(origin_hash_hex, target_hash)
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
        let origin_hash = HashFinder::new(4).find();
        let target_hash = Entropy::from(origin_hash).hash();

        let hash_hex = hex::encode(target_hash);
        assert!(hash_hex.starts_with("0000"))
    }

    #[test]
    fn checks_the_hash_for_the_required_number_of_leading_zeros() {
        let hash = String::from("3ca727c7fefed674268797882ff4b26c8e28873ee6fbfae71d9ccc35e24444d4");
        assert!(HashFinder::new(3).check(hash).unwrap());

        let hash = String::from("73b8f38be026335eb78946ea30434ff3cee4cff6544d49b4772f80397d40e72f");
        assert!(HashFinder::new(4).check(hash).unwrap());

        let hash = String::from("51ad0600f06b0d57300a37952cea658410488748400628c8a2e7d712892d806e");
        assert!(HashFinder::new(5).check(hash).unwrap());

        let hash = String::from("51ad0600f06b0d57300a37952cea658410488748400628c8a2e7d712892d806e");
        assert!(HashFinder::default().check(hash).unwrap());

        let hash = String::from("3ca727c7fefed674268797882ff4b26c8e28873ee6fbfae71d9ccc35e24444d4");
        assert_eq!(HashFinder::new(4).check(hash).unwrap(), false);

        let hash = String::from("3c+727c7fefed674268797882ff4b26c8e28873ee6fbfae71d9ccc35e24444d4");
        let err = HashFinder::new(4).check(hash).unwrap_err();
        assert_eq!(err, FromHexError::InvalidHexCharacter { c: '+', index: 2 });

        let hash = String::from("3ca727c7fefed674268797882ff4b26c8e28873ee6fbfae71d9ccc35e24444d");
        let err = HashFinder::new(4).check(hash).unwrap_err();
        assert_eq!(err, FromHexError::OddLength);

        let hash =
            String::from("3ca727c7fefed674268797882ff4b26c8e28873ee6fbfae71d9ccc35e24444d444d4");
        let err = HashFinder::new(4).check(hash).unwrap_err();
        assert_eq!(err, FromHexError::InvalidStringLength)
    }
}
