use sha3::{Digest as _, Keccak256};

/// Compute the Keccak-256 hash of a byte slice.
pub fn v256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
