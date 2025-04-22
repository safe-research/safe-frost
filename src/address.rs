use crate::{fmt::Hex, keccak};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use std::{
    fmt::{self, Display, Formatter},
    str,
};

/// Ethereum public address.
pub struct Address([u8; 20]);

impl Address {
    /// Compute the public address from a public verifying key.
    pub fn from_key(pubkey: &frost::VerifyingKey) -> Self {
        let p = pubkey.to_element().to_affine().to_encoded_point(false);
        let bytes = keccak::v256(&p.as_bytes()[1..])[12..].try_into().unwrap();
        Self(bytes)
    }

    /// Returns the address as a slice of bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let addr = format!("{}", Hex(&self.0));
        let digest = keccak::v256(addr.as_bytes());
        let mut checksummed = *b"0x0000000000000000000000000000000000000000";
        for (i, (c, a)) in checksummed[2..].iter_mut().zip(addr.as_bytes()).enumerate() {
            let byte = digest[i / 2];
            let nibble = 0xf & if i % 2 == 0 { byte >> 4 } else { byte };
            *c = if nibble >= 8 {
                a.to_ascii_uppercase()
            } else {
                a.to_ascii_lowercase()
            };
        }

        f.write_str(str::from_utf8(&checksummed).unwrap())
    }
}
