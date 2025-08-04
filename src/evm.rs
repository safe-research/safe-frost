use frost::{Field as _, Secp256K1ScalarField, VerifyingKey, keys::PublicKeyPackage};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use std::fmt::{self, Display, Formatter};

/// Verifies whether or not a `secp256k1` public key is valid and supported with
/// the FROST(secp256k1, SHA-256) EVM verifier implementation.
///
/// In particular, public keys with x-coordinates that are higher than the curve
/// order are not supported. This is because we abuse the `ecrecover` precompile
/// to compute scalar multiplcation and point addition `-z⋅G + e⋅P` by passing
/// the public key's `P` x-coordinate as the `ecrecover` signature `r` value.
/// This "trick" does not support public keys with x-coordinates greater than the
/// curve order because:
///
/// 1. ECDSA signature `r` values are encoded as scalars that must be less than
///    the curve order.
/// 2. Ethereum `ecrecover` does not support recovery IDs (the `v` value) that
///    encode when the signature `R` point encoded in the `r` value has an
///    x-coordinate of `R.x = r + n` (where `n` is the order of the curve).
pub fn verified_public_key(key: &PublicKeyPackage) -> Result<&VerifyingKey, NotSupported> {
    let key = key.verifying_key();
    let point = key.to_element().to_encoded_point(true);
    let _ = Secp256K1ScalarField::deserialize(point.as_bytes()[1..].try_into()?)?;
    Ok(key)
}

/// An error decoding a hex string.
#[derive(Debug)]
pub struct NotSupported;

impl Display for NotSupported {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("public key not supported by the EVM verifier")
    }
}

impl From<frost::FieldError> for NotSupported {
    fn from(_: frost::FieldError) -> Self {
        NotSupported
    }
}

impl From<std::array::TryFromSliceError> for NotSupported {
    fn from(_: std::array::TryFromSliceError) -> Self {
        NotSupported
    }
}

impl std::error::Error for NotSupported {}
