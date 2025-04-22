use frost::serde::{Deserialize, Serialize};

/// A round-2 signature share package.
#[derive(Deserialize, Serialize)]
#[serde(crate = "::frost::serde")]
pub struct SignatureSharePackage {
    identifier: frost::Identifier,
    signature: frost::round2::SignatureShare,
}

impl SignatureSharePackage {
    /// Creates a new signature share package.
    pub fn new(identifier: frost::Identifier, signature: frost::round2::SignatureShare) -> Self {
        Self {
            identifier,
            signature,
        }
    }

    /// Gets the identifier of the signature share package.
    pub fn identifier(&self) -> &frost::Identifier {
        &self.identifier
    }

    /// Gets the signature share.
    pub fn signature(&self) -> &frost::round2::SignatureShare {
        &self.signature
    }

    /// Serialize the signature share package into a byte vector.
    ///
    /// This uses the [`postcard`] serialization format, to match the default
    /// format used by the [`frost`] crate.
    pub fn serialize(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    /// Deserialize a signature share package from a byte slice.
    ///
    /// This uses the [`postcard`] serialization format, to match the default
    /// format used by the [`frost`] crate.
    pub fn deserialize(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}
