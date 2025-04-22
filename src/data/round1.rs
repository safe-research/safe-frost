use frost::serde::{Deserialize, Serialize};

/// A round-1 commitment package.
#[derive(Deserialize, Serialize)]
#[serde(crate = "::frost::serde")]
pub struct CommitmentsPackage {
    identifier: frost::Identifier,
    commitments: frost::round1::SigningCommitments,
}

impl CommitmentsPackage {
    /// Creates a new commitment package.
    pub fn new(
        identifier: frost::Identifier,
        commitments: frost::round1::SigningCommitments,
    ) -> Self {
        Self {
            identifier,
            commitments,
        }
    }

    /// Gets the identifier of the commitment package.
    pub fn identifier(&self) -> &frost::Identifier {
        &self.identifier
    }

    /// Gets the signing commitments of the commitment package.
    pub fn commitments(&self) -> &frost::round1::SigningCommitments {
        &self.commitments
    }

    /// Serialize the commitment package into a byte vector.
    ///
    /// This uses the [`postcard`] serialization format, to match the default
    /// format used by the [`frost`] crate.
    pub fn serialize(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    /// Deserialize a commitment package from a byte slice.
    ///
    /// This uses the [`postcard`] serialization format, to match the default
    /// format used by the [`frost`] crate.
    pub fn deserialize(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}
