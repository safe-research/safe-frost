use crate::cmd::{self, Root};
use argh::FromArgs;
use std::fs;

#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
/// verify a FROST signature
pub struct Command {}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        let data = fs::read(root.public_key())?;
        let pubkey = frost::keys::PublicKeyPackage::deserialize(&data)?;

        let data = fs::read(root.signing_package())?;
        let signing = frost::SigningPackage::deserialize(&data)?;

        let data = fs::read(root.signature())?;
        let signature = frost::Signature::deserialize(&data)?;

        pubkey
            .verifying_key()
            .verify(signing.message(), &signature)?;

        Ok(())
    }
}
