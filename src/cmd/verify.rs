use crate::cmd::{self};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
/// verify a FROST signature
pub struct Command {
    /// public key file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".into()"#)]
    public_key_path: PathBuf,

    /// round-1 signing package file
    #[argh(option, short = '1', default = r#"".frost/round1".into()"#)]
    signing_package_path: PathBuf,

    /// round-2 aggregate signature file
    #[argh(option, short = '2', default = r#"".frost/round2".into()"#)]
    signature_path: PathBuf,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let data = fs::read(&self.public_key_path)?;
        let pubkey = frost::keys::PublicKeyPackage::deserialize(&data)?;

        let data = fs::read(&self.signing_package_path)?;
        let signing = frost::SigningPackage::deserialize(&data)?;

        let data = fs::read(&self.signature_path)?;
        let signature = frost::Signature::deserialize(&data)?;

        pubkey
            .verifying_key()
            .verify(signing.message(), &signature)?;

        Ok(())
    }
}
