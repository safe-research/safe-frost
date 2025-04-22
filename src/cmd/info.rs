use crate::{
    address::Address,
    cmd,
    fmt::{Coord, Scalar},
};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "info")]
/// display information
pub struct Command {
    #[argh(subcommand)]
    subcommand: Subcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    PublicKey(PublicKey),
    Signature(Signature),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "public-key")]
/// display information of a FROST public key
struct PublicKey {
    /// public key file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".into()"#)]
    public_key_path: PathBuf,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "signature")]
/// display information of a FROST signature
struct Signature {
    /// round-2 aggregate signature file
    #[argh(option, short = '2', default = r#"".frost/round2".into()"#)]
    signature_path: PathBuf,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        match self.subcommand {
            Subcommand::PublicKey(cmd) => {
                let data = fs::read(&cmd.public_key_path)?;
                let key = frost::keys::PublicKeyPackage::deserialize(&data)?;
                let key = key.verifying_key();

                println!("address:    {}", Address::from_key(key));
                println!("public key: {}", Coord(&key.to_element()));
            }
            Subcommand::Signature(cmd) => {
                let data = fs::read(&cmd.signature_path)?;
                let signature = frost::Signature::deserialize(&data)?;

                println!("R: {}", Coord(signature.R()));
                println!("z: {}", Scalar(signature.z()));
            }
        }
        Ok(())
    }
}
