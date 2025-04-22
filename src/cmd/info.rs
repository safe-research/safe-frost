use crate::{address::Address, cmd, fmt::Coord};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "info")]
/// display information about a FROST public key
pub struct Command {
    /// public key file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".into()"#)]
    public_key_path: PathBuf,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let data = fs::read(&self.public_key_path)?;
        let package = frost::keys::PublicKeyPackage::deserialize(&data)?;
        let key = package.verifying_key();

        println!("address:    {}", Address::from_key(key));
        println!("public key: {}", Coord(&key.to_element()));

        Ok(())
    }
}
