use crate::{
    cmd::{self, Root},
    evm, hex,
};
use argh::FromArgs;
use std::{
    fs::File,
    io::{self, Write as _},
    path::PathBuf,
};

#[derive(FromArgs)]
#[argh(subcommand, name = "split")]
/// generate a FROST public key and signing shares
pub struct Command {
    /// secret key, leave empty to generate a random one
    #[argh(option, short = 'k', from_str_fn(parse_root_key))]
    secret_key: Option<frost::SigningKey>,

    /// signer threshold
    #[argh(option, short = 't', default = "3")]
    threshold: u16,

    /// signer count
    #[argh(option, short = 'n', default = "5")]
    signers: u16,

    /// overwrite existing files, otherwise error if writing the public key or
    /// signing key share would overwrite an existing file
    #[argh(switch, short = 'f')]
    force: bool,
}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        let mut shares;
        let mut pubkey_package;

        while {
            let mut rng = rand::thread_rng();
            let secret = self
                .secret_key
                .unwrap_or_else(|| frost::SigningKey::new(&mut rng));

            (shares, pubkey_package) = frost::keys::split(
                &secret,
                self.signers,
                self.threshold,
                frost::keys::IdentifierList::Default,
                &mut rng,
            )?;
            evm::verified_public_key(&pubkey_package).is_err()
        } {}

        root.ensure()?;
        self.write(root.public_key(), &pubkey_package.serialize()?)?;
        for (index, (_, share)) in shares.into_iter().enumerate() {
            let key_package = frost::keys::KeyPackage::try_from(share)?;
            self.write(root.signing_key(index), &key_package.serialize()?)?;
        }

        Ok(())
    }

    fn write(&self, path: PathBuf, contents: &[u8]) -> Result<(), io::Error> {
        let mut file = if self.force {
            File::create(path)?
        } else {
            File::create_new(path)?
        };
        file.write_all(contents)?;
        Ok(())
    }
}

fn parse_root_key(value: &str) -> Result<frost::SigningKey, String> {
    let secret = hex::decode::<[u8; 32]>(value).map_err(|e| format!("invalid secret: {e}"))?;
    let key = frost::SigningKey::deserialize(&secret).map_err(|e| format!("invalid key: {e}"))?;
    Ok(key)
}
