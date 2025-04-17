use crate::{cmd, hex};
use argh::FromArgs;
use std::{
    fs::File,
    io::{self, Write as _},
};

#[derive(FromArgs)]
#[argh(subcommand, name = "split")]
/// generate a FROST public key and signing shares
pub struct Command {
    /// secret key, leave empty to generate a random one
    #[argh(option, short = 'k', from_str_fn(parse_signing_key))]
    secret_key: Option<frost::SigningKey>,

    /// signer threshold
    #[argh(option, short = 't', default = "3")]
    threshold: u16,

    /// signer count
    #[argh(option, short = 'n', default = "5")]
    signers: u16,

    /// public key output file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".to_string()"#)]
    public_key_path: String,

    /// signing key share output file format, the '%' will be replaced with
    /// the signer index
    #[argh(
        option,
        short = 's',
        default = r#"".frost/key.%".to_string()"#,
        from_str_fn(parse_signing_key_path)
    )]
    signing_key_path: String,

    /// overwrite existing files, otherwise error if writing the public key or
    /// signing key share would overwrite an existing file
    #[argh(switch, short = 'f')]
    force: bool,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let mut rng = rand::thread_rng();
        let secret = self
            .secret_key
            .unwrap_or_else(|| frost::SigningKey::new(&mut rng));

        let (shares, pubkey_package) = frost::keys::split(
            &secret,
            self.signers,
            self.threshold,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )?;

        self.write(&self.public_key_path, &pubkey_package.serialize()?)?;
        for (index, (_, share)) in shares.into_iter().enumerate() {
            let key_package = frost::keys::KeyPackage::try_from(share)?;
            self.write(&self.signing_key_path(index), &key_package.serialize()?)?;
        }

        Ok(())
    }

    fn signing_key_path(&self, index: usize) -> String {
        self.signing_key_path.replace('%', &index.to_string())
    }

    fn write(&self, path: &str, contents: &[u8]) -> Result<(), io::Error> {
        let mut file = if self.force {
            File::create(path)?
        } else {
            File::create_new(path)?
        };
        file.write_all(contents)?;
        Ok(())
    }
}

fn parse_signing_key(value: &str) -> Result<frost::SigningKey, String> {
    let secret = hex::decode::<[u8; 32]>(value).map_err(|e| format!("invalid secret: {e}"))?;
    let key = frost::SigningKey::deserialize(&secret).map_err(|e| format!("invalid key: {e}"))?;
    Ok(key)
}

fn parse_signing_key_path(value: &str) -> Result<String, String> {
    (value.as_bytes().iter().filter(|b| **b == b'%').count() == 1)
        .then(|| value.to_string())
        .ok_or_else(|| "invalid signing key path format".to_string())
}
