use crate::{
    cmd::{self, PathFormat},
    data::round2::SignatureSharePackage,
};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "aggregate")]
/// aggregate round-2 signature shares
pub struct Command {
    /// public key file
    #[argh(option, short = 'p', default = r#"".frost/key.pub".into()"#)]
    public_key_path: PathBuf,

    /// round-1 signing package file
    #[argh(option, short = '1', default = r#"".frost/round1".into()"#)]
    signing_package_path: PathBuf,

    /// round-2 signature share file format, the '%' will be replaced with the
    /// share index
    #[argh(option, short = 'd', default = "PathFormat::signature()")]
    signature_share_path: PathFormat,

    /// round-2 aggregate signature output file
    #[argh(option, short = '2', default = r#"".frost/round2".into()"#)]
    signature_path: PathBuf,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let data = fs::read(&self.public_key_path)?;
        let pubkey = frost::keys::PublicKeyPackage::deserialize(&data)?;

        let data = fs::read(&self.signing_package_path)?;
        let signing = frost::SigningPackage::deserialize(&data)?;

        let shares = self
            .signature_share_path
            .files()?
            .map(|path| -> anyhow::Result<_> {
                let data = fs::read(&path?)?;
                let share = SignatureSharePackage::deserialize(&data)?;
                Ok((*share.identifier(), *share.signature()))
            })
            .collect::<Result<_, _>>()?;

        let signature = frost::aggregate(&signing, &shares, &pubkey)?;

        fs::write(self.signature_path, signature.serialize()?)?;

        // Clean up the signature shares after aggregating them, as they are no
        // longer needed.
        for path in self.signature_share_path.files()? {
            fs::remove_file(path?)?;
        }

        Ok(())
    }
}
