use crate::{
    cmd::{self, PathFormat},
    data::round2::SignatureSharePackage,
};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "sign")]
/// generate round-2 signature shares
pub struct Command {
    /// share index
    #[argh(option, short = 'i')]
    share_index: usize,

    /// signing key share file format, the '%' will be replaced with the share
    /// index
    #[argh(option, short = 's', default = "PathFormat::signing_key()")]
    signing_key_path: PathFormat,

    /// round-1 nonces file format, the '%' will be replaced with the share
    /// index
    #[argh(option, short = 'z', default = "PathFormat::nonces()")]
    nonces_path: PathFormat,

    /// round-1 signing package file
    #[argh(option, short = '1', default = r#"".frost/round1".into()"#)]
    signing_package_path: PathBuf,

    /// round-2 signature share output file format, the '%' will be replaced
    /// with the share index
    #[argh(option, short = 'd', default = "PathFormat::signature()")]
    signature_share_path: PathFormat,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let data = fs::read(self.signing_key_path())?;
        let key = frost::keys::KeyPackage::deserialize(&data)?;

        let data = fs::read(self.nonces_path())?;
        let nonces = frost::round1::SigningNonces::deserialize(&data)?;

        let data = fs::read(&self.signing_package_path)?;
        let signing = frost::SigningPackage::deserialize(&data)?;

        let signature = frost::round2::sign(&signing, &nonces, &key)?;
        let share = SignatureSharePackage::new(*key.identifier(), signature);

        fs::write(self.signature_share_path(), share.serialize()?)?;

        // To avoid accidentally re-using nonces (which would be CATASTROPHIC),
        // we delete it after signing.
        fs::remove_file(self.nonces_path())?;

        Ok(())
    }

    fn signing_key_path(&self) -> PathBuf {
        self.signing_key_path.for_index(self.share_index)
    }

    fn nonces_path(&self) -> PathBuf {
        self.nonces_path.for_index(self.share_index)
    }

    fn signature_share_path(&self) -> PathBuf {
        self.signature_share_path.for_index(self.share_index)
    }
}
