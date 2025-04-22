use crate::{
    cmd::{self, PathFormat},
    data::round1::CommitmentsPackage,
};
use argh::FromArgs;
use std::{fs, path::PathBuf};

#[derive(FromArgs)]
#[argh(subcommand, name = "commit")]
/// generate round-1 share nonces and commitments
pub struct Command {
    /// share index
    #[argh(option, short = 'i')]
    share_index: usize,

    /// signing key share file format, the '%' will be replaced with the share
    /// index
    #[argh(option, short = 's', default = "PathFormat::signing_key()")]
    signing_key_path: PathFormat,

    /// round-1 nonces output file format, the '%' will be replaced with the
    /// share index
    #[argh(option, short = 'z', default = "PathFormat::nonces()")]
    nonces_path: PathFormat,

    /// round-1 commitments output file format, the '%' will be replaced with
    /// the share index
    #[argh(option, short = 'c', default = "PathFormat::commitments()")]
    commitments_path: PathFormat,
}

impl Command {
    pub fn run(self) -> cmd::Result {
        let mut rng = rand::thread_rng();
        let data = fs::read(self.signing_key_path())?;
        let key = frost::keys::KeyPackage::deserialize(&data)?;

        let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut rng);
        let commitments = CommitmentsPackage::new(*key.identifier(), commitments);

        fs::write(self.nonces_path(), nonces.serialize()?)?;
        fs::write(self.commitments_path(), commitments.serialize()?)?;

        Ok(())
    }

    fn signing_key_path(&self) -> PathBuf {
        self.signing_key_path.for_index(self.share_index)
    }

    fn nonces_path(&self) -> PathBuf {
        self.nonces_path.for_index(self.share_index)
    }

    fn commitments_path(&self) -> PathBuf {
        self.commitments_path.for_index(self.share_index)
    }
}
