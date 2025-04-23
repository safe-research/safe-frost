use crate::{
    cmd::{self, Root},
    data::round1::CommitmentsPackage,
};
use argh::FromArgs;
use std::fs;

#[derive(FromArgs)]
#[argh(subcommand, name = "commit")]
/// generate round-1 share nonces and commitments
pub struct Command {
    /// share index
    #[argh(option, short = 'i')]
    share_index: usize,
}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        let mut rng = rand::thread_rng();
        let data = fs::read(root.signing_key(self.share_index))?;
        let key = frost::keys::KeyPackage::deserialize(&data)?;

        let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut rng);
        let commitments = CommitmentsPackage::new(*key.identifier(), commitments);

        fs::write(root.nonces(self.share_index), nonces.serialize()?)?;
        fs::write(root.commitments(self.share_index), commitments.serialize()?)?;

        Ok(())
    }
}
