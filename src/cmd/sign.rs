use crate::{
    cmd::{self, Root},
    data::round2::SignatureSharePackage,
};
use argh::FromArgs;
use std::fs;

#[derive(FromArgs)]
#[argh(subcommand, name = "sign")]
/// generate round-2 signature shares
pub struct Command {
    /// share index
    #[argh(option, short = 'i')]
    share_index: usize,
}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        let data = fs::read(root.signing_key(self.share_index))?;
        let key = frost::keys::KeyPackage::deserialize(&data)?;

        let data = fs::read(root.nonces(self.share_index))?;
        let nonces = frost::round1::SigningNonces::deserialize(&data)?;

        let data = fs::read(root.signing_package())?;
        let signing = frost::SigningPackage::deserialize(&data)?;

        let signature = frost::round2::sign(&signing, &nonces, &key)?;
        let share = SignatureSharePackage::new(*key.identifier(), signature);

        fs::write(root.signature_share(self.share_index), share.serialize()?)?;

        // To avoid accidentally re-using nonces (which would be CATASTROPHIC),
        // we delete it after signing.
        fs::remove_file(root.nonces(self.share_index))?;

        Ok(())
    }
}
