use crate::{
    cmd::{self, Root},
    data::round2::SignatureSharePackage,
};
use argh::FromArgs;
use std::fs;

#[derive(FromArgs)]
#[argh(subcommand, name = "aggregate")]
/// aggregate round-2 signature shares
pub struct Command {}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        let data = fs::read(root.public_key())?;
        let pubkey = frost::keys::PublicKeyPackage::deserialize(&data)?;

        let data = fs::read(root.signing_package())?;
        let signing = frost::SigningPackage::deserialize(&data)?;

        let shares = root
            .all_signature_shares()?
            .map(|path| -> anyhow::Result<_> {
                let data = fs::read(&path)?;
                let share = SignatureSharePackage::deserialize(&data)?;
                Ok((*share.identifier(), *share.signature()))
            })
            .collect::<Result<_, _>>()?;

        let signature = frost::aggregate(&signing, &shares, &pubkey)?;

        fs::write(root.signature(), signature.serialize()?)?;

        // Clean up the signature shares after aggregating them, as they are no
        // longer needed.
        for path in root.all_signature_shares()? {
            fs::remove_file(path)?;
        }

        Ok(())
    }
}
