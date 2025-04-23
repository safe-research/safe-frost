use crate::{
    cmd::{self, Root},
    data::round1::CommitmentsPackage,
    fmt::Hex,
    hex,
};
use argh::{FromArgValue, FromArgs};
use std::{
    fmt::{self, Display, Formatter},
    fs,
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prepare")]
/// generate round-1 signing package
pub struct Command {
    /// the message to sign as a hexadecimal string
    #[argh(option, short = 'm')]
    message: Message,
}

struct Message(Vec<u8>);

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:#}", Hex(&self.0))
    }
}

impl FromArgValue for Message {
    fn from_arg_value(value: &str) -> Result<Self, String> {
        hex::decode(value)
            .map(Self)
            .map_err(|e| format!("invalid message: {e}"))
    }
}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        let commitments = root
            .all_commitments()?
            .map(|path| -> anyhow::Result<_> {
                let data = fs::read(path)?;
                let commitments = CommitmentsPackage::deserialize(&data)?;
                Ok((*commitments.identifier(), *commitments.commitments()))
            })
            .collect::<Result<_, _>>()?;
        let signing = frost::SigningPackage::new(commitments, self.message.as_ref());

        fs::write(root.signing_package(), signing.serialize()?)?;

        // Clean up the commitments after generating the signing package, as
        // they are no longer needed.
        for path in root.all_commitments()? {
            fs::remove_file(path)?;
        }

        Ok(())
    }
}
