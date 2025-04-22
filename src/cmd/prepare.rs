use crate::{
    cmd::{self, PathFormat},
    data::round1::CommitmentsPackage,
    fmt::Hex,
    hex,
};
use argh::{FromArgValue, FromArgs};
use std::{
    fmt::{self, Display, Formatter},
    fs,
    path::PathBuf,
};

#[derive(FromArgs)]
#[argh(subcommand, name = "prepare")]
/// generate round-1 signing package
pub struct Command {
    /// round-1 commitments file format, the '%' will be replaced with the
    /// share index
    #[argh(option, short = 'c', default = "PathFormat::commitments()")]
    commitments_path: PathFormat,

    /// the message to sign as a hexadecimal string
    #[argh(option, short = 'm')]
    message: Message,

    /// round-1 signing package output file
    #[argh(option, short = '1', default = r#"".frost/round1".into()"#)]
    signing_package_path: PathBuf,
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
    pub fn run(self) -> cmd::Result {
        let commitments = self
            .commitments_path
            .files()?
            .map(|path| -> anyhow::Result<_> {
                let data = fs::read(&path?)?;
                let commitments = CommitmentsPackage::deserialize(&data)?;
                Ok((*commitments.identifier(), *commitments.commitments()))
            })
            .collect::<Result<_, _>>()?;
        let signing = frost::SigningPackage::new(commitments, self.message.as_ref());

        fs::write(self.signing_package_path, signing.serialize()?)?;

        // Clean up the commitments after generating the signing package, as
        // they are no longer needed.
        for path in self.commitments_path.files()? {
            fs::remove_file(path?)?;
        }

        Ok(())
    }
}
