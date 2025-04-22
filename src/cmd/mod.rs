pub mod aggregate;
pub mod commit;
pub mod info;
pub mod prepare;
pub mod sign;
pub mod split;
pub mod verify;

use argh::{FromArgValue, FromArgs};
use std::{
    fmt::{self, Display, Formatter},
    path::PathBuf,
};

pub type Result = std::result::Result<(), anyhow::Error>;

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum Subcommand {
    Info(info::Command),
    Split(split::Command),
    Commit(commit::Command),
    Prepare(prepare::Command),
    Sign(sign::Command),
    Aggregate(aggregate::Command),
    Verify(verify::Command),
}

impl Subcommand {
    pub fn run(self) -> Result {
        match self {
            Self::Info(cmd) => cmd.run(),
            Self::Split(cmd) => cmd.run(),
            Self::Commit(cmd) => cmd.run(),
            Self::Prepare(cmd) => cmd.run(),
            Self::Sign(cmd) => cmd.run(),
            Self::Aggregate(cmd) => cmd.run(),
            Self::Verify(cmd) => cmd.run(),
        }
    }
}

/// A format for paths on a share index.
struct PathFormat(String);

impl PathFormat {
    fn new(format: impl ToString) -> Option<Self> {
        let format = format.to_string();
        (format.as_bytes().iter().filter(|b| **b == b'%').count() == 1).then_some(Self(format))
    }

    fn signing_key() -> Self {
        Self::new(".frost/key.%").unwrap()
    }

    fn nonces() -> Self {
        Self::new(".frost/round1.%.nonces").unwrap()
    }

    fn commitments() -> Self {
        Self::new(".frost/round1.%.commitments").unwrap()
    }

    fn signature() -> Self {
        Self::new(".frost/round2.%").unwrap()
    }

    fn for_index(&self, index: usize) -> PathBuf {
        self.0.replace("%", &index.to_string()).into()
    }

    fn files(&self) -> std::result::Result<glob::Paths, glob::PatternError> {
        let pattern = self.0.replace("%", "*");
        glob::glob(&pattern)
    }
}

impl Display for PathFormat {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromArgValue for PathFormat {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        Self::new(value).ok_or_else(|| "invalid path format".to_string())
    }
}
