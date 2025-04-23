pub mod aggregate;
pub mod commit;
pub mod info;
pub mod prepare;
pub mod sign;
pub mod split;
pub mod verify;

use argh::{FromArgValue, FromArgs};
use std::{fs, io, path::PathBuf};

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
    pub fn run(self, root: Root) -> Result {
        match self {
            Self::Info(cmd) => cmd.run(root),
            Self::Split(cmd) => cmd.run(root),
            Self::Commit(cmd) => cmd.run(root),
            Self::Prepare(cmd) => cmd.run(root),
            Self::Sign(cmd) => cmd.run(root),
            Self::Aggregate(cmd) => cmd.run(root),
            Self::Verify(cmd) => cmd.run(root),
        }
    }
}

/// The FROST root directory.
pub struct Root(PathBuf);

impl Root {
    fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(&self.0)
    }

    fn public_key(&self) -> PathBuf {
        self.0.join("key.pub")
    }

    fn signing_key(&self, index: usize) -> PathBuf {
        self.0.join(format!("key.{index}"))
    }

    fn nonces(&self, index: usize) -> PathBuf {
        self.0.join(format!("round1.{index}.nonces"))
    }

    fn commitments(&self, index: usize) -> PathBuf {
        self.0.join(format!("round1.{index}.commitments"))
    }

    fn all_commitments(&self) -> io::Result<impl Iterator<Item = PathBuf>> {
        let mut result = Vec::new();
        for entry in self.0.read_dir()? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|name| {
                    name.to_str()?
                        .strip_prefix("round1.")?
                        .strip_suffix(".commitments")?
                        .parse::<usize>()
                        .ok()
                })
                .is_some()
            {
                result.push(path);
            };
        }
        Ok(result.into_iter())
    }

    fn signing_package(&self) -> PathBuf {
        self.0.join("round1")
    }

    fn signature_share(&self, index: usize) -> PathBuf {
        self.0.join(format!("round2.{index}"))
    }

    fn all_signature_shares(&self) -> io::Result<impl Iterator<Item = PathBuf>> {
        let mut result = Vec::new();
        for entry in self.0.read_dir()? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|name| {
                    name.to_str()?
                        .strip_prefix("round2.")?
                        .parse::<usize>()
                        .ok()
                })
                .is_some()
            {
                result.push(path);
            };
        }
        Ok(result.into_iter())
    }

    fn signature(&self) -> PathBuf {
        self.0.join("round2")
    }
}

impl Default for Root {
    fn default() -> Self {
        Self(PathBuf::from(".frost"))
    }
}

impl FromArgValue for Root {
    fn from_arg_value(value: &str) -> std::result::Result<Self, String> {
        Ok(Self(PathBuf::from(value)))
    }
}
