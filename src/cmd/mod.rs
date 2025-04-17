pub mod combine;
pub mod commit;
pub mod info;
pub mod prepare;
pub mod sign;
pub mod split;

use argh::FromArgs;
use std::error::Error;

pub type Result = std::result::Result<(), Box<dyn Error>>;

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum Subcommand {
    Info(info::Command),
    Split(split::Command),
}
