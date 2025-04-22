//! Sample Frost threshold signature generation.

mod address;
mod cmd;
mod data;
mod fmt;
mod hex;
mod keccak;

use argh::FromArgs;

#[derive(FromArgs)]
/// generate a FROST threshold signature
struct Args {
    #[argh(subcommand)]
    subcommand: cmd::Subcommand,
}

fn main() {
    let args = argh::from_env::<Args>();
    if let Err(err) = args.subcommand.run() {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}
