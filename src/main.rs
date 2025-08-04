//! Sample Frost threshold signature generation.

mod address;
mod cmd;
mod data;
mod evm;
mod fmt;
mod hex;
mod keccak;

use argh::FromArgs;

#[derive(FromArgs)]
/// generate a FROST threshold signature
struct Args {
    #[argh(subcommand)]
    subcommand: cmd::Subcommand,

    /// the FROST root directory
    #[argh(option, short = 'R', default = "cmd::Root::default()")]
    root_directory: cmd::Root,
}

fn main() {
    let args = argh::from_env::<Args>();
    if let Err(err) = args.subcommand.run(args.root_directory) {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}
