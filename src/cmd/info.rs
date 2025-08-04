use crate::{
    address::Address,
    cmd::{self, Root},
    evm,
    fmt::{Coord, Hex, Scalar},
};
use argh::FromArgs;
use std::fs;

#[derive(FromArgs)]
#[argh(subcommand, name = "info")]
/// display information
pub struct Command {
    #[argh(subcommand)]
    subcommand: Subcommand,

    /// output in Solidity ABI encoded format, intended for use with Foundry
    /// `ffi` cheatcodes
    #[argh(switch, short = 'e')]
    abi_encode: bool,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    PublicKey(PublicKey),
    Signature(Signature),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "public-key")]
/// display information of a FROST public key
struct PublicKey {}

#[derive(FromArgs)]
#[argh(subcommand, name = "signature")]
/// display information of a FROST signature
struct Signature {
    /// include the public key in the signature encoding; this is needed by the
    /// EIP-7702 `FROSTAccount` implementation for signature verification
    #[argh(switch, short = 'p')]
    with_public_key: bool,
}

impl Command {
    pub fn run(self, root: Root) -> cmd::Result {
        match self.subcommand {
            Subcommand::PublicKey(_) => {
                let data = fs::read(root.public_key())?;
                let key = frost::keys::PublicKeyPackage::deserialize(&data)?;
                let key = evm::verified_public_key(&key)?;

                if self.abi_encode {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(&abi::address(Address::from_key(key)));
                    buf.extend_from_slice(&abi::coord(&key.to_element()));
                    print!("{}", Hex(&buf))
                } else {
                    println!("address:    {}", Address::from_key(key));
                    println!("public key: {}", Coord(&key.to_element()));
                }
            }
            Subcommand::Signature(cmd) => {
                let data = fs::read(root.signature())?;
                let signature = frost::Signature::deserialize(&data)?;

                let key = if cmd.with_public_key {
                    let data = fs::read(root.public_key())?;
                    Some(frost::keys::PublicKeyPackage::deserialize(&data)?)
                } else {
                    None
                };
                let key = key.as_ref().map(evm::verified_public_key).transpose()?;

                if self.abi_encode {
                    let mut buf = Vec::new();
                    if let Some(key) = &key {
                        buf.extend_from_slice(&abi::coord(&key.to_element()));
                    }
                    buf.extend_from_slice(&abi::coord(signature.R()));
                    buf.extend_from_slice(&abi::scalar(signature.z()));
                    print!("{}", Hex(&buf))
                } else if let Some(key) = &key {
                    println!("public key: {}", Coord(&key.to_element()));
                    println!("R:          {}", Coord(signature.R()));
                    println!("z:          {}", Scalar(signature.z()));
                } else {
                    println!("R: {}", Coord(signature.R()));
                    println!("z: {}", Scalar(signature.z()));
                }
            }
        }
        Ok(())
    }
}

/// Poor man's Solidity ABI encoding.
mod abi {
    use crate::address::Address;
    use k256::elliptic_curve::{bigint::Encoding as _, sec1::ToEncodedPoint as _};

    pub fn address(a: Address) -> [u8; 32] {
        let mut b = [0_u8; 32];
        b[12..].copy_from_slice(a.as_slice());
        b
    }

    pub fn scalar(a: &k256::Scalar) -> [u8; 32] {
        k256::U256::from(a).to_be_bytes()
    }

    pub fn coord(a: &k256::ProjectivePoint) -> [u8; 64] {
        a.to_encoded_point(false).as_bytes()[1..]
            .try_into()
            .unwrap()
    }
}
