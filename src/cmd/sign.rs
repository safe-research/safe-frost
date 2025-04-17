use crate::fmt::Hex;
use argh::FromArgValue;
use std::fmt::{self, Display, Formatter};

pub struct Message(Vec<u8>);

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
        let hex = value.strip_prefix("0x").unwrap_or(value);
        if hex.len() % 2 != 0 {
            return Err("odd number of hex digits".to_string());
        }
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            b => Err(format!("invalid hex digit {b:#02x}")),
        };
        hex.as_bytes()
            .chunks(2)
            .map(|b| Ok((nibble(b[0])? << 4) | nibble(b[1])?))
            .collect::<Result<Vec<_>, _>>()
            .map(Message)
    }
}
