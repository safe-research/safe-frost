use std::fmt::{self, Display, Formatter};

/// Decode a hex string.
pub fn decode<T>(value: &str) -> Result<T, DecodeError>
where
    T: BytesOfLength,
{
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.len() % 2 != 0 {
        return Err(DecodeError::OddLength);
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b => Err(DecodeError::InvalidDigit(b)),
    };

    let len = hex.len() / 2;
    let mut res = T::of_len(len).ok_or(DecodeError::WrongLength(len))?;
    for (b, r) in hex.as_bytes().chunks(2).zip(res.as_mut()) {
        *r = (nibble(b[0])? << 4) | nibble(b[1])?;
    }
    Ok(res)
}

/// A trait for constructing a byte buffer of a specific length.
pub trait BytesOfLength: AsMut<[u8]> + Sized {
    /// Constructs a byte buffer of a specific length.
    fn of_len(len: usize) -> Option<Self>;
}

impl BytesOfLength for Vec<u8> {
    fn of_len(len: usize) -> Option<Self> {
        Some(vec![0; len])
    }
}

impl<const N: usize> BytesOfLength for [u8; N] {
    fn of_len(len: usize) -> Option<Self> {
        (len == N).then_some([0; N])
    }
}

/// An error decoding a hex string.
#[derive(Debug)]
pub enum DecodeError {
    /// The hex string has an odd number of digits.
    OddLength,
    /// Unexpected byte length.
    WrongLength(usize),
    /// The hex string contains an invalid digit.
    InvalidDigit(u8),
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("odd number of hex digits"),
            Self::WrongLength(len) => write!(f, "wrong byte length of {len}"),
            Self::InvalidDigit(digit) => write!(f, "invalid hex digit {digit:#02x}"),
        }
    }
}

impl std::error::Error for DecodeError {}
