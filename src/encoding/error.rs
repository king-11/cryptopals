use std::fmt::Display;

#[derive(Debug)]
pub enum ParsingDirection {
    Encoding,
    Decoding,
}

impl Display for ParsingDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsingDirection::Decoding => f.write_str("decoding"),
            ParsingDirection::Encoding => f.write_str("encoding"),
        }
    }
}

#[derive(Debug)]
pub enum Encoding {
    Hex,
    Base64,
}

impl Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Encoding::Hex => f.write_str("hex"),
            Encoding::Base64 => f.write_str("base64"),
        }
    }
}

#[derive(Debug)]
pub enum Value {
    Bytes(Vec<u8>),
    String(String),
}

#[derive(Debug)]
pub struct ParsingError {
    pub direction: ParsingDirection,
    pub encoding: Encoding,
    pub value: Value,
}

impl ParsingError {
    pub fn from_bytes(direction: ParsingDirection, encoding: Encoding, bytes: Vec<u8>) -> Self {
        ParsingError {
            direction,
            encoding,
            value: Value::Bytes(bytes),
        }
    }

    pub fn from_string(direction: ParsingDirection, encoding: Encoding, string: String) -> Self {
        ParsingError {
            direction,
            encoding,
            value: Value::String(string),
        }
    }
}

impl Display for ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{} failed {} for {:?}",
            self.encoding, self.direction, self.value
        ))
    }
}

impl std::error::Error for ParsingError {}
