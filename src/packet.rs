#![allow(dead_code)]

use std::io::Read;

use crate::error::RconError;

/// Indicates the purpose of a packet.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PacketType {
    /// Represents an authentication request to the server.
    Auth,
    /// Represents a notification of the connection's current auth status.
    AuthResponse,
    /// Represents a command issued to the server by a client.
    ExecCommand,
    /// Represents a response to an [`ExecCommand`].
    ResponseValue,
    /// Represents an unknown packet type.
    Unknown(i32),
}

impl PacketType {
    fn from_i32(value: i32, is_response: bool) -> Self {
        match value {
            3 => Self::Auth,
            2 if is_response => Self::AuthResponse,
            2 => Self::ExecCommand,
            0 => Self::ResponseValue,
            _ => Self::Unknown(value),
        }
    }

    fn into_i32(self) -> i32 {
        match self {
            PacketType::Auth => 3,
            PacketType::AuthResponse | PacketType::ExecCommand => 2,
            PacketType::ResponseValue => 0,
            PacketType::Unknown(n) => n,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Packet {
    size: i32,
    pub id: i32,
    pub ptype: PacketType,
    pub body: String,
}

impl Packet {
    pub fn new(id: i32, ptype: PacketType, body: String) -> Self {
        Self {
            size: 10 + body.len() as i32,
            id,
            ptype,
            body,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(self.size as usize);
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());
        buf.extend_from_slice(&self.ptype.into_i32().to_le_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // empty string and null terminator
        buf
    }

    pub fn deserialize(mut buf: impl Read) -> Result<Self, RconError> {
        // Read i32 packet fields.
        let mut field_buf = [0u8; 4]; // tmp buffer for i32 packet fields
        buf.read_exact(&mut field_buf)?;
        let size = i32::from_le_bytes(field_buf);
        buf.read_exact(&mut field_buf)?;
        let id = i32::from_le_bytes(field_buf);
        buf.read_exact(&mut field_buf)?;
        let ptype_raw = i32::from_le_bytes(field_buf);

        // TODO: Validate size!
        let body_len = size - 10;
        let mut body_buf = vec![0u8; body_len as usize];
        buf.read_exact(&mut body_buf)?;
        let body = String::from_utf8(body_buf)?;

        // Read terminating bytes.
        let mut term_buf = [0u8; 2];
        buf.read_exact(&mut term_buf)?;
        // TODO: Verify that bytes are zero?

        // Note: Deserialized packets will always be `is_response`. The tag `2` is shared between
        // `ExecCommand` (req) and `AuthResponse` (resp), and only the latter is relevant here.
        Ok(Self {
            size,
            id,
            ptype: PacketType::from_i32(ptype_raw, true),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn serialize_auth() {
        let expected = [
            17, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 112, 97, 115, 115, 119, 114, 100, 0, 0,
        ];
        let p = Packet::new(1, PacketType::Auth, "passwrd".into());
        let buf = p.serialize();
        print_buffer_hex(&buf);

        assert_eq!(buf.as_slice(), expected);
    }

    #[test]
    fn deserialize_auth_response() {
        // id == 0 in AuthResponse indicates authn success
        let expected = Packet::new(0, PacketType::AuthResponse, "".into());
        let data = [10, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0];

        // Use a `Cursor` to fulfill the `Read` trait boundary on an array.
        let packet = Packet::deserialize(Cursor::new(data)).unwrap();

        let buf = expected.serialize();
        print_buffer_hex(&buf);

        assert_eq!(packet, expected)
    }

    /// Print bytes as hex view for `--nocapture` or `--show-output`.
    fn print_buffer_hex(buf: &[u8]) {
        for line in buf.chunks(16) {
            for byte in line {
                print!("{byte:02x} ")
            }
            println!()
        }
    }
}
