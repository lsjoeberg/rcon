use std::cmp::Ordering;
use std::io::{Read, Write};

use crate::error::RconError;

const PACKET_HEADER_SIZE: i32 = 8;
const PACKET_PADDING_SIZE: i32 = 2;
const MIN_PACKET_SIZE: i32 = PACKET_HEADER_SIZE + PACKET_PADDING_SIZE;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RconReq {
    ExecCommand,
    Auth,
    Unknown(i32),
}

impl From<i32> for RconReq {
    fn from(value: i32) -> Self {
        match value {
            2 => Self::ExecCommand,
            3 => Self::Auth,
            _ => Self::Unknown(value),
        }
    }
}

impl From<RconReq> for i32 {
    fn from(value: RconReq) -> Self {
        match value {
            RconReq::ExecCommand => 2,
            RconReq::Auth => 3,
            RconReq::Unknown(v) => v,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RconResp {
    ResponseValue,
    AuthResponse,
    Unknown(i32),
}

impl From<i32> for RconResp {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::ResponseValue,
            2 => Self::AuthResponse,
            _ => Self::Unknown(value),
        }
    }
}

impl From<RconResp> for i32 {
    fn from(value: RconResp) -> Self {
        match value {
            RconResp::ResponseValue => 0,
            RconResp::AuthResponse => 2,
            RconResp::Unknown(v) => v,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MsgType {
    Request(RconReq),
    Response(RconResp),
}

impl From<MsgType> for i32 {
    fn from(value: MsgType) -> Self {
        match value {
            MsgType::Request(v) => v.into(),
            MsgType::Response(v) => v.into(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Packet {
    size: i32,
    pub id: i32,
    pub ptype: MsgType,
    pub body: String,
}

impl Packet {
    pub fn new(id: i32, ptype: MsgType, body: String) -> Self {
        Self {
            size: MIN_PACKET_SIZE + body.len() as i32,
            id,
            ptype,
            body,
        }
    }

    pub fn serialize(&self, w: &mut impl Write) -> Result<(), RconError> {
        let mut buf: Vec<u8> = Vec::with_capacity(self.size as usize);

        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());

        let ptype_raw: i32 = self.ptype.into();

        buf.extend_from_slice(&ptype_raw.to_le_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // empty string and null terminator
        w.write_all(&buf)?;
        Ok(())
    }

    pub fn deserialize(r: &mut impl Read) -> Result<Self, RconError> {
        // Read i32 packet fields.
        let mut field_buf = [0u8; 4]; // tmp buffer for i32 packet fields
        r.read_exact(&mut field_buf)?;
        let size = i32::from_le_bytes(field_buf);
        r.read_exact(&mut field_buf)?;
        let id = i32::from_le_bytes(field_buf);
        r.read_exact(&mut field_buf)?;
        let ptype_raw = i32::from_le_bytes(field_buf);

        // Read body.
        let body_len = size - MIN_PACKET_SIZE;
        let body = match body_len.cmp(&0) {
            Ordering::Greater => {
                let mut body_buf = vec![0u8; body_len as usize];
                r.read_exact(&mut body_buf)?;
                String::from_utf8(body_buf)?
            }
            Ordering::Equal => String::new(),
            Ordering::Less => return Err(RconError::InvalidPacket),
        };

        // Read terminating bytes.
        let mut term_buf = [0u8; 2];
        r.read_exact(&mut term_buf)?;
        if term_buf[0] != 0 || term_buf[1] != 0 {
            return Err(RconError::InvalidPacket);
        }

        // Note: Deserialized packets will always be response messages. The tag
        // `2` is shared between `ExecCommand` (req) and `AuthResponse (resp),
        // and only the latter is relevant here.
        Ok(Self {
            size,
            id,
            ptype: MsgType::Response(RconResp::from(ptype_raw)),
            body,
        })
    }

    pub fn is_error(&self) -> bool {
        self.id < 0
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
        let p = Packet::new(1, MsgType::Request(RconReq::Auth), "passwrd".into());
        let mut buf = Vec::new();
        p.serialize(&mut buf).unwrap();
        print_buffer_hex(&buf);

        assert_eq!(buf, expected);
    }

    #[test]
    fn deserialize_auth_response() {
        // id == 0 in AuthResponse indicates authn success
        let expected = Packet::new(0, MsgType::Response(RconResp::AuthResponse), "".into());
        let data = [10, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0];

        // Use a `Cursor` to fulfill the `Read` trait boundary on an array.
        let packet = Packet::deserialize(&mut Cursor::new(data)).unwrap();

        let mut buf = Vec::new();
        expected.serialize(&mut buf).unwrap();
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
