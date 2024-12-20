use std::cmp::Ordering;
use std::io::{Read, Write};

use crate::error::Error;

const PACKET_HEADER_SIZE: usize = 8;
const PACKET_PADDING_SIZE: usize = 2;
pub const MIN_PACKET_SIZE: usize = PACKET_HEADER_SIZE + PACKET_PADDING_SIZE;
pub const MAX_PACKET_SIZE: usize = 4096; // S->C
pub const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - MIN_PACKET_SIZE;
pub const MAX_CMD_SIZE: usize = 1446; // C->S

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
    size: usize,
    pub id: i32,
    pub ptype: MsgType,
    pub body: String,
}

impl Packet {
    pub fn new(id: i32, ptype: MsgType, body: String) -> Result<Self, Error> {
        // Ensure body fits in an RCON packet.
        let body_len = body.len();
        if body_len >= MAX_PAYLOAD_SIZE {
            return Err(Error::PayloadTooLong(body.len()));
        }

        Ok(Self {
            size: MIN_PACKET_SIZE + body_len,
            id,
            ptype,
            body,
        })
    }

    pub fn serialize(&self, w: &mut impl Write) -> Result<(), Error> {
        // Ensure size is within spec.
        if !(MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&self.size) {
            return Err(Error::InvalidPacketSize(self.size));
        }
        let Ok(size_raw) = i32::try_from(self.size) else {
            return Err(Error::InvalidPacketSize(self.size));
        };

        let mut buf: Vec<u8> = Vec::with_capacity(self.size);
        buf.extend_from_slice(&size_raw.to_le_bytes());
        buf.extend_from_slice(&self.id.to_le_bytes());

        let ptype_raw: i32 = self.ptype.into();
        buf.extend_from_slice(&ptype_raw.to_le_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // empty string and null terminator
        w.write_all(&buf)?;
        Ok(())
    }

    pub fn deserialize(r: &mut impl Read) -> Result<Self, Error> {
        // Read i32 packet fields.
        let mut field_buf = [0u8; 4]; // tmp buffer for i32 packet fields
        r.read_exact(&mut field_buf)?;
        let size_raw = i32::from_le_bytes(field_buf);
        r.read_exact(&mut field_buf)?;
        let id = i32::from_le_bytes(field_buf);
        r.read_exact(&mut field_buf)?;
        let ptype_raw = i32::from_le_bytes(field_buf);

        // Ensure size is valid: non-negative and within spec.
        let Ok(size) = usize::try_from(size_raw) else {
            return Err(Error::BadResponsePacket);
        };
        if !(MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&size) {
            return Err(Error::InvalidPacketSize(size));
        }

        // Read body.
        let body_len = size - MIN_PACKET_SIZE;
        let body = match body_len.cmp(&0) {
            Ordering::Greater => {
                let mut body_buf = vec![0u8; body_len];
                r.read_exact(&mut body_buf)?;
                String::from_utf8(body_buf)?
            }
            Ordering::Equal => String::new(),
            Ordering::Less => return Err(Error::BadResponsePacket),
        };

        // Read terminating bytes.
        let mut term_buf = [0u8; 2];
        r.read_exact(&mut term_buf)?;
        if term_buf[0] != 0 || term_buf[1] != 0 {
            return Err(Error::BadResponsePacket);
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
    use super::*;

    use std::io::Cursor;

    #[test]
    fn new_packet() {
        let body = String::from("list");
        let res = Packet::new(42, MsgType::Request(RconReq::ExecCommand), body.clone());
        assert!(res.is_ok());

        let p = res.unwrap();
        assert_eq!(p.id, 42);
        assert_eq!(p.ptype, MsgType::Request(RconReq::ExecCommand));
        assert_eq!(p.body, body);
        assert_eq!(p.size, MIN_PACKET_SIZE + body.len());
    }

    #[test]
    fn new_packet_too_long_body() {
        let body = String::from_utf8([0x61u8; MAX_PACKET_SIZE].into()).unwrap();
        let res = Packet::new(42, MsgType::Request(RconReq::ExecCommand), body);
        assert!(res.is_err());
    }

    #[test]
    fn serialize_auth() {
        // size = 17, id = 1, ptype = 3, body = "passwrd", \0\0
        let expected = [
            17, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 112, 97, 115, 115, 119, 114, 100, 0, 0,
        ];
        let p = Packet::new(1, MsgType::Request(RconReq::Auth), "passwrd".into())
            .expect("password should fit in packet body");
        let mut buf = Vec::new();
        p.serialize(&mut buf).unwrap();
        print_buffer_hex(&buf);

        assert_eq!(buf, expected);
    }

    #[test]
    fn deserialize_auth_response() {
        // id == 0 in AuthResponse indicates authn success
        let expected = Packet::new(0, MsgType::Response(RconResp::AuthResponse), String::new())
            .expect("empty string should fit in packet body");

        // size = 10, id = 0, ptype = 2, body = "", \0\0
        let data = [10, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0];

        // Use a `Cursor` to fulfill the `Read` trait boundary on an array.
        let packet = Packet::deserialize(&mut Cursor::new(data)).unwrap();

        let mut buf = Vec::new();
        expected.serialize(&mut buf).unwrap();
        print_buffer_hex(&buf);

        assert_eq!(packet, expected);
    }

    #[test]
    fn deserialize_neg_size() {
        // A packet has a positive size.
        // size = -1, id = 42, ptype = 0, body = "", \0\0
        let data = [255, 255, 255, 255, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let res = Packet::deserialize(&mut Cursor::new(data));
        assert!(res.is_err());
    }

    #[test]
    fn deserialize_too_small_size() {
        // A packet is at least 10 bytes.
        // size = 9, id = 42, ptype = 0, body = "", \0\0
        let data = [9, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let res = Packet::deserialize(&mut Cursor::new(data));
        assert!(res.is_err());
        let Err(Error::InvalidPacketSize(s)) = res else {
            panic!();
        };
        assert_eq!(s, 9);
    }

    #[test]
    fn deserialize_too_large_size() {
        // A packet is at most 4096 bytes.
        // size = 4097, id = 42, ptype = 0, body = "", \0\0
        let data = [1, 16, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let res = Packet::deserialize(&mut Cursor::new(data));
        assert!(res.is_err());
        let Err(Error::InvalidPacketSize(s)) = res else {
            panic!();
        };
        assert_eq!(s, 4097);
    }

    #[test]
    fn serialize_bad_size() {
        let packet = Packet {
            size: usize::MAX,
            id: 0,
            ptype: MsgType::Request(RconReq::ExecCommand),
            body: "list".to_string(),
        };
        let mut buf = Vec::new();
        let res = packet.serialize(&mut buf);
        assert!(res.is_err());
        let Err(Error::InvalidPacketSize(s)) = res else {
            panic!();
        };
        assert_eq!(s, usize::MAX);
    }

    /// Print bytes as hex view for `--nocapture` or `--show-output`.
    fn print_buffer_hex(buf: &[u8]) {
        for line in buf.chunks(16) {
            for byte in line {
                print!("{byte:02x} ");
            }
            println!();
        }
    }
}
