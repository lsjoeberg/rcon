use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};

use crate::error::RconError;
use crate::packet::{Packet, PacketType};

pub struct Connection {
    stream: TcpStream,
    next_id: i32,
}

impl Connection {
    pub fn connect(addr: impl ToSocketAddrs, password: &str) -> Result<Connection, RconError> {
        let stream = TcpStream::connect(addr)?;
        let mut conn = Connection { stream, next_id: 0 };
        conn.auth(password)?;
        Ok(conn)
    }

    fn auth(&mut self, password: &str) -> Result<(), RconError> {
        // Note: A server responds with an empty `ResponseValue` followed by an `AuthResponse`.
        // The server uses the `AuthResponse` packet ID as status code, so the response ID should
        // be paired with the `ResponseValue` packet.
        self.send(PacketType::Auth, password)?;

        // Receive `AuthResponse`.
        let auth_response = loop {
            let r = Packet::deserialize(&self.stream)?;
            if r.ptype == PacketType::AuthResponse {
                break r;
            }
        };

        // If authentication was successful, the ID is the request ID.
        // If authentication failed, the ID is -1.
        if auth_response.id == -1 {
            return Err(RconError::AuthFailure);
        }

        Ok(())
    }

    pub fn exec(&mut self, cmd: &str) -> Result<String, RconError> {
        // Note: A server responds with one or more `ResponseValue`.
        // The max packet size is 4096 (default), but may differ between game servers.
        self.send(PacketType::ExecCommand, cmd)?;
        let response = self.recv_multi_packet_response()?;
        Ok(response)
    }

    fn send(&mut self, ptype: PacketType, body: &str) -> Result<i32, RconError> {
        let id = self.fetch_and_add_id();
        let packet = Packet::new(id, ptype, body.into());
        let data = packet.serialize();
        self.stream.write_all(&data)?;
        Ok(id)
    }

    fn recv_multi_packet_response(&mut self) -> Result<String, RconError> {
        // Send an empty ExecCommand packet, just after the actual client request packet.
        // Since the server always responds to requests in the receiving order (FIFO), we
        // can detect the end of a multi-packet response when receiving the response to the
        // empty packet.
        let end_id = self.send(PacketType::ExecCommand, "")?; // empty packet
        let mut response = String::new();
        loop {
            let recv_packet = Packet::deserialize(&self.stream)?;
            if recv_packet.id == end_id {
                break;
            }
            response += &recv_packet.body;
        }
        Ok(response)
    }

    /// Increment the packet ID and return the current one.
    /// Wraps back to `1` on overflow.
    fn fetch_and_add_id(&mut self) -> i32 {
        let id = self.next_id;
        // The ID should be positive according to the spec.
        self.next_id = self.next_id.checked_add(1).unwrap_or(1);
        id
    }
}
