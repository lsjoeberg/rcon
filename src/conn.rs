use std::net::{TcpStream, ToSocketAddrs};

use crate::error::Error;
use crate::packet::{MsgType, Packet, RconReq, RconResp, MAX_CMD_SIZE};

pub struct Connection {
    stream: TcpStream,
    next_id: i32,
}

impl Connection {
    /// # Errors
    /// Will return `Err` if a TCP connection cannot be established, or if authentication fails.
    pub fn connect(addr: impl ToSocketAddrs, password: impl AsRef<str>) -> Result<Connection, Error> {
        let stream = TcpStream::connect(addr)?;
        let mut conn = Connection { stream, next_id: 0 };
        conn.auth(password.as_ref())?;
        Ok(conn)
    }

    fn auth(&mut self, password: &str) -> Result<(), Error> {
        // Note: A server responds with an empty `ResponseValue` followed by an `AuthResponse`.
        // The server uses the `AuthResponse` packet ID as status code, so the response ID should
        // be paired with the `ResponseValue` packet.
        self.send(RconReq::Auth, password)?;

        // Receive `AuthResponse`.
        let auth_response = loop {
            let r = Packet::deserialize(&mut self.stream)?;
            if r.ptype == MsgType::Response(RconResp::AuthResponse) {
                break r;
            }
        };

        // Check if authentication was successful.
        if auth_response.is_error() {
            return Err(Error::AuthFailure);
        }

        Ok(())
    }

    /// # Errors
    /// Will return `Err` if `cmd` is larger than [`MAX_CMD_SIZE`] bytes, or if the bytes cannot be
    /// written to the TCP socket.
    pub fn exec(&mut self, cmd: &str) -> Result<String, Error> {
        // Note: The client-to-server max payload is sometimes limited; for
        // Minecraft this is 1446 bytes.
        if cmd.len() > MAX_CMD_SIZE {
            return Err(Error::CmdTooLong(cmd.len()));
        }

        // A server responds with one or more `ResponseValue`.
        self.send(RconReq::ExecCommand, cmd)?;
        let response = self.recv_multi_packet_response()?;

        Ok(response)
    }

    fn send(&mut self, request: RconReq, body: &str) -> Result<i32, Error> {
        let id = self.fetch_and_add_id();
        let packet = Packet::new(id, MsgType::Request(request), body.into())?;
        packet.serialize(&mut self.stream)?;
        Ok(id)
    }

    fn recv_multi_packet_response(&mut self) -> Result<String, Error> {
        // Send an empty ExecCommand packet, just after the actual client request packet.
        // Since the server always responds to requests in the receiving order (FIFO), we
        // can detect the end of a multi-packet response when receiving the response to the
        // empty packet.
        let end_id = self.send(RconReq::ExecCommand, "")?; // empty packet
        let mut response = String::new();
        loop {
            let recv_packet = Packet::deserialize(&mut self.stream)?;
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
