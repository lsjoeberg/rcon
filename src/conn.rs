use crate::error::Error;
use crate::packet::{
    MsgType::{Request, Response},
    Packet,
    ReqType::{self, AuthRequest, ExecCommand},
    ResType::{AuthResponse, ResponseValue},
    MAX_CMD_SIZE,
};

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Indicates the resolution of an authentication handshake with the RCON
/// server. The RCON protocol specifies that an authentication request should
/// be answered with two packets: one [`ResponseValue`] to match the specific
/// request, and one [`AuthResponse`] to indicate the authentication result.
/// Some servers may omit the [`ResponseValue`] and only send an
/// [`AuthResponse`]. This could be considered unsafe.
enum HandshakeStatus {
    /// The handshake was matched to the specific authentication request.
    Matched,
    /// Only an [`AuthResponse`] was received from the server, not guaranteed
    /// to be a response to the sent [`AuthRequest`].
    BareAuthResponse,
}

pub struct Connection {
    stream: TcpStream,
    next_id: i32,
}

impl Connection {
    /// # Errors
    /// Will return `Err` if a TCP connection cannot be established, or if authentication fails.
    pub fn connect(
        addr: impl ToSocketAddrs,
        password: impl AsRef<str>,
    ) -> Result<Connection, Error> {
        // Create a TCP stream.
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        // Create a new RCON connection.
        let mut conn = Connection { stream, next_id: 0 };

        // Attempt to authenticate the connection.
        conn.auth(password.as_ref())?;

        Ok(conn)
    }

    fn auth(&mut self, password: &str) -> Result<HandshakeStatus, Error> {
        let auth_id = self.send(AuthRequest, password)?;

        // The protocol says that the server response to an Auth packet is:
        //   1. An empty ResponseValue with ID matching the Auth packet, followed by
        //   2. An AuthResponse, which ID indicate authentication success/failure.
        // However, some servers may still respond only with an AuthResponse.
        // The implementation below will check the ID if a ResponseValue is received,
        // but will also accept an AuthResponse upfront.

        let (response, status) = loop {
            let p = Packet::deserialize(&mut self.stream)?;
            match p.ptype {
                Response(ResponseValue) => {
                    // Received an empty ResponseValue, which should match the `auth_id`.
                    if p.body.is_empty() && p.id == auth_id {
                        break (None, HandshakeStatus::Matched);
                    }
                }
                Response(AuthResponse) => {
                    // No ResponseValue received with matching ID, just the AuthResponse.
                    break (Some(p), HandshakeStatus::BareAuthResponse);
                }
                _ => {}
            }
        };

        let auth_response = match response {
            Some(p) => p,
            None => Packet::deserialize(&mut self.stream)?, // receive next packet as AuthResponse
        };

        // Check if authentication was successful.
        if auth_response.ptype != Response(AuthResponse) || auth_response.is_error() {
            return Err(Error::AuthFailure);
        }

        Ok(status)
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
        self.send(ExecCommand, cmd)?;
        let response = self.recv_multi_packet_response()?;

        Ok(response)
    }

    fn send(&mut self, request: ReqType, body: &str) -> Result<i32, Error> {
        let id = self.fetch_and_add_id();
        let packet = Packet::new(id, Request(request), body.into())?;
        packet.serialize(&mut self.stream)?;
        Ok(id)
    }

    fn recv_multi_packet_response(&mut self) -> Result<String, Error> {
        // Send an empty ExecCommand packet, just after the actual client request packet.
        // Since the server always responds to requests in the receiving order (FIFO), we
        // can detect the end of a multi-packet response when receiving the response to the
        // empty packet.
        let end_id = self.send(ExecCommand, "")?; // empty packet
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
