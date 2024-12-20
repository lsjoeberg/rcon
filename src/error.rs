use crate::packet::{MAX_CMD_SIZE, MAX_PACKET_SIZE, MAX_PAYLOAD_SIZE, MIN_PACKET_SIZE};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("bad packet from server")]
    BadResponsePacket,

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("invalid data")]
    InvalidData(#[from] std::string::FromUtf8Error),

    #[error("command too long {0} (expected <= {hi})", hi=MAX_CMD_SIZE)]
    CmdTooLong(usize),

    #[error("payload too long {0} (expected <= {hi})", hi=MAX_PAYLOAD_SIZE)]
    PayloadTooLong(usize),

    #[error(
        "invalid packet size {0} (expected size in [{lo}, {hi}])",
        lo=MIN_PACKET_SIZE,
        hi=MAX_PACKET_SIZE
    )]
    InvalidPacketSize(usize),

    #[error("authentication failed")]
    AuthFailure,
}
