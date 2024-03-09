use thiserror::Error;

#[derive(Error, Debug)]
pub enum RconError {
    #[error("invalid packet")]
    InvalidPacket,
    #[error("todo")]
    IO(#[from] std::io::Error),
    #[error("invalid data")]
    InvalidData(#[from] std::string::FromUtf8Error),
}
