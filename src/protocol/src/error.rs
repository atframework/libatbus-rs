//! libatbus-protocol error type

use std::error::Error;
use std::fmt;
use std::io;
use std::str;

use prost::{DecodeError, EncodeError};

#[derive(Debug)]
pub enum ProtocolError {
    /// I/O error when reading or writing
    IoError(io::Error),
    /// Need more data to decode frame length (varint)
    TruncatedFrameLength,
    /// Malformed varint of frame length
    BadFrameLength,
    /// Frame length limit exceeded(limit, got)
    FrameLengthLimitExceeded(usize, usize),
    /// Buffer not enough to encode data(need, has)
    BufferNotEnough(usize, usize),
    /// Need more data to decode packet
    TruncatedPacket,
    /// Need pick packet before write more data
    HasPendingPacket,
    /// Decode failed
    DecodeFailed(DecodeError),
    /// Encode failed
    EncodeFailed(EncodeError),
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            &ProtocolError::IoError(ref e) => write!(f, "IO error: {}", e),
            ProtocolError::TruncatedFrameLength => write!(
                f,
                "truncated frame length, maybe need more data o decode it"
            ),
            ProtocolError::BadFrameLength => write!(f, "incorrect varint of frame length"),
            &ProtocolError::FrameLengthLimitExceeded(ref limit, ref got) => {
                write!(
                    f,
                    "frame length limit exceeded, limit {}, got {}",
                    limit, got
                )
            }
            &ProtocolError::BufferNotEnough(ref need, ref has) => write!(
                f,
                "buffer not enough, require {} byte(s), but we only got {} byte(s)",
                need, has
            ),
            ProtocolError::TruncatedPacket => {
                write!(f, "truncated packet, maybe need more data o decode it")
            }
            ProtocolError::HasPendingPacket => {
                write!(f, "need pick packet before put more data")
            }
            &ProtocolError::DecodeFailed(ref e) => {
                write!(f, "decode failed: {}", e)
            }
            &ProtocolError::EncodeFailed(ref e) => {
                write!(f, "encode failed: {}", e)
            }
        }
    }
}

impl Error for ProtocolError {
    #[allow(deprecated)] // call to `description`
    fn description(&self) -> &str {
        match &self {
            &ProtocolError::IoError(ref e) => e.description(),
            &ProtocolError::TruncatedFrameLength => {
                "truncated frame length, maybe need more data o decode it"
            }
            &ProtocolError::BadFrameLength => "incorrect varint of frame length",
            &ProtocolError::FrameLengthLimitExceeded(_, _) => "frame length limit exceeded",
            &ProtocolError::BufferNotEnough(_, _) => "buffer not enough",
            &ProtocolError::TruncatedPacket => "truncated packet, maybe need more data o decode it",
            &ProtocolError::HasPendingPacket => "need pick packet before put more data",
            &ProtocolError::DecodeFailed(ref e) => &e.description(),
            &ProtocolError::EncodeFailed(ref e) => &e.description(),
        }
    }

    fn cause(&self) -> Option<&dyn Error> {
        match self {
            &ProtocolError::IoError(ref e) => Some(e),
            _ => Some(self),
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(err: io::Error) -> Self {
        ProtocolError::IoError(err)
    }
}

impl From<ProtocolError> for io::Error {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::IoError(e) => e,
            e => io::Error::new(io::ErrorKind::Other, Box::new(e)),
        }
    }
}
