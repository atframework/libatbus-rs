// Copyright 2023 atframework
// Licensed under the MIT licenses.

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
    /// Need more data to decode varint
    TruncatedVarint,
    /// Need more data to decode frame message length (varint)
    TruncatedFrameMessageLength,
    /// Need more data to decode protocol version (varint)
    TruncatedProtocolVersionLength,
    /// Message length limit exceeded(limit, got)
    MessageLengthLimitExceeded(usize, usize),
    /// Buffer not enough to encode data(need, has)
    BufferNotEnough(usize, usize),
    /// Need more data to decode message
    TruncatedMessage,
    /// Protocol hash code mismatch(expect, got)
    ProtocolHashMismatch(Vec<u8>, Vec<u8>),
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
            ProtocolError::TruncatedVarint => {
                write!(f, "truncated varint, maybe need more data to decode it")
            }
            ProtocolError::TruncatedFrameMessageLength => write!(
                f,
                "truncated frame message length, maybe need more data to decode it"
            ),
            ProtocolError::TruncatedProtocolVersionLength => {
                write!(
                    f,
                    "truncated protocol version, maybe need more data to decode it"
                )
            }
            &ProtocolError::MessageLengthLimitExceeded(ref limit, ref got) => {
                write!(
                    f,
                    "message length limit exceeded, limit {}, got {}",
                    limit, got
                )
            }
            &ProtocolError::BufferNotEnough(ref need, ref has) => write!(
                f,
                "buffer not enough, require {} byte(s), but we only got {} byte(s)",
                need, has
            ),
            ProtocolError::TruncatedMessage => {
                write!(f, "truncated message, maybe need more data to decode it")
            }
            ProtocolError::ProtocolHashMismatch(e, r) => {
                write!(f, "protocol hash mismatch, expect: {:?}, got: {:?}", e, r)
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
            &ProtocolError::TruncatedVarint => {
                "truncated varint, maybe need more data to decode it"
            }
            &ProtocolError::TruncatedFrameMessageLength => {
                "truncated frame message length, maybe need more data to decode it"
            }
            &ProtocolError::TruncatedProtocolVersionLength => {
                "truncated protocol version, maybe need more data to decode it"
            }
            &ProtocolError::MessageLengthLimitExceeded(_, _) => "message length limit exceeded",
            &ProtocolError::BufferNotEnough(_, _) => "buffer not enough",
            &ProtocolError::TruncatedMessage => {
                "truncated message, maybe need more data to decode it"
            }
            &ProtocolError::ProtocolHashMismatch(_, _) => "protocol hash mismatch",
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
