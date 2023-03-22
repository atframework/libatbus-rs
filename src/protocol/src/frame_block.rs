// Copyright 2023 atframework
// Licensed under the MIT licenses.

//! libatbus-protocol algorithm for frame block

use murmur3;

use super::error::{ProtocolError, ProtocolResult};

use std::convert::Into;
use std::io;

pub const FRAME_HASH_SIZE: usize = 4;
const FRAME_HASH_MAGIC: u32 = 0x01000193;

#[allow(dead_code)]
pub struct FrameBlockAlgorithm;

#[derive(Debug, Clone, PartialEq)]
pub struct VarintData {
    /// Consumed buffer size
    pub consume: usize,
    /// Decoded value
    pub value: u64,
}

impl FrameBlockAlgorithm {
    /// Compute hash code for buffer data
    pub fn hash<U>(rem: U) -> [u8; FRAME_HASH_SIZE]
    where
        U: bytes::Buf,
    {
        let mut result: [u8; FRAME_HASH_SIZE] = [0; FRAME_HASH_SIZE];

        if let Ok(mut hash_integer) = murmur3::murmur3_x64_128(&mut rem.reader(), FRAME_HASH_MAGIC)
        {
            unsafe {
                for i in 0..FRAME_HASH_SIZE {
                    *result.get_unchecked_mut(i) = hash_integer as u8;
                    hash_integer >>= 8;
                }
            }
        }

        result
    }

    /// Try to decode frame length from buffer
    #[inline]
    pub fn decode_varint<U>(input: U) -> ProtocolResult<VarintData>
    where
        U: bytes::Buf,
    {
        if input.remaining() == 0 {
            return Err(ProtocolError::TruncatedVarint);
        }

        let rem = input.chunk();

        if rem[0] < 0x80 {
            Ok(VarintData {
                consume: 1,
                value: rem[0] as u64,
            })
        } else if rem.len() >= 2 && rem[1] < 0x80 {
            Ok(VarintData {
                consume: 2,
                value: (rem[0] & 0x7f) as u64 | (rem[1] as u64) << 7,
            })
        } else {
            let mut consume: usize = 1;
            let mut length: u64 = (rem[0] & 0x7f) as u64;
            let mut loff = 7;
            loop {
                if consume >= 10 {
                    return Err(ProtocolError::IoError(io::Error::from(
                        io::ErrorKind::InvalidInput,
                    )));
                }

                if consume >= rem.len() {
                    return Err(ProtocolError::TruncatedVarint);
                }

                length |= ((rem[consume] & 0x7f) as u64) << loff;
                if rem[consume] < 0x80 {
                    consume += 1;
                    break;
                }

                consume += 1;
                loff += 7;
            }

            Ok(VarintData {
                consume: consume,
                value: length,
            })
        }
    }

    /// Compute buffer length need to encode frame length
    #[allow(dead_code)]
    #[inline]
    pub fn compute_varint_consume<U: Into<u64>>(input: U) -> usize {
        let mut value: u64 = input.into();
        let mut result: usize = 1;
        while (value & !0x7F) > 0 {
            value >>= 7;
            result += 1;
        }

        result
    }

    /// Encode frame length into buffer and return the consumed buffer length
    #[inline]
    pub fn encode_varint<T, U>(mut output: T, input: U) -> ProtocolResult<usize>
    where
        T: bytes::BufMut,
        U: Into<u64>,
    {
        let origin_input: u64 = input.into();
        let mut value: u64 = origin_input;
        let mut consume: usize = 0;

        while (value & !0x7F) > 0 {
            if consume >= output.remaining_mut() {
                return Err(ProtocolError::BufferNotEnough(
                    FrameBlockAlgorithm::compute_varint_consume(origin_input),
                    output.remaining_mut(),
                ));
            }

            output
                .chunk_mut()
                .write_byte(consume, ((value & 0x7F) | 0x80) as u8);
            value >>= 7;
            consume += 1;
        }

        if consume >= output.remaining_mut() {
            return Err(ProtocolError::BufferNotEnough(
                FrameBlockAlgorithm::compute_varint_consume(origin_input),
                output.remaining_mut(),
            ));
        }

        output.chunk_mut().write_byte(consume, value as u8);

        Ok(consume + 1)
    }
}

#[cfg(test)]
mod test {
    use super::super::error::ProtocolError;
    use super::FrameBlockAlgorithm;
    use super::VarintData;
    use std::io;

    #[test]
    fn test_decode_varint_error() {
        let buf = &[0x96][..];
        let decode_result = FrameBlockAlgorithm::decode_varint(buf);
        match decode_result.unwrap_err() {
            ProtocolError::TruncatedVarint => assert!(true),
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::TruncatedVarint,
                e
            ),
        }

        let decode_result = FrameBlockAlgorithm::decode_varint(
            &[0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96][..],
        );
        match decode_result.unwrap_err() {
            ProtocolError::IoError(e) => {
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            }
            e => panic!(
                "Expect IoError(io::Error(io::ErrorKind::InvalidInput)): real got {:?}",
                e
            ),
        }
    }

    #[test]
    fn test_decode_varint() {
        assert_eq!(
            VarintData {
                consume: 1,
                value: 7
            },
            FrameBlockAlgorithm::decode_varint(&[0x07][..]).unwrap()
        );

        assert_eq!(
            VarintData {
                consume: 2,
                value: 150
            },
            FrameBlockAlgorithm::decode_varint(&[0x96, 0x01][..]).unwrap()
        );

        assert_eq!(
            VarintData {
                consume: 10,
                value: 0xffffffffffffffff
            },
            FrameBlockAlgorithm::decode_varint(
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01][..]
            )
            .unwrap()
        );

        assert_eq!(
            VarintData {
                consume: 5,
                value: 0xffffffff
            },
            FrameBlockAlgorithm::decode_varint(&[0xff, 0xff, 0xff, 0xff, 0x0f][..]).unwrap()
        );
    }

    #[test]
    fn test_encode_varint_error() {
        let mut buffer: [u8; 16] = [0; 16];
        let mut invalid_buffer = &mut buffer[0..9];
        let encode_result =
            FrameBlockAlgorithm::encode_varint(&mut invalid_buffer, 0xffffffffffffffff as u64);
        match encode_result.unwrap_err() {
            ProtocolError::BufferNotEnough(need, has) => {
                assert_eq!(need, 10);
                assert_eq!(has, 9);
            }
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::BufferNotEnough(10, 9),
                e
            ),
        }
    }

    #[test]
    fn test_encode_varint() {
        let mut buffer: [u8; 16] = [0; 16];

        assert_eq!(
            1,
            FrameBlockAlgorithm::encode_varint(&mut buffer[..], 7 as u64).unwrap()
        );
        assert_eq!(1, FrameBlockAlgorithm::compute_varint_consume(7 as u64));
        assert_eq!(&buffer[0..1], &[0x07]);

        assert_eq!(
            2,
            FrameBlockAlgorithm::encode_varint(&mut buffer[..], 150 as u64).unwrap()
        );
        assert_eq!(2, FrameBlockAlgorithm::compute_varint_consume(150 as u64));
        assert_eq!(&buffer[0..2], &[0x96, 0x01]);

        let mut valid_buffer = &mut buffer[0..10];
        assert_eq!(
            10,
            FrameBlockAlgorithm::encode_varint(&mut valid_buffer, 0xffffffffffffffff as u64)
                .unwrap()
        );
        assert_eq!(
            10,
            FrameBlockAlgorithm::compute_varint_consume(0xffffffffffffffff as u64)
        );
        assert_eq!(
            &buffer[0..10],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );

        assert_eq!(
            5,
            FrameBlockAlgorithm::encode_varint(&mut buffer[..], 0xffffffff as u64).unwrap()
        );
        assert_eq!(
            5,
            FrameBlockAlgorithm::compute_varint_consume(0xffffffff as u64)
        );
        assert_eq!(&buffer[0..5], &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn test_hash() {
        assert_eq!(
            [49, 98, 162, 47],
            FrameBlockAlgorithm::hash(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9][..])
        )
    }
}
