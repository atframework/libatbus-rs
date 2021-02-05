//! libatbus-protocol algorithm for frame block

use murmur3;

use super::error::{ProtocolError, ProtocolResult};

use std::convert::Into;
use std::io::Cursor;

pub const FRAME_HASH_SIZE: usize = 4;
pub const FRAME_VARINT_RESERVE_SIZE: usize = 16;
const FRAME_HASH_MAGIC: u32 = 0x01000193;

#[allow(dead_code)]
pub struct FrameBlockAlgorithm;

pub struct FrameBlock<T>
where
    T: AsRef<[u8]>,
{
    data_block: T,
    validate_cache: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameLength {
    /// Consumed buffer size
    pub consume: usize,
    /// Decoded length
    pub length: u64,
}

impl FrameBlockAlgorithm {
    /// Compute hash code for buffer data
    pub fn hash<U: AsRef<[u8]>>(rem: &U) -> [u8; FRAME_HASH_SIZE] {
        let mut result: [u8; FRAME_HASH_SIZE] = [0; FRAME_HASH_SIZE];
        let mut cursor = Cursor::new(rem);

        if let Ok(mut hash_integer) = murmur3::murmur3_x64_128(&mut cursor, FRAME_HASH_MAGIC) {
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
    pub fn decode_frame_length<U: AsRef<[u8]>>(input: &U) -> ProtocolResult<FrameLength> {
        let rem = input.as_ref();
        if rem.len() == 0 {
            return Err(ProtocolError::TruncatedFrameLength);
        }

        if rem[0] < 0x80 {
            Ok(FrameLength {
                consume: 1,
                length: rem[0] as u64,
            })
        } else if rem.len() >= 2 && rem[1] < 0x80 {
            Ok(FrameLength {
                consume: 2,
                length: (rem[0] & 0x7f) as u64 | (rem[1] as u64) << 7,
            })
        } else {
            let mut consume: usize = 1;
            let mut length: u64 = (rem[0] & 0x7f) as u64;
            let mut loff = 7;
            loop {
                if consume >= 10 {
                    return Err(ProtocolError::BadFrameLength);
                }

                if consume >= rem.len() {
                    return Err(ProtocolError::TruncatedFrameLength);
                }

                length |= ((rem[consume] & 0x7f) as u64) << loff;
                if rem[consume] < 0x80 {
                    consume += 1;
                    break;
                }

                consume += 1;
                loff += 7;
            }

            Ok(FrameLength {
                consume: consume,
                length: length,
            })
        }
    }

    /// Compute buffer length need to encode frame length
    #[allow(dead_code)]
    #[inline]
    pub fn compute_frame_length_consume<U: Into<u64>>(input: U) -> usize {
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
    pub fn encode_frame_length<T: AsMut<[u8]>, U: Into<u64>>(
        output: &mut T,
        input: U,
    ) -> ProtocolResult<usize> {
        let origin_input: u64 = input.into();
        let mut value: u64 = origin_input;
        let mut consume: usize = 0;
        let buf = output.as_mut();

        unsafe {
            while (value & !0x7F) > 0 {
                if consume >= buf.len() {
                    return Err(ProtocolError::BufferNotEnough(
                        FrameBlockAlgorithm::compute_frame_length_consume(origin_input),
                        buf.len(),
                    ));
                }

                *buf.get_unchecked_mut(consume) = ((value & 0x7F) | 0x80) as u8;
                value >>= 7;
                consume += 1;
            }

            if consume >= buf.len() {
                return Err(ProtocolError::BufferNotEnough(
                    FrameBlockAlgorithm::compute_frame_length_consume(origin_input),
                    buf.len(),
                ));
            }

            *buf.get_unchecked_mut(consume) = value as u8;
        }

        Ok(consume + 1)
    }
}

impl<T> FrameBlock<T>
where
    T: AsRef<[u8]>,
{
    /// Create a FrameBlock with reference data buffer
    pub fn new(rem: T) -> FrameBlock<T> {
        let data_block = rem.as_ref();
        let validate_cache = if data_block.len() < FRAME_HASH_SIZE {
            false
        } else {
            let data_buffer = &data_block[0..data_block.len() - FRAME_HASH_SIZE];
            FrameBlockAlgorithm::hash(&data_buffer)
                == data_block[data_block.len() - FRAME_HASH_SIZE..]
        };
        FrameBlock {
            data_block: rem,
            validate_cache: validate_cache,
        }
    }

    pub fn validate(&self) -> bool {
        self.validate_cache
    }

    pub fn data(&self) -> Option<&[u8]> {
        if self.validate() {
            let data_block = self.data_block.as_ref();
            Some(&data_block[0..data_block.len() - FRAME_HASH_SIZE])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::error::ProtocolError;
    use super::FrameLength;
    use super::{FrameBlockAlgorithm, FRAME_VARINT_RESERVE_SIZE};

    #[test]
    fn test_decode_frame_length_error() {
        let decode_result = FrameBlockAlgorithm::decode_frame_length(&[0x96]);
        match decode_result.unwrap_err() {
            ProtocolError::TruncatedFrameLength => assert!(true),
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::TruncatedFrameLength,
                e
            ),
        }

        let decode_result = FrameBlockAlgorithm::decode_frame_length(&[
            0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96,
        ]);
        match decode_result.unwrap_err() {
            ProtocolError::BadFrameLength => assert!(true),
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::BadFrameLength,
                e
            ),
        }
    }

    #[test]
    fn test_decode_frame_length() {
        assert_eq!(
            FrameLength {
                consume: 1,
                length: 7
            },
            FrameBlockAlgorithm::decode_frame_length(&[0x07]).unwrap()
        );

        assert_eq!(
            FrameLength {
                consume: 2,
                length: 150
            },
            FrameBlockAlgorithm::decode_frame_length(&[0x96, 0x01]).unwrap()
        );

        assert_eq!(
            FrameLength {
                consume: 10,
                length: 0xffffffffffffffff
            },
            FrameBlockAlgorithm::decode_frame_length(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
            ])
            .unwrap()
        );

        assert_eq!(
            FrameLength {
                consume: 5,
                length: 0xffffffff
            },
            FrameBlockAlgorithm::decode_frame_length(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap()
        );
    }

    #[test]
    fn test_encode_frame_length_error() {
        let mut buffer: [u8; FRAME_VARINT_RESERVE_SIZE] = [0; FRAME_VARINT_RESERVE_SIZE];
        let mut invalid_buffer = &mut buffer[0..9];
        let encode_result = FrameBlockAlgorithm::encode_frame_length(
            &mut invalid_buffer,
            0xffffffffffffffff as u64,
        );
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
    fn test_encode_frame_length() {
        let mut buffer: [u8; FRAME_VARINT_RESERVE_SIZE] = [0; FRAME_VARINT_RESERVE_SIZE];

        assert_eq!(
            1,
            FrameBlockAlgorithm::encode_frame_length(&mut buffer, 7 as u64).unwrap()
        );
        assert_eq!(
            1,
            FrameBlockAlgorithm::compute_frame_length_consume(7 as u64)
        );
        assert_eq!(&buffer[0..1], &[0x07]);

        assert_eq!(
            2,
            FrameBlockAlgorithm::encode_frame_length(&mut buffer, 150 as u64).unwrap()
        );
        assert_eq!(
            2,
            FrameBlockAlgorithm::compute_frame_length_consume(150 as u64)
        );
        assert_eq!(&buffer[0..2], &[0x96, 0x01]);

        let mut valid_buffer = &mut buffer[0..10];
        assert_eq!(
            10,
            FrameBlockAlgorithm::encode_frame_length(&mut valid_buffer, 0xffffffffffffffff as u64)
                .unwrap()
        );
        assert_eq!(
            10,
            FrameBlockAlgorithm::compute_frame_length_consume(0xffffffffffffffff as u64)
        );
        assert_eq!(
            &buffer[0..10],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );

        assert_eq!(
            5,
            FrameBlockAlgorithm::encode_frame_length(&mut buffer, 0xffffffff as u64).unwrap()
        );
        assert_eq!(
            5,
            FrameBlockAlgorithm::compute_frame_length_consume(0xffffffff as u64)
        );
        assert_eq!(&buffer[0..5], &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn test_hash() {
        assert_eq!(
            [49, 98, 162, 47],
            FrameBlockAlgorithm::hash(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        )
    }
}
