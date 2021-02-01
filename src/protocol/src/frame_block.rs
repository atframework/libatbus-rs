//! libatbus-protocol algorithm for frame block

use murmur3;

use super::error::{ProtocolError, ProtocolResult};

use std::io::Cursor;

pub const FRAME_HASH_SIZE: usize = 4;
const FRAME_HASH_MAGIC: u32 = 0x01000193;

#[allow(dead_code)]
pub struct FrameBlock {}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameLength {
    /// Consumed buffer size
    pub consume: usize,
    /// Decoded length
    pub length: u64,
}

impl FrameBlock {
    /// Create a FrameBlock with reference data buffer
    pub fn new() -> FrameBlock {
        FrameBlock {}
    }

    pub fn validate(&self) -> bool {
        false
    }

    /// Compute hash code for buffer data
    pub fn hash<T: AsRef<[u8]>>(rem: T) -> [u8; FRAME_HASH_SIZE] {
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
    pub fn decode_frame_length<T: AsRef<[u8]>>(input: T) -> ProtocolResult<FrameLength> {
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
                    return Err(ProtocolError::IncorrectVarint);
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
    #[inline]
    pub fn compute_frame_length_consume(mut value: u64) -> usize {
        let mut result: usize = 1;
        while (value & !0x7F) > 0 {
            value >>= 7;
            result += 1;
        }

        result
    }

    /// Encode frame length into buffer and return the consumed buffer length
    #[inline]
    pub fn encode_frame_length<T: AsMut<[u8]>>(
        mut output: T,
        mut value: u64,
    ) -> ProtocolResult<usize> {
        let mut consume: usize = 0;
        let buf = output.as_mut();

        unsafe {
            while (value & !0x7F) > 0 {
                if consume >= buf.len() {
                    return Err(ProtocolError::BufferNotEnough);
                }

                *buf.get_unchecked_mut(consume) = ((value & 0x7F) | 0x80) as u8;
                value >>= 7;
                consume += 1;
            }

            if consume >= buf.len() {
                return Err(ProtocolError::BufferNotEnough);
            }

            *buf.get_unchecked_mut(consume) = value as u8;
        }

        Ok(consume + 1)
    }
}

#[cfg(test)]
mod test {
    use super::super::error::ProtocolError;
    use super::FrameBlock;
    use super::FrameLength;

    #[test]
    fn test_decode_frame_length_error() {
        let decode_result = FrameBlock::decode_frame_length(&[0x96]);
        match decode_result.unwrap_err() {
            ProtocolError::TruncatedFrameLength => assert!(true),
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::TruncatedFrameLength,
                e
            ),
        }

        let decode_result = FrameBlock::decode_frame_length(&[
            0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96, 0x96,
        ]);
        match decode_result.unwrap_err() {
            ProtocolError::IncorrectVarint => assert!(true),
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::IncorrectVarint,
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
            FrameBlock::decode_frame_length(&[0x07]).unwrap()
        );

        assert_eq!(
            FrameLength {
                consume: 2,
                length: 150
            },
            FrameBlock::decode_frame_length(&[0x96, 0x01]).unwrap()
        );

        assert_eq!(
            FrameLength {
                consume: 10,
                length: 0xffffffffffffffff
            },
            FrameBlock::decode_frame_length(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
            ])
            .unwrap()
        );

        assert_eq!(
            FrameLength {
                consume: 5,
                length: 0xffffffff
            },
            FrameBlock::decode_frame_length(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap()
        );
    }

    #[test]
    fn test_encode_frame_length_error() {
        let mut buffer: [u8; 16] = [0; 16];
        let encode_result = FrameBlock::encode_frame_length(&mut buffer[0..9], 0xffffffffffffffff);
        match encode_result.unwrap_err() {
            ProtocolError::BufferNotEnough => assert!(true),
            e => panic!(
                "Expect {:?}: real got {:?}",
                ProtocolError::BufferNotEnough,
                e
            ),
        }
    }

    #[test]
    fn test_encode_frame_length() {
        let mut buffer: [u8; 16] = [0; 16];

        assert_eq!(1, FrameBlock::encode_frame_length(&mut buffer, 7).unwrap());
        assert_eq!(1, FrameBlock::compute_frame_length_consume(7));
        assert_eq!(&buffer[0..1], &[0x07]);

        assert_eq!(
            2,
            FrameBlock::encode_frame_length(&mut buffer, 150).unwrap()
        );
        assert_eq!(2, FrameBlock::compute_frame_length_consume(150));
        assert_eq!(&buffer[0..2], &[0x96, 0x01]);

        assert_eq!(
            10,
            FrameBlock::encode_frame_length(&mut buffer[0..10], 0xffffffffffffffff).unwrap()
        );
        assert_eq!(
            10,
            FrameBlock::compute_frame_length_consume(0xffffffffffffffff)
        );
        assert_eq!(
            &buffer[0..10],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );

        assert_eq!(
            5,
            FrameBlock::encode_frame_length(&mut buffer, 0xffffffff).unwrap()
        );
        assert_eq!(5, FrameBlock::compute_frame_length_consume(0xffffffff));
        assert_eq!(&buffer[0..5], &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn test_hash() {
        assert_eq!(
            [49, 98, 162, 47],
            FrameBlock::hash(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        )
    }
}
