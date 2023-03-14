// Copyright 2023 atframework
// Licensed under the MIT licenses.

//! libatbus-protocol decoder

use crate::prost::{DecodeError, Message};

use super::frame_block;
use super::{BoxedFrameMessage, FrameMessage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderError<'a> {
    /// Decode version
    NeedMoreDataToDecodeVersion,
    /// Decode frame length
    NeedMoreDataToDecodeLength,
    /// Decode message
    NeedMoreDataToDecodeMessage,
    /// Decode hash
    NeedMoreDataToDecodeHash,
    /// Invalid Hash(message buffer, cosume size)
    InvalidHash(&'a [u8], usize),
    /// Failed to decode message(message buffer, cosume size)
    DecodeMessageFailed(&'a [u8], usize, DecodeError),
}

struct DecoderRawLength {
    pub version: u64,
    pub message_length: u64,
    pub message_offset: usize,
    pub total_length: usize,
}

struct DecoderRawMessage<'a> {
    pub version: u64,
    pub message_data: &'a [u8],
    pub total_length: usize,
}

pub struct DecoderFrame {
    pub message: BoxedFrameMessage,
    pub consume_length: usize,
    pub version: u64,
}

pub struct Decoder {}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder {}
    }

    fn try_decode_raw_length<'a, T: Into<&'a [u8]>>(
        input: T,
    ) -> Result<DecoderRawLength, DecoderError<'a>> {
        let buffer: &[u8] = input.into();
        let mut start_offset = 0;
        let version = if let Ok(x) = frame_block::FrameBlockAlgorithm::decode_varint(&buffer) {
            start_offset += x.consume;
            x.value
        } else {
            return Err(DecoderError::NeedMoreDataToDecodeVersion);
        };

        let message_length = if let Ok(x) =
            frame_block::FrameBlockAlgorithm::decode_varint(&&buffer[start_offset..buffer.len()])
        {
            start_offset += x.consume;
            x.value
        } else {
            return Err(DecoderError::NeedMoreDataToDecodeLength);
        };

        Ok(DecoderRawLength {
            version: version,
            message_length: message_length,
            message_offset: start_offset,
            total_length: start_offset + (message_length as usize) + frame_block::FRAME_HASH_SIZE,
        })
    }

    fn try_decode_raw_message<'a, T: Into<&'a [u8]>>(
        input: T,
    ) -> Result<DecoderRawMessage<'a>, DecoderError<'a>> {
        let buffer: &[u8] = input.into();
        let raw_length = Self::try_decode_raw_length(buffer)?;

        let hash_data_offset = raw_length.message_offset + (raw_length.message_length as usize);
        if hash_data_offset > buffer.len() {
            Err(DecoderError::NeedMoreDataToDecodeMessage)
        } else if raw_length.total_length > buffer.len() {
            Err(DecoderError::NeedMoreDataToDecodeHash)
        } else {
            let message_data = &buffer[raw_length.message_offset..hash_data_offset];
            let hash_data = &buffer[hash_data_offset..raw_length.total_length];

            let target_buffer_to_calc_hash = &buffer[0..hash_data_offset];
            let expect_hash = frame_block::FrameBlockAlgorithm::hash(&target_buffer_to_calc_hash);
            if expect_hash != hash_data {
                return Err(DecoderError::InvalidHash(
                    message_data,
                    raw_length.total_length,
                ));
            }

            Ok(DecoderRawMessage {
                version: raw_length.version,
                message_data: message_data,
                total_length: raw_length.total_length,
            })
        }
    }

    pub fn is_completed<'a, T: Into<&'a [u8]>>(&self, input: T) -> Result<(), DecoderError<'a>> {
        let buffer: &[u8] = input.into();
        let raw_length = Self::try_decode_raw_length(buffer)?;

        if buffer.len() < raw_length.message_offset + raw_length.message_length as usize {
            Err(DecoderError::NeedMoreDataToDecodeMessage)
        } else if buffer.len() < raw_length.total_length {
            Err(DecoderError::NeedMoreDataToDecodeHash)
        } else {
            Ok(())
        }
    }

    pub fn peek<'a, T: Into<&'a [u8]>>(&self, input: T) -> Result<DecoderFrame, DecoderError<'a>> {
        let state = Self::try_decode_raw_message(input)?;

        let message = match FrameMessage::decode(state.message_data) {
            Ok(x) => Box::new(x),
            Err(e) => {
                return Err(DecoderError::DecodeMessageFailed(
                    state.message_data,
                    state.total_length,
                    e,
                ))
            }
        };

        Ok(DecoderFrame {
            message: message,
            consume_length: state.total_length,
            version: state.version,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::libatbus_utility;
    use crate::rand::{thread_rng, Rng};
    use std::time;

    use super::super::encoder::{Encoder, EncoderFrame};
    use super::super::proto;
    use super::super::PacketFlagType;
    use super::super::PacketMessage;
    use super::Decoder;
    use super::DecoderError;
    use super::FrameMessage;

    fn pack_message(msg: &FrameMessage) -> bytes::Bytes {
        let encode_frame = EncoderFrame::new(&msg);
        let mut ret = bytes::BytesMut::with_capacity(encode_frame.get_total_length());

        let encoder = Encoder::new();
        let _ = encoder.put_bytes(encode_frame, &mut ret);

        ret.freeze()
    }

    fn generate_packet_message(content_length: usize) -> FrameMessage {
        let head = proto::atbus::protocol::MessageHead {
            source: libatbus_utility::unique_id::generate_stanard_uuid_v4().to_vec(),
            destination: libatbus_utility::unique_id::generate_stanard_uuid_v4().to_vec(),
            forward_for_source: vec![],
            forward_for_connection_id: 0,
        };
        let mut body = PacketMessage {
            stream_id: 1,
            stream_offset: 0,
            content: vec![b'0'; content_length],
            flags: PacketFlagType::ResetOffset as i32,
            padding_size: thread_rng().gen_range(0..content_length / 2) as i32,
            timepoint_microseconds: time::SystemTime::now()
                .duration_since(time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
        };
        thread_rng().fill(body.content.as_mut_slice());

        let ret = FrameMessage {
            head: Some(head),
            body: Some(proto::atbus::protocol::frame_message::Body::Packet(body)),
        };

        ret
    }

    fn expect_option<T>(left: &Option<T>, right: &Option<T>) -> bool {
        assert_eq!(left.is_some(), right.is_some());
        left.is_some() && right.is_some()
    }

    fn expect_msg_head_eq(
        left: &proto::atbus::protocol::MessageHead,
        right: &proto::atbus::protocol::MessageHead,
    ) {
        assert_eq!(left.source, right.source);
        assert_eq!(left.destination, right.destination);
        assert_eq!(left.forward_for_source, right.forward_for_source);
        assert_eq!(
            left.forward_for_connection_id,
            right.forward_for_connection_id
        );
    }

    fn expect_msg_eq(left: &FrameMessage, right: &FrameMessage) {
        if expect_option(&left.head, &right.head) {
            expect_msg_head_eq(left.head.as_ref().unwrap(), right.head.as_ref().unwrap());
        }

        assert_eq!(left.body, right.body);
    }

    #[test]
    fn test_decoder_message_from_head() {
        let decoder = Decoder::new();
        let msg1 = generate_packet_message(thread_rng().gen_range(256..2048));

        let msg1_block = pack_message(&msg1);

        // Incompleted version
        {
            let empty_buffer: Vec<u8> = vec![];
            assert_eq!(
                Err(DecoderError::NeedMoreDataToDecodeVersion),
                decoder.is_completed(empty_buffer.as_slice())
            );

            let result = decoder.peek(empty_buffer.as_slice());
            assert!(result.is_err());
            if let Err(e) = result {
                assert_eq!(DecoderError::NeedMoreDataToDecodeVersion, e);
            }
        }

        // Incompleted length
        {
            let partly_buffer = &msg1_block[0..2];

            assert_eq!(
                Err(DecoderError::NeedMoreDataToDecodeLength),
                decoder.is_completed(partly_buffer)
            );

            let result = decoder.peek(partly_buffer);
            assert!(result.is_err());
            if let Err(e) = result {
                assert_eq!(DecoderError::NeedMoreDataToDecodeLength, e);
            }
        }

        // Incompleted message
        {
            let partly_buffer = &msg1_block[0..200];

            assert_eq!(
                Err(DecoderError::NeedMoreDataToDecodeMessage),
                decoder.is_completed(partly_buffer)
            );

            let result = decoder.peek(partly_buffer);
            assert!(result.is_err());
            if let Err(e) = result {
                assert_eq!(DecoderError::NeedMoreDataToDecodeMessage, e);
            }
        }

        // Incompleted hash
        {
            let partly_buffer = &msg1_block[0..msg1_block.len() - 1];

            assert_eq!(
                Err(DecoderError::NeedMoreDataToDecodeHash),
                decoder.is_completed(partly_buffer)
            );

            let result = decoder.peek(partly_buffer);
            assert!(result.is_err());
            if let Err(e) = result {
                assert_eq!(DecoderError::NeedMoreDataToDecodeHash, e);
            }
        }

        // Invalid hash
        {
            let mut full_buffer = msg1_block.to_vec();
            (*full_buffer.get_mut(msg1_block.len() - 1).unwrap()) += 1;

            assert!(decoder.is_completed(full_buffer.as_slice()).is_ok());

            let result = decoder.peek(full_buffer.as_slice());
            assert!(result.is_err());
            match result {
                Err(e) => match e {
                    DecoderError::InvalidHash(_, _) => {}
                    _ => {
                        println!("Expect DecoderError::InvalidHash, real got {:?}", e);
                        assert!(false);
                    }
                },
                _ => {
                    println!("Expect DecoderError::InvalidHash, real got Ok");
                    assert!(false);
                }
            }
        }

        // Unpack success
        {
            let full_buffer = msg1_block.to_vec();
            let decode_result = decoder.peek(full_buffer.as_slice());
            assert!(decode_result.is_ok());

            if let Ok(msg2) = decode_result {
                assert_eq!(
                    msg2.version,
                    proto::atbus::protocol::AtbusProtocolConst::Version as u64
                );
                expect_msg_eq(&msg1, &msg2.message);
            }
        }
    }

    #[test]
    fn test_decoder_decode_length_error() {
        // Receive two or more packets at once
        let decoder = Decoder::new();
        let msg1 = generate_packet_message(thread_rng().gen_range(256..2048));
        let msg2 = generate_packet_message(thread_rng().gen_range(256..2048));

        let msg1_block = pack_message(&msg1);
        let msg2_block = pack_message(&msg2);

        let mut msg_block_all_in_one: Vec<u8> =
            Vec::with_capacity(msg1_block.len() + msg2_block.len());

        msg_block_all_in_one.extend_from_slice(msg1_block.as_ref());
        msg_block_all_in_one.extend_from_slice(msg2_block.as_ref());

        let decode_msg1 = decoder
            .peek(msg_block_all_in_one.as_ref())
            .expect("decode msg1 failed");
        assert_eq!(decode_msg1.consume_length, msg1_block.len());
        assert_eq!(
            decode_msg1.version,
            proto::atbus::protocol::AtbusProtocolConst::Version as u64
        );
        expect_msg_eq(&msg1, &decode_msg1.message);

        let decode_msg2 = decoder
            .peek(&msg_block_all_in_one[decode_msg1.consume_length..msg_block_all_in_one.len()])
            .expect("decode msg2 failed");
        assert_eq!(decode_msg2.consume_length, msg2_block.len());
        assert_eq!(
            decode_msg2.version,
            proto::atbus::protocol::AtbusProtocolConst::Version as u64
        );
        expect_msg_eq(&msg2, &decode_msg2.message);
    }
}
