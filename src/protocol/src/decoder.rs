//! libatbus-protocol decoder

use bytes::{Buf, BufMut, BytesMut};
use protobuf::Message;
use std::io;

use super::error::{ProtocolError, ProtocolResult};
use super::frame_block;
use super::{BoxedFrameMessage, FrameMessage};

pub enum DecoderState {
    /// Decode frame length
    DecodeLength,
    /// Frame length already decoded and it's a small packet
    ReceiveCompactFrame(usize, u64),
    /// Frame length already decoded and it's a large packet
    ReceiveStandaloneFrame(Box<BytesMut>, u64),
}

pub struct Decoder {
    state: DecoderState,
    frame_consume_offset: usize,
    frame_consume_length: usize,
    frame_compact_buffer: BytesMut,
    frame_compact_resize: usize,
    current_message: Option<BoxedFrameMessage>,
}

impl Decoder {
    pub fn new() -> Decoder {
        let mut result = Decoder {
            state: DecoderState::DecodeLength,
            frame_consume_offset: 0,
            frame_consume_length: 0,
            frame_compact_buffer: BytesMut::new(),
            frame_compact_resize: 0,
            current_message: None,
        };

        result.resize_compact_buffer(16 * 1024);
        result
    }

    pub fn peek_packet(&mut self) -> ProtocolResult<&BoxedFrameMessage> {
        if let Some(ref x) = self.current_message {
            return Ok(x);
        }

        // Maybe pending buffer already has one packet
        loop {
            let update_again = match self.update_state() {
                Ok(x) => x,
                Err(e) => {
                    self.optimize_compact_buffer();
                    return Err(e);
                }
            };

            if !update_again {
                break;
            }
        }
        self.optimize_compact_buffer();

        if let Some(ref x) = self.current_message {
            Ok(x)
        } else {
            Err(ProtocolError::TruncatedPacket)
        }
    }

    pub fn get_packet(&mut self) -> ProtocolResult<BoxedFrameMessage> {
        let ret = match self.peek_packet() {
            Ok(_) => {
                if let Some(x) = self.current_message.take() {
                    Ok(x)
                } else {
                    Err(ProtocolError::TruncatedPacket)
                }
            }
            Err(e) => Err(e),
        };

        ret
    }

    pub fn extend_from_slice(&mut self, extend: &[u8]) -> (usize, ProtocolResult<()>) {
        if self.current_message.is_some() {
            return (0, Err(ProtocolError::HasPendingPacket));
        }

        let ret = match &mut self.state {
            &mut DecoderState::ReceiveStandaloneFrame(ref mut buf_block, length) => {
                let max_size = length as usize - buf_block.len();
                let consume_size = std::cmp::min(max_size, extend.len());

                buf_block.extend_from_slice(&extend[0..consume_size]);

                consume_size
            }
            _ => {
                let max_size = self.frame_compact_buffer.len() - self.frame_consume_length;
                let consume_size = std::cmp::min(max_size, extend.len());
                unsafe {
                    std::ptr::copy(
                        extend.as_ptr(),
                        self.frame_compact_buffer
                            .get_unchecked_mut(self.frame_consume_length),
                        consume_size,
                    );
                }
                self.frame_consume_length += consume_size;

                consume_size
            }
        };

        loop {
            let update_again = match self.update_state() {
                Ok(x) => x,
                Err(e) => {
                    self.optimize_compact_buffer();
                    return (ret, Err(e));
                }
            };

            if !update_again {
                break;
            }
        }
        self.optimize_compact_buffer();

        (ret, Ok(()))
    }

    pub fn put<U: Buf>(&mut self, src: &mut U) -> (usize, ProtocolResult<()>) {
        let mut ret = 0;
        while src.has_remaining() && self.current_message.is_none() {
            let s = src.chunk();
            let (consume_size, err) = self.extend_from_slice(s);
            if consume_size > 0 {
                ret += consume_size;
                src.advance(consume_size);
            }

            if let Err(e) = err {
                return (ret, Err(e));
            }
        }

        (ret, Ok(()))
    }

    pub fn get_compact_buffer_size(&self) -> usize {
        self.frame_compact_buffer.len()
    }

    pub fn resize_compact_buffer(&mut self, mut new_len: usize) {
        // At lease frame_block::FRAME_VARINT_RESERVE_SIZE bytes for frame length(at most 10 bytes)
        if new_len < frame_block::FRAME_VARINT_RESERVE_SIZE {
            new_len = frame_block::FRAME_VARINT_RESERVE_SIZE;
        }

        self.frame_compact_resize = new_len;
        self.optimize_compact_buffer();
    }

    #[inline]
    pub fn get_compact_data_length(&self) -> usize {
        self.frame_consume_length - self.frame_consume_offset
    }

    fn optimize_compact_buffer_run(&mut self) {
        let data_length = self.get_compact_data_length();
        unsafe {
            std::ptr::copy(
                self.frame_compact_buffer
                    .get_unchecked(self.frame_consume_offset),
                self.frame_compact_buffer.get_unchecked_mut(0),
                data_length,
            );
        }
        self.frame_consume_length = data_length;
        self.frame_consume_offset = 0;
    }

    fn optimize_compact_buffer(&mut self) {
        if self.frame_consume_length == self.frame_consume_offset {
            self.frame_consume_offset = 0;
            self.frame_consume_length = 0;
        } else {
            if self.frame_consume_offset + frame_block::FRAME_VARINT_RESERVE_SIZE
                > self.frame_compact_buffer.len()
            {
                self.optimize_compact_buffer_run();
            }
        }

        if self.frame_compact_resize >= frame_block::FRAME_VARINT_RESERVE_SIZE {
            if self.frame_consume_length <= self.frame_compact_resize {
                self.frame_compact_buffer
                    .resize(self.frame_compact_resize, 0);
                self.frame_compact_resize = 0;
            } else {
                if self.get_compact_data_length() <= self.frame_compact_resize {
                    self.optimize_compact_buffer_run();

                    self.frame_compact_resize = 0;
                }
            }
        }
    }

    fn update_state(&mut self) -> ProtocolResult<bool> {
        match &mut self.state {
            DecoderState::DecodeLength => {
                if self.frame_consume_length <= self.frame_consume_offset {
                    return Ok(false);
                }

                // Try to decode length
                let received_buffer = &self.frame_compact_buffer
                    [self.frame_consume_offset..self.frame_consume_length];
                if let Ok(x) =
                    frame_block::FrameBlockAlgorithm::decode_frame_length(&received_buffer)
                {
                    let frame_size_with_length_varint =
                        x.consume + x.length as usize + frame_block::FRAME_HASH_SIZE;
                    if frame_size_with_length_varint <= self.frame_compact_buffer.len() {
                        // Maybe need memmove to head
                        if self.frame_consume_offset + frame_size_with_length_varint
                            > self.frame_compact_buffer.len()
                        {
                            let new_length = self.get_compact_data_length();

                            // memmove [VARINT|DATA|HASH CODE] into [HEAD]
                            unsafe {
                                std::ptr::copy(
                                    self.frame_compact_buffer
                                        .get_unchecked(self.frame_consume_offset),
                                    self.frame_compact_buffer.get_unchecked_mut(0),
                                    new_length,
                                );
                            }

                            self.frame_consume_offset = 0;
                            self.frame_consume_length = new_length;
                        }

                        self.state = DecoderState::ReceiveCompactFrame(x.consume, x.length);
                    } else {
                        let packet_length_with_hash =
                            x.length as usize + frame_block::FRAME_HASH_SIZE;
                        let mut boxed_bytes =
                            Box::new(BytesMut::with_capacity(packet_length_with_hash));
                        let received_data_begin = self.frame_consume_offset + x.consume;
                        let received_data_length = self.frame_consume_length - received_data_begin;
                        let consume_size =
                            std::cmp::min(received_data_length, packet_length_with_hash);

                        // Copy [DATA|HASH CODE] into boxed buffer block
                        if consume_size > 0
                            && self.frame_consume_length > self.frame_consume_offset + x.consume
                        {
                            boxed_bytes.put(
                                &self.frame_compact_buffer
                                    [received_data_begin..received_data_begin + consume_size],
                            );
                        }
                        self.frame_consume_offset += consume_size;
                        self.state = DecoderState::ReceiveStandaloneFrame(boxed_bytes, x.length);

                        self.optimize_compact_buffer();
                    }

                    // Packet maybe already finished, return true to update again
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            &mut DecoderState::ReceiveStandaloneFrame(ref mut buf_block, length) => {
                if self.current_message.is_some() {
                    return Ok(false);
                }

                if buf_block.len() >= length as usize + frame_block::FRAME_HASH_SIZE {
                    let ret = match Self::decode_message(frame_block::FrameBlock::new(
                        buf_block.as_ref(),
                    )) {
                        Ok(msg) => {
                            self.current_message = Some(msg);
                            Ok(true)
                        }
                        Err(e) => Err(e),
                    };
                    self.state = DecoderState::DecodeLength;

                    ret
                } else {
                    Ok(false)
                }
            }
            &mut DecoderState::ReceiveCompactFrame(consume, length) => {
                if self.current_message.is_some() {
                    return Ok(false);
                }

                let received_frame_length = self.get_compact_data_length();
                if received_frame_length >= consume + length as usize + frame_block::FRAME_HASH_SIZE
                {
                    let buffer_begin = self.frame_consume_offset + consume;
                    let buffer_end = buffer_begin + length as usize + frame_block::FRAME_HASH_SIZE;
                    let ret = match Self::decode_message(frame_block::FrameBlock::new(
                        &self.frame_compact_buffer[buffer_begin..buffer_end],
                    )) {
                        Ok(msg) => {
                            self.current_message = Some(msg);
                            Ok(true)
                        }
                        Err(e) => Err(e),
                    };

                    self.frame_consume_offset = buffer_end;
                    self.state = DecoderState::DecodeLength;

                    ret
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn decode_message<T: AsRef<[u8]>>(
        block: frame_block::FrameBlock<T>,
    ) -> ProtocolResult<BoxedFrameMessage> {
        if !block.validate() {
            return Err(ProtocolError::IoError(io::ErrorKind::InvalidData.into()));
        }

        match FrameMessage::parse_from_bytes(&block.data().unwrap()) {
            Ok(msg) => Ok(Box::new(msg)),
            Err(e) => Err(ProtocolError::DecodeFailed(e)),
        }
    }
}

#[cfg(test)]
mod test {
    use protobuf::Message;
    use rand::{thread_rng, Rng};

    use super::super::proto::libatbus_protocol;
    use super::frame_block;
    use super::Decoder;
    use super::FrameMessage;
    use protobuf::CodedOutputStream;

    fn pack_message(msg: &FrameMessage) -> bytes::Bytes {
        let msg_length = msg.compute_size();

        let mut varint: [u8; frame_block::FRAME_VARINT_RESERVE_SIZE] =
            [0; frame_block::FRAME_VARINT_RESERVE_SIZE];

        let varint_length =
            frame_block::FrameBlockAlgorithm::encode_frame_length(&mut varint, msg_length as u64)
                .unwrap();

        let total_size = varint_length + msg_length as usize + frame_block::FRAME_HASH_SIZE;
        let mut ret = bytes::BytesMut::with_capacity(total_size);

        ret.extend_from_slice(&varint[0..varint_length]);
        ret.resize(varint_length + msg_length as usize, 0);
        let _ = msg
            .write_to_with_cached_sizes(&mut CodedOutputStream::bytes(&mut ret[varint_length..]));

        let buffer = &ret.as_ref()[varint_length..];
        let hash = frame_block::FrameBlockAlgorithm::hash(&buffer);
        ret.extend_from_slice(&hash);

        ret.freeze()
    }

    fn generate_uuid() -> Vec<u8> {
        let mut ret = Vec::new();
        ret.resize(32, 0 as u8);
        thread_rng().fill(&mut ret[16..]);
        for i in 0..16 {
            let c = ret[i + 16];
            let lc = c % 16;
            let hc = c / 16;
            ret[i << 1] = if lc >= 10 {
                lc - 10 + 'a' as u8
            } else {
                lc + '0' as u8
            };
            ret[(i << 1) + 1] = if hc >= 10 {
                hc - 10 + 'a' as u8
            } else {
                hc + '0' as u8
            };
        }

        ret
    }

    fn generate_packet_message(content_length: usize) -> FrameMessage {
        let mut ret = FrameMessage::new();
        ret.mut_head().set_source(generate_uuid());
        ret.mut_head().set_destination(generate_uuid());
        ret.mut_head()
            .set_version(libatbus_protocol::ATBUS_PROTOCOL_CONST::ATBUS_PROTOCOL_VERSION as i32);

        let body = ret.mut_packet();
        body.set_packet_sequence(123);
        body.set_packet_acknowledge(456);
        body.set_flags(
            libatbus_protocol::ATBUS_PACKET_FLAG_TYPE::ATBUS_PACKET_FLAG_RESET_SEQUENCE as i32,
        );
        body.mut_content().resize(content_length, 0);
        thread_rng().fill(body.mut_content().as_mut_slice());

        ret
    }

    #[test]
    fn test_decoder_small_message_from_head() {
        let mut decoder = Decoder::new();
        let msg1 = generate_packet_message(decoder.get_compact_buffer_size() / 2);

        let mut msg1_block = pack_message(&msg1);

        {
            let msg1_block_size = msg1_block.len();
            let (decode_size, decode_err) = decoder.put(&mut msg1_block);
            assert_eq!(decode_size, msg1_block_size);
            assert!(decode_err.is_ok());

            let msg2 = decoder.peek_packet().unwrap();
            assert_eq!(msg1.get_head().get_source(), msg2.get_head().get_source());
            assert_eq!(
                msg1.get_head().get_destination(),
                msg2.get_head().get_destination()
            );
            assert_eq!(msg1.get_head().get_version(), msg2.get_head().get_version());
            assert_eq!(msg1.has_packet(), msg2.has_packet());
            assert_eq!(
                msg1.get_packet().get_packet_sequence(),
                msg2.get_packet().get_packet_sequence()
            );
            assert_eq!(
                msg1.get_packet().get_packet_acknowledge(),
                msg2.get_packet().get_packet_acknowledge()
            );
            assert_eq!(msg1.get_packet().get_flags(), msg2.get_packet().get_flags());
            assert_eq!(
                msg1.get_packet().get_content(),
                msg2.get_packet().get_content()
            );
        }
    }

    #[test]
    fn test_decoder_small_message_not_from_head() {
        // receive two or more packets at once
        let mut decoder = Decoder::new();
        let msg1 = generate_packet_message(decoder.get_compact_buffer_size() / 3);
        let msg2 = generate_packet_message(decoder.get_compact_buffer_size() / 4);

        let msg1_block = pack_message(&msg1);
        let msg2_block = pack_message(&msg2);

        {
            let msg1_block_size = msg1_block.len();
            let msg2_block_size = msg2_block.len();

            let mut msg_block_all_in_one =
                bytes::BytesMut::with_capacity(msg1_block_size + msg2_block_size);
            msg_block_all_in_one.extend_from_slice(msg1_block.as_ref());
            msg_block_all_in_one.extend_from_slice(msg2_block.as_ref());

            let (decode_size, decode_err) = decoder.put(&mut msg_block_all_in_one);
            assert_eq!(decode_size, msg1_block_size + msg2_block_size);
            assert!(decode_err.is_ok());
        }
        {
            let msg3 = decoder.get_packet().unwrap();
            assert_eq!(msg1.get_head().get_source(), msg3.get_head().get_source());
            assert_eq!(
                msg1.get_head().get_destination(),
                msg3.get_head().get_destination()
            );
            assert_eq!(msg1.get_head().get_version(), msg3.get_head().get_version());
            assert_eq!(msg1.has_packet(), msg3.has_packet());
            assert_eq!(
                msg1.get_packet().get_packet_sequence(),
                msg3.get_packet().get_packet_sequence()
            );
            assert_eq!(
                msg1.get_packet().get_packet_acknowledge(),
                msg3.get_packet().get_packet_acknowledge()
            );
            assert_eq!(msg1.get_packet().get_flags(), msg3.get_packet().get_flags());
            assert_eq!(
                msg1.get_packet().get_content(),
                msg3.get_packet().get_content()
            );
            drop(msg1);
        }

        {
            let msg4 = decoder.get_packet().unwrap();
            assert_eq!(msg2.get_head().get_source(), msg4.get_head().get_source());
            assert_eq!(
                msg2.get_head().get_destination(),
                msg4.get_head().get_destination()
            );
            assert_eq!(msg2.get_head().get_version(), msg4.get_head().get_version());
            assert_eq!(msg2.has_packet(), msg4.has_packet());
            assert_eq!(
                msg2.get_packet().get_packet_sequence(),
                msg4.get_packet().get_packet_sequence()
            );
            assert_eq!(
                msg2.get_packet().get_packet_acknowledge(),
                msg4.get_packet().get_packet_acknowledge()
            );
            assert_eq!(msg2.get_packet().get_flags(), msg4.get_packet().get_flags());
            assert_eq!(
                msg2.get_packet().get_content(),
                msg4.get_packet().get_content()
            );
        }
    }

    #[test]
    fn test_decoder_small_message_with_memmove() {
        // TODO receive two or more packets at once but the last packet need memmove
    }

    #[test]
    fn test_decoder_decode_error_but_consume_bad_datas() {
        // TODO receive two or more packets at once
    }

    #[test]
    fn test_decoder_large_message() {}

    #[test]
    fn test_decoder_resize_compact_buffer_without_memmove() {}

    #[test]
    fn test_decoder_resize_compact_buffer_with_memmove() {
        // TODO receive two or more packets at once but the last packet is a large packet
    }
}
