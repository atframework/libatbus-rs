// Copyright 2023 atframework
// Licensed under the MIT licenses.

//! libatbus-protocol decoder

use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use std::cmp::min;
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
    frame_schedule_resize: usize,
    frame_length_limit: usize,
    frame_compact_buffer: BytesMut,
    current_message: Option<BoxedFrameMessage>,
}

impl Decoder {
    #[inline]
    fn padding(length: usize) -> usize {
        (length + 0x0f) & (!(0x0f as usize))
    }

    pub fn new() -> Decoder {
        Decoder::with_compact_buffer_length(16 * 1024)
    }

    pub fn with_compact_buffer_length(length: usize) -> Decoder {
        let mut result = Decoder {
            state: DecoderState::DecodeLength,
            frame_consume_offset: 0,
            frame_consume_length: 0,
            frame_schedule_resize: 0,
            frame_length_limit: 1 * 1024 * 1024 * 1024, // 1GB
            frame_compact_buffer: BytesMut::new(),
            current_message: None,
        };

        result.resize_compact_buffer(length);
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
            &mut DecoderState::ReceiveStandaloneFrame(ref mut buf_block, ref length) => {
                let max_size = *length as usize + frame_block::FRAME_HASH_SIZE - buf_block.len();
                let consume_size = min(max_size, extend.len());

                buf_block.extend_from_slice(&extend[0..consume_size]);

                consume_size
            }
            _ => {
                // FIXME DecoderState::DecodeLength => It's only need to memory copy 16 bytes for large packet.
                let max_size = self.get_compact_buffer_size() - self.frame_consume_length;
                let consume_size = min(max_size, extend.len());
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

                    return match e {
                        ProtocolError::TruncatedFrameLength => (ret, Ok(())),
                        err => (ret, Err(err)),
                    };
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

            if 0 == consume_size {
                break;
            }
        }

        (ret, Ok(()))
    }

    #[inline]
    pub fn put_slice<U: AsRef<[u8]>>(&mut self, src: U) -> (usize, ProtocolResult<()>) {
        self.extend_from_slice(src.as_ref())
    }

    #[inline]
    pub fn get_compact_buffer_size(&self) -> usize {
        self.frame_compact_buffer.len()
    }

    pub fn resize_compact_buffer(&mut self, mut new_len: usize) {
        // At lease frame_block::FRAME_VARINT_RESERVE_SIZE bytes for frame length(at most 10 bytes)
        if new_len < frame_block::FRAME_VARINT_RESERVE_SIZE {
            new_len = frame_block::FRAME_VARINT_RESERVE_SIZE;
        }

        new_len = Decoder::padding(new_len);
        if new_len >= self.get_compact_buffer_size() {
            self.frame_compact_buffer.resize(new_len, 0);

            self.frame_schedule_resize = 0;
        } else if self.get_compact_data_size() > new_len {
            // Can not resize right now, we will try later
            self.frame_schedule_resize = new_len;
        } else if new_len < self.frame_consume_length {
            self.optimize_compact_buffer_run();
            self.frame_compact_buffer.resize(new_len, 0);

            self.frame_schedule_resize = 0;
        } else {
            self.frame_compact_buffer.resize(new_len, 0);

            self.frame_schedule_resize = 0;
        }
    }

    #[inline]
    pub fn get_compact_data_size(&self) -> usize {
        self.frame_consume_length - self.frame_consume_offset
    }

    #[inline]
    fn get_compact_buffer_slice(&self, begin: usize, end: usize) -> &[u8] {
        &self.frame_compact_buffer[begin..end]
    }

    fn optimize_compact_buffer_run(&mut self) {
        let data_length = self.get_compact_data_size();

        if 0 == self.frame_consume_offset || 0 == data_length {
            return;
        }

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
                > self.get_compact_buffer_size()
            {
                self.optimize_compact_buffer_run();
            }
        }

        if self.frame_schedule_resize > 0 {
            self.resize_compact_buffer(self.frame_schedule_resize);
        }
    }

    fn update_state(&mut self) -> ProtocolResult<bool> {
        match &mut self.state {
            DecoderState::DecodeLength => {
                if self.frame_consume_length <= self.frame_consume_offset {
                    return Ok(false);
                }

                // Try to decode length
                let received_buffer = self
                    .get_compact_buffer_slice(self.frame_consume_offset, self.frame_consume_length);
                match frame_block::FrameBlockAlgorithm::decode_frame_length(&received_buffer) {
                    Ok(x) => {
                        if x.length as usize > self.frame_length_limit {
                            return Err(ProtocolError::FrameLengthLimitExceeded(
                                self.frame_length_limit,
                                x.length as usize,
                            ));
                        }

                        let frame_size_with_length_varint =
                            x.consume + x.length as usize + frame_block::FRAME_HASH_SIZE;
                        let compact_buffer_size = self.get_compact_buffer_size();
                        if frame_size_with_length_varint <= compact_buffer_size {
                            // Maybe need memmove to head
                            if self.frame_consume_offset + frame_size_with_length_varint
                                > compact_buffer_size
                            {
                                // memmove [VARINT|DATA|HASH CODE] into [HEAD]
                                self.optimize_compact_buffer_run();
                            }

                            self.state = DecoderState::ReceiveCompactFrame(x.consume, x.length);
                        } else {
                            let packet_length_with_hash =
                                x.length as usize + frame_block::FRAME_HASH_SIZE;
                            let mut boxed_bytes =
                                Box::new(BytesMut::with_capacity(packet_length_with_hash));
                            let received_data_begin = self.frame_consume_offset + x.consume;
                            let received_data_length =
                                self.frame_consume_length - received_data_begin;
                            let consume_size = min(received_data_length, packet_length_with_hash);

                            // Copy [DATA|HASH CODE] into boxed buffer block
                            if consume_size > 0 && self.frame_consume_length > received_data_begin {
                                boxed_bytes.put(self.get_compact_buffer_slice(
                                    received_data_begin,
                                    received_data_begin + consume_size,
                                ));
                            }
                            if consume_size >= received_data_length {
                                self.frame_consume_offset = self.frame_consume_length;
                            } else {
                                self.frame_consume_offset = received_data_begin + consume_size;
                            }
                            self.state =
                                DecoderState::ReceiveStandaloneFrame(boxed_bytes, x.length);

                            self.optimize_compact_buffer();
                        }

                        // Packet maybe already finished, return true to update again
                        Ok(true)
                    }
                    Err(e) => Err(e),
                }
            }
            &mut DecoderState::ReceiveStandaloneFrame(ref mut buf_block, ref length) => {
                if self.current_message.is_some() {
                    return Ok(false);
                }

                if buf_block.len() >= *length as usize + frame_block::FRAME_HASH_SIZE {
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
            &mut DecoderState::ReceiveCompactFrame(ref frame_consume, ref frame_length) => {
                if self.current_message.is_some() {
                    return Ok(false);
                }
                let length = *frame_length as usize;
                let consume = *frame_consume;

                let received_frame_length = self.get_compact_data_size();
                if received_frame_length >= consume + length + frame_block::FRAME_HASH_SIZE {
                    let buffer_begin = self.frame_consume_offset + consume;
                    let buffer_end = buffer_begin + length + frame_block::FRAME_HASH_SIZE;
                    let ret = match Self::decode_message(frame_block::FrameBlock::new(
                        self.get_compact_buffer_slice(buffer_begin, buffer_end),
                    )) {
                        Ok(msg) => {
                            self.current_message = Some(msg);
                            Ok(true)
                        }
                        Err(e) => Err(e),
                    };

                    self.frame_consume_offset = buffer_end;
                    self.state = DecoderState::DecodeLength;

                    self.optimize_compact_buffer();

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
        match block.data() {
            Some(block_data) => match FrameMessage::decode_length_delimited(block_data) {
                Ok(msg) => Ok(Box::new(msg)),
                Err(e) => Err(ProtocolError::DecodeFailed(e)),
            },
            None => Err(ProtocolError::IoError(io::ErrorKind::InvalidData.into())),
        }
    }
}

#[cfg(test)]
mod test {
    use bytes::Buf;
    use rand::{thread_rng, Rng};
    use std::collections::HashMap;

    use super::super::encoder::{Encoder, EncoderFrame};
    use super::super::error::ProtocolError;
    use super::super::proto;
    use super::frame_block;
    use super::Decoder;
    use super::FrameMessage;

    fn pack_message(msg: &FrameMessage) -> bytes::Bytes {
        let encode_frame = EncoderFrame::new(&msg);
        let mut ret = bytes::BytesMut::with_capacity(encode_frame.get_total_length());

        let encoder = Encoder::new();
        let _ = encoder.put_bytes(encode_frame, &mut ret);

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
        let head = proto::atbus::protocol::MessageHead {
            version: proto::atbus::protocol::AtbusProtocolConst::Version as i32,
            source: generate_uuid(),
            destination: generate_uuid(),
            forward_for_source: vec![],
            forward_for_connection_id: 1,
        };
        let mut body = proto::atbus::protocol::PacketData {
            stream_id: 1,
            stream_offset: 0,
            content: vec![b'0'; content_length],
            packet_type: proto::atbus::protocol::AtbusPacketType::Data as i32,
            packet_length: 0,
            flags: proto::atbus::protocol::AtbusPacketFlagType::ResetSequence as i32,
            options: None,
            labels: HashMap::new(),
            forward_for: None,
            close_reason: None,
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
        assert_eq!(left.version, right.version);
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
            expect_msg_eq(&msg1, &msg2);
        }
    }

    #[test]
    fn test_decoder_small_message_not_from_head() {
        // receive two or more packets at once
        let mut decoder = Decoder::with_compact_buffer_length(4096);
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
            expect_msg_eq(&msg1, &msg3);
            drop(msg1);
        }

        {
            let msg4 = decoder.get_packet().unwrap();
            expect_msg_eq(&msg2, &msg4);
        }
    }

    #[test]
    fn test_decoder_small_message_with_memmove() {
        let mut decoder = Decoder::with_compact_buffer_length(4096);

        // receive two or more packets at once but the last packet need memmove
        let msg1 = generate_packet_message(decoder.get_compact_buffer_size() / 2);
        let msg2 = generate_packet_message(decoder.get_compact_buffer_size() / 2);

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
            assert_eq!(decode_size, decoder.get_compact_buffer_size());
            assert!(decode_err.is_ok());
            assert!(msg_block_all_in_one.remaining() > 0);

            let msg3 = decoder.get_packet().unwrap();
            expect_msg_eq(&msg1, &msg3);
            assert_eq!(
                msg2_block_size,
                decoder.get_compact_data_size() + msg_block_all_in_one.remaining()
            );
            assert_eq!(0, decoder.frame_consume_offset);

            let _ = decoder.put(&mut msg_block_all_in_one);
            let msg4 = decoder.get_packet().unwrap();
            expect_msg_eq(&msg2, &msg4);
        }
    }

    #[test]
    fn test_decoder_decode_message_error_but_consume_bad_datas() {
        let mut decoder = Decoder::with_compact_buffer_length(4096);
        let msg1 = generate_packet_message(decoder.get_compact_buffer_size() / 4);
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

            // Set bad data
            for i in msg1_block_size / 2..msg1_block_size {
                unsafe {
                    *msg_block_all_in_one.get_unchecked_mut(i) = 0;
                }
            }
            let hash_data =
                &msg_block_all_in_one[2..msg1_block_size - frame_block::FRAME_HASH_SIZE];
            let hash_result = frame_block::FrameBlockAlgorithm::hash(&hash_data);
            for i in 0..frame_block::FRAME_HASH_SIZE {
                unsafe {
                    *msg_block_all_in_one
                        .get_unchecked_mut(msg1_block_size - frame_block::FRAME_HASH_SIZE + i) =
                        hash_result[i];
                }
            }

            let (decode_size, decode_err) = decoder.put_slice(&msg_block_all_in_one);
            assert_eq!(decode_size, msg1_block_size + msg2_block_size);
            assert!(decode_err.is_err());
            match decode_err.unwrap_err() {
                ProtocolError::DecodeFailed(e) => {
                    println!("Got ProtocolError::DecodeFailed({})", e);
                }
                e => {
                    println!("Expect ProtocolError::DecodeFailed, real got {}", e);
                    assert!(false);
                }
            }
        }

        {
            let msg4 = decoder.get_packet().unwrap();
            expect_msg_eq(&msg2, &msg4);
        }
    }

    #[test]
    fn test_decoder_decode_length_error() {
        // TODO receive two or more packets at once
        // We can not recover from a bad data of frame length
        let mut decoder = Decoder::with_compact_buffer_length(4096);
        let msg1 = generate_packet_message(decoder.get_compact_buffer_size() / 4);
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

            // Set bad data
            for i in 0..10 {
                unsafe {
                    *msg_block_all_in_one.get_unchecked_mut(i) = 0xff;
                }
            }

            let (decode_size, decode_err) = decoder.put_slice(&msg_block_all_in_one);
            assert_eq!(decode_size, msg1_block_size + msg2_block_size);
            assert!(decode_err.is_err());
            match decode_err.unwrap_err() {
                ProtocolError::BadFrameLength => {
                    println!("Got ProtocolError::BadFrameLength");
                }
                e => {
                    println!("Expect ProtocolError::BadFrameLength, real got {}", e);
                    assert!(false);
                }
            }

            let old_frame_offset = decoder.frame_consume_offset;
            let old_frame_length = decoder.frame_consume_length;
            let old_frame_has_msg = decoder.current_message.is_some();

            match decoder.peek_packet() {
                Ok(_) => {
                    println!("Expect ProtocolError::BadFrameLength, real got Ok");
                    assert!(false);
                }
                Err(e) => match e {
                    ProtocolError::BadFrameLength => {
                        println!("Got ProtocolError::BadFrameLength");
                    }
                    e => {
                        println!("Expect ProtocolError::BadFrameLength, real got {}", e);
                        assert!(false);
                    }
                },
            }

            assert_eq!(old_frame_offset, decoder.frame_consume_offset);
            assert_eq!(old_frame_length, decoder.frame_consume_length);
            assert_eq!(old_frame_has_msg, decoder.current_message.is_some());
        }
    }

    #[test]
    fn test_decoder_large_message() {
        let msg1 = generate_packet_message(1024);
        let msg1_block = pack_message(&msg1);

        let msg1_fit_size = Decoder::padding(msg1_block.len());

        let mut decoder = Decoder::with_compact_buffer_length(msg1_fit_size);

        let msg2 = generate_packet_message(4096);
        let msg2_block = pack_message(&msg2);

        {
            let msg1_block_size = msg1_block.len();
            let msg2_block_size = msg2_block.len();

            let mut msg_block_all_in_one =
                bytes::BytesMut::with_capacity(msg1_block_size + msg2_block_size);
            msg_block_all_in_one.extend_from_slice(msg1_block.as_ref());
            let msg2_block_partly = &msg2_block[0..1];
            msg_block_all_in_one.extend_from_slice(&msg2_block_partly);

            let (decode_size, decode_err) = decoder.put(&mut msg_block_all_in_one);
            assert_eq!(decode_size, msg1_block_size + 1);
            assert!(decode_err.is_ok());

            let msg3 = decoder.get_packet().unwrap();
            expect_msg_eq(&msg1, &msg3);

            msg_block_all_in_one.extend_from_slice(&msg2_block[1..]);
            while msg_block_all_in_one.remaining() > 0 {
                let _ = decoder.put(&mut msg_block_all_in_one);
            }

            let msg4 = decoder.get_packet().unwrap();
            expect_msg_eq(&msg2, &msg4);
        }
    }

    #[test]
    fn test_decoder_resize_compact_buffer() {
        let mut decoder = Decoder::new();
        let origin_compact_buffer_size = decoder.get_compact_buffer_size();

        let msg1 = generate_packet_message(origin_compact_buffer_size / 2);

        let msg1_block = pack_message(&msg1);
        let msg1_block_size = msg1_block.len();

        {
            let (decode_size, decode_err) = decoder.put_slice(&msg1_block[0..msg1_block_size - 1]);
            assert_eq!(decode_size, msg1_block_size - 1);
            assert!(decode_err.is_ok());
            assert_eq!(decode_size, decoder.get_compact_data_size());
        }

        // Branch 4
        let new_size_large = Decoder::padding(origin_compact_buffer_size / 4 * 3);
        decoder.resize_compact_buffer(new_size_large);
        assert_eq!(new_size_large, decoder.get_compact_buffer_size());

        // Branch 2
        let new_size_small = Decoder::padding(msg1_block_size / 2);
        decoder.resize_compact_buffer(new_size_small);
        assert_eq!(new_size_large, decoder.get_compact_buffer_size());
        assert_eq!(new_size_small, decoder.frame_schedule_resize);

        let _ = decoder.put_slice(&msg1_block[msg1_block_size - 1..]);
        assert_eq!(0, decoder.get_compact_data_size());
        assert_eq!(new_size_small, decoder.get_compact_buffer_size());

        // Consume packet
        let msg2 = decoder.get_packet().unwrap();
        expect_msg_eq(&msg1, &msg2);

        // Branch 1
        decoder.resize_compact_buffer(origin_compact_buffer_size);
        assert_eq!(
            origin_compact_buffer_size,
            decoder.get_compact_buffer_size()
        );

        // Mock - Branch 3
        decoder.frame_consume_offset = new_size_small;
        decoder.frame_consume_length = new_size_small + msg1_block_size - 1;
        unsafe {
            std::ptr::copy(
                msg1_block.get_unchecked(0),
                decoder
                    .frame_compact_buffer
                    .get_unchecked_mut(new_size_small),
                msg1_block_size - 1,
            );
        }
        let padding_block_size = Decoder::padding(msg1_block_size);
        decoder.resize_compact_buffer(padding_block_size);
        assert_eq!(padding_block_size, decoder.get_compact_buffer_size());
        assert_eq!(0, decoder.frame_consume_offset);
        assert_eq!(msg1_block_size - 1, decoder.frame_consume_length);
        assert_eq!(
            &msg1_block[0..msg1_block_size - 1],
            &decoder.frame_compact_buffer[0..msg1_block_size - 1]
        );
    }
}
