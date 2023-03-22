// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::convert::From;

use super::error::{ProtocolError, ProtocolResult};
use super::frame_block;
use super::proto;
use super::FrameMessage;

use bytes;
use prost::Message;

pub struct EncoderFrame<'a> {
    message: &'a FrameMessage,
    message_length: usize,
    varint_length_size: usize,
    varint_version_size: usize,
}

impl<'a> EncoderFrame<'a> {
    pub fn new(msg: &'a FrameMessage) -> EncoderFrame<'a> {
        let message_length = msg.encoded_len();
        EncoderFrame {
            message: msg,
            message_length: message_length,
            varint_length_size: frame_block::FrameBlockAlgorithm::compute_varint_consume(
                message_length as u64,
            ),
            varint_version_size: frame_block::FrameBlockAlgorithm::compute_varint_consume(
                proto::atbus::protocol::AtbusProtocolConst::Version as u64,
            ),
        }
    }

    #[inline]
    pub fn get_message(&self) -> &FrameMessage {
        &self.message
    }

    #[inline]
    pub fn get_message_length(&self) -> usize {
        self.message_length
    }

    #[inline]
    pub fn get_total_length(&self) -> usize {
        self.varint_version_size
            + self.varint_length_size
            + self.message_length
            + frame_block::FRAME_HASH_SIZE
    }
}

impl<'a> From<&'a FrameMessage> for EncoderFrame<'a> {
    fn from(input: &'a FrameMessage) -> Self {
        EncoderFrame::new(&input)
    }
}

impl<'a, T: AsRef<FrameMessage>> From<&'a T> for EncoderFrame<'a> {
    fn from(input: &'a T) -> Self {
        EncoderFrame::new(&input.as_ref())
    }
}

pub struct Encoder {}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {}
    }

    #[inline]
    pub fn get_reserve_header_length(&self) -> usize {
        10 + 10 + frame_block::FRAME_HASH_SIZE
    }

    pub fn put_block<B>(&self, input: EncoderFrame, mut output: B) -> ProtocolResult<(usize, B)>
    where
        B: bytes::BufMut,
    {
        if output.remaining_mut() < input.get_total_length() {
            return Err(ProtocolError::BufferNotEnough(
                input.get_total_length(),
                output.remaining_mut(),
            ));
        }

        let mut output_slice = {
            let chunk = output.chunk_mut();

            unsafe { std::slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) }
        };

        if output_slice.len() < input.get_total_length() {
            return Err(ProtocolError::BufferNotEnough(
                input.get_total_length(),
                output_slice.len(),
            ));
        }

        match frame_block::FrameBlockAlgorithm::encode_varint(
            &mut output_slice,
            proto::atbus::protocol::AtbusProtocolConst::Version as u64,
        ) {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        }

        let mut start_offset = input.varint_version_size;
        let mut target = &mut output_slice[start_offset..start_offset + input.varint_length_size];
        match frame_block::FrameBlockAlgorithm::encode_varint(
            &mut target,
            input.get_message_length() as u64,
        ) {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        }
        start_offset += input.varint_length_size;

        let mut output_message =
            &mut output_slice[start_offset..start_offset + input.get_message_length()];
        match input.get_message().encode(&mut output_message) {
            Ok(_) => {}
            Err(e) => {
                return Err(ProtocolError::EncodeFailed(e));
            }
        }
        start_offset += input.get_message_length();

        let target = &output_slice[0..start_offset];
        let hash = frame_block::FrameBlockAlgorithm::hash(target);

        unsafe {
            std::ptr::copy_nonoverlapping(
                hash.get_unchecked(0),
                output_slice.get_unchecked_mut(start_offset),
                frame_block::FRAME_HASH_SIZE,
            );
        }

        unsafe {
            output.advance_mut(input.get_total_length());
        }
        Ok((input.get_total_length(), output))
    }
}
