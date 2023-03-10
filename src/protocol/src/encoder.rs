// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::convert::From;

use super::error::{ProtocolError, ProtocolResult};
use super::frame_block;
use super::FrameMessage;

use bytes;
use prost::Message;

pub struct EncoderFrame<'a> {
    message: &'a FrameMessage,
    message_length: usize,
    varint_length: usize,
}

impl<'a> EncoderFrame<'a> {
    pub fn new(msg: &'a FrameMessage) -> EncoderFrame<'a> {
        let message_length = msg.encoded_len();
        EncoderFrame {
            message: msg,
            message_length: message_length,
            varint_length: frame_block::FrameBlockAlgorithm::compute_frame_length_consume(
                message_length as u64,
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
        self.varint_length + self.message_length + frame_block::FRAME_HASH_SIZE
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

    pub fn put_slice(&self, input: EncoderFrame, output: &mut [u8]) -> ProtocolResult<usize> {
        if output.len() < input.get_total_length() {
            return Err(ProtocolError::BufferNotEnough(
                input.get_total_length(),
                output.len(),
            ));
        }

        let mut target = &mut output[0..input.varint_length];
        match frame_block::FrameBlockAlgorithm::encode_frame_length(
            &mut target,
            input.get_message_length() as u64,
        ) {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        }

        let mut output_message =
            &mut output[input.varint_length..input.varint_length + input.get_message_length()];
        match input.get_message().encode(&mut output_message) {
            Ok(_) => {}
            Err(e) => {
                return Err(ProtocolError::EncodeFailed(e));
            }
        }

        let target = &output[input.varint_length..input.varint_length + input.get_message_length()];
        let hash = frame_block::FrameBlockAlgorithm::hash(&target);

        unsafe {
            std::ptr::copy_nonoverlapping(
                hash.get_unchecked(0),
                output.get_unchecked_mut(input.varint_length + input.get_message_length()),
                frame_block::FRAME_HASH_SIZE,
            );
        }

        Ok(input.get_total_length())
    }

    pub fn put<T: AsMut<[u8]>>(
        &self,
        input: EncoderFrame,
        output: &mut T,
    ) -> ProtocolResult<usize> {
        self.put_slice(input, &mut output.as_mut())
    }

    pub fn put_bytes(
        &self,
        input: EncoderFrame,
        output: &mut bytes::BytesMut,
    ) -> ProtocolResult<usize> {
        let old_length = output.len();
        output.resize(old_length + input.get_total_length(), 0);

        let target = &mut output[old_length..];
        self.put_slice(input, target)
    }
}
