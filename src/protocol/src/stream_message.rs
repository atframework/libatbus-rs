// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::HashMap;
use std::io;
use std::rc;

use crate::prost::Message;

use super::{
    error::{ProtocolError, ProtocolResult},
    BoxedFrameMessage, CloseReasonMessage, ForwardMessage, FrameMessage, FrameMessageBody,
    FrameMessageHead, PacketContentMessage, PacketFlagType, PacketFragmentFlagType,
    PacketFragmentMessage, PacketMessage, PacketOptionMessage,
};

use super::proto;
type InternalMessageType = proto::atbus::protocol::AtbusPacketType;

pub struct StreamConnectionContext {
    frame_message_template: FrameMessage,
    frame_message_predict_size: usize,
    fragment_message_template: PacketFragmentMessage,
    fragment_message_predict_size: usize,
    packet_padding_size: usize,
}

pub struct StreamMessage {
    pub stream_offset: i64,
    pub data: ::prost::bytes::Bytes,

    /// @see atbus.protocol.ATBUS_PACKET_FLAG_TYPE
    pub flags: i32,

    /// Only has value when has ATBUS_PACKET_FLAG_TYPE_FINISH_STREAM or ATBUS_PACKET_FLAG_TYPE_FINISH_CONNECTION
    pub close_reason: Option<Box<CloseReasonMessage>>,

    /// Connection context
    pub connection_context: rc::Rc<StreamConnectionContext>,
}

pub struct StreamPacketFragmentMessage {
    offset: i64,
    data: PacketFragmentMessage,
}

pub struct StreamPacketFragmentUnpack {
    pub stream_offset: i64,
    pub fragment: ::prost::alloc::vec::Vec<StreamPacketFragmentMessage>,
    pub packet_flag: i32,
    pub timepoint_microseconds: i64,
}

impl StreamConnectionContext {
    pub fn new(
        head: FrameMessageHead,
        stream_id: i64,
        packet_padding_size: usize,
        options: Option<PacketOptionMessage>,
        labels: HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
        forward_for: Option<ForwardMessage>,
    ) -> Self {
        let mut ret = StreamConnectionContext {
            frame_message_template: FrameMessage {
                head: Some(head),
                body: Some(FrameMessageBody::Packet(PacketMessage {
                    stream_id: stream_id,
                    stream_offset: 1,
                    content: bytes::Bytes::new(),
                    flags: 16,
                    padding_size: packet_padding_size as i32,
                    timepoint_microseconds: 1,
                })),
            },
            frame_message_predict_size: 0,
            fragment_message_template: PacketFragmentMessage {
                packet_type: InternalMessageType::Handshake as i32,
                data: bytes::Bytes::new(),
                fragment_flag: PacketFragmentFlagType::HasMore as i32,
                options: options,
                labels: labels,
                forward_for: forward_for,
                close_reason: None,
            },
            fragment_message_predict_size: 0,
            packet_padding_size: packet_padding_size,
        };

        // Reserve varint for packet and content field.
        ret.frame_message_predict_size = ret.frame_message_template.encoded_len() + 20;

        // Reserve varint for fragment and data field.
        ret.fragment_message_predict_size = ret.fragment_message_template.encoded_len() + 20;

        ret
    }

    pub fn reset_padding_size(&mut self, packet_padding_size: usize) {
        if let Some(b) = self.frame_message_template.body.as_mut() {
            if let FrameMessageBody::Packet(ref mut p) = b {
                p.padding_size = packet_padding_size as i32;
            }
        }

        // Reserve varint for packet and content field.
        self.frame_message_predict_size = self.frame_message_template.encoded_len() + 20;
    }
}

pub struct StreamPacketFragmentPack {
    pub frame_count: usize,
    pub consume_size: usize,
}

impl StreamMessage {
    pub fn predict_frame_size(&self, stream_offset: i64, timepoint_microseconds: i64) -> usize {
        self.connection_context.frame_message_predict_size
            + prost::length_delimiter_len(if stream_offset > 0 {
                stream_offset as usize
            } else {
                0
            })
            + prost::length_delimiter_len(if timepoint_microseconds > 0 {
                timepoint_microseconds as usize
            } else {
                0
            })
    }

    pub fn predict_fragment_size(&self, close_reason: &Option<CloseReasonMessage>) -> usize {
        if let Some(cr) = close_reason {
            let encoded_len_of_cr = cr.encoded_len();
            // Key tag use last 3 bits of first byte as wire type.
            self.connection_context.fragment_message_predict_size
                + prost::length_delimiter_len(encoded_len_of_cr * 8)
                + prost::length_delimiter_len(encoded_len_of_cr)
        } else {
            self.connection_context.fragment_message_predict_size
        }
    }

    pub fn get_message_length(&self) -> usize {
        self.data.len()
    }

    pub fn get_message_begin_offset(&self) -> i64 {
        self.stream_offset
    }

    pub fn get_message_end_offset(&self) -> i64 {
        self.stream_offset + self.data.len() as i64
    }

    pub fn pack<B>(
        &self,
        mut output: B,
        mut start_stream_offset: i64,
        packet_size_limit: usize,
        timepoint_microseconds: i64,
    ) -> StreamPacketFragmentPack
    where
        B: bytes::BufMut,
    {
        let mut ret = StreamPacketFragmentPack {
            frame_count: 0,
            consume_size: 0,
        };

        if start_stream_offset >= self.get_message_end_offset() {
            return ret;
        }

        self.pack_internal(
            output,
            &mut ret,
            start_stream_offset,
            packet_size_limit,
            timepoint_microseconds,
        );

        ret
    }

    fn pack_internal<B>(
        &self,
        mut output: B,
        packer: &mut StreamPacketFragmentPack,
        mut start_stream_offset: i64,
        packet_size_limit: usize,
        timepoint_microseconds: i64,
    ) where
        B: bytes::BufMut,
    {
        if start_stream_offset >= self.get_message_end_offset() {
            return;
        }

        // bytes::BufMut;
    }
}

impl StreamPacketFragmentMessage {
    pub fn new(offset: i64, data: PacketFragmentMessage) -> Self {
        StreamPacketFragmentMessage { offset, data }
    }

    pub fn unpack_from_buffer<B>(
        mut buf: B,
        expect_stream_id: Option<i64>,
    ) -> ProtocolResult<StreamPacketFragmentUnpack>
    where
        B: bytes::Buf,
    {
        match FrameMessage::decode(buf) {
            Ok(f) => Self::unpack(Box::new(f), expect_stream_id),
            Err(e) => Err(ProtocolError::DecodeFailed(e)),
        }
    }

    pub fn unpack(
        frame: BoxedFrameMessage,
        expect_stream_id: Option<i64>,
    ) -> ProtocolResult<StreamPacketFragmentUnpack> {
        let frame_body = match frame.body.as_ref() {
            Some(b) => b,
            _ => {
                return Err(ProtocolError::IoError(io::Error::from(
                    io::ErrorKind::InvalidInput,
                )));
            }
        };

        let packet_body = match &frame_body {
            &FrameMessageBody::Packet(ref p) => p,
            _ => {
                return Err(ProtocolError::IoError(io::Error::from(
                    io::ErrorKind::InvalidInput,
                )));
            }
        };

        if let Some(stream_id) = expect_stream_id {
            if stream_id != packet_body.stream_id {
                return Err(ProtocolError::IoError(io::Error::from(
                    io::ErrorKind::InvalidInput,
                )));
            }
        }

        if packet_body.stream_offset < 0 {
            return Err(ProtocolError::IoError(io::Error::from(
                io::ErrorKind::InvalidInput,
            )));
        }

        if packet_body.content.is_empty()
            || packet_body.stream_id < 0
            || packet_body.padding_size as usize >= packet_body.content.len()
        {
            return Ok(StreamPacketFragmentUnpack {
                stream_offset: packet_body.stream_offset,
                fragment: vec![],
                packet_flag: packet_body.flags,
                timepoint_microseconds: packet_body.timepoint_microseconds,
            });
        }

        let packets = {
            let content_bytes = if packet_body.padding_size > 0 {
                &packet_body.content
                    [0..packet_body.content.len() - packet_body.padding_size as usize]
            } else {
                &packet_body.content
            };

            match PacketContentMessage::decode(content_bytes) {
                Ok(p) => p,
                Err(e) => {
                    return Err(ProtocolError::DecodeFailed(e));
                }
            }
        };

        let mut ret = StreamPacketFragmentUnpack {
            stream_offset: packet_body.stream_offset,
            fragment: vec![],
            packet_flag: packet_body.flags,
            timepoint_microseconds: packet_body.timepoint_microseconds,
        };
        ret.fragment.reserve(packets.fragment.len());

        let mut start_offset = packet_body.stream_offset;
        for p in packets.fragment {
            let length = p.data.len();

            ret.fragment
                .push(StreamPacketFragmentMessage::new(start_offset, p));

            start_offset += length as i64;
        }

        Ok(ret)
    }

    pub fn get_fragment_message(&self) -> &PacketFragmentMessage {
        &self.data
    }

    pub fn get_message_length(&self) -> usize {
        self.data.data.len()
    }

    pub fn get_message_begin_offset(&self) -> i64 {
        self.offset
    }

    pub fn get_message_end_offset(&self) -> i64 {
        self.offset + self.data.data.len() as i64
    }

    #[inline]
    pub fn check_target_fragment_flag(target: i32, flag: PacketFragmentFlagType) -> bool {
        (target & flag as i32) != 0
    }

    #[inline]
    pub fn check_fragment_flag(&self, flag: PacketFragmentFlagType) -> bool {
        Self::check_target_fragment_flag(self.data.fragment_flag, flag)
    }

    pub fn is_empty(&self) -> bool {
        self.data.data.len() == 0
    }

    pub fn sub_frame(&self, start_offset: usize) -> Option<StreamPacketFragmentMessage> {
        if start_offset >= self.data.data.len() {
            None
        } else {
            Some(Self::new(
                self.offset + start_offset as i64,
                PacketFragmentMessage {
                    packet_type: self.data.packet_type,
                    data: self.data.data.slice(start_offset..),
                    fragment_flag: self.data.fragment_flag,
                    options: self.data.options.clone(),
                    labels: self.data.labels.clone(),
                    forward_for: self.data.forward_for.clone(),
                    close_reason: self.data.close_reason.clone(),
                },
            ))
        }
    }
}

#[cfg(test)]
mod test {
    // use super::super::error::ProtocolError;
    // use super::FrameBlockAlgorithm;
    // use super::VarintData;
    // use std::io;

    #[test]
    fn test_decode_varint_error() {}
}
