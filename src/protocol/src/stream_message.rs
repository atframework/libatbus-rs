// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::HashMap;
use std::io;

use crate::prost::Message;

use super::{
    error::{ProtocolError, ProtocolResult},
    BoxedFrameMessage, CloseReasonMessage, ForwardMessage, FrameMessageBody, PacketContentMessage,
    PacketFragmentFlagType, PacketFragmentMessage, PacketOptionMessage,
};

pub struct StreamMessage {
    pub start_stream_offset: i64,
    pub data: Vec<u8>,

    /// @see atbus.protocol.ATBUS_PACKET_FLAG_TYPE
    pub flags: i32,

    pub options: Option<Box<PacketOptionMessage>>,
    pub labels: Option<Box<HashMap<String, Vec<u8>>>>,
    pub forward_for: Option<Box<ForwardMessage>>,
    pub close_reason: Option<Box<CloseReasonMessage>>,
}

pub struct StreamPacketFragmentMessage {
    offset: i64,
    data: PacketFragmentMessage,
}

pub struct StreamPacketFragmentUnpack {
    pub stream_offset: i64,
    pub fragment: Vec<StreamPacketFragmentMessage>,
    pub packet_flag: i32,
    pub timepoint_microseconds: i64,
}

impl StreamPacketFragmentMessage {
    pub fn new(offset: i64, data: PacketFragmentMessage) -> Self {
        StreamPacketFragmentMessage { offset, data }
    }

    pub fn unpack(frame: BoxedFrameMessage) -> ProtocolResult<StreamPacketFragmentUnpack> {
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
                &packet_body.content.as_slice()
                    [0..packet_body.content.len() - packet_body.padding_size as usize]
            } else {
                &packet_body.content.as_slice()
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

    pub fn check_fragment_flag(&self, flag: PacketFragmentFlagType) -> bool {
        (self.data.fragment_flag & flag as i32) != 0
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
                    data: Vec::from(&self.data.data.as_slice()[start_offset..]),
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
