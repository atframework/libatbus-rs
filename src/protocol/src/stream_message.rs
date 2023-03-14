// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::HashMap;
use std::io;

use crate::prost::Message;

use super::{
    error::{ProtocolError, ProtocolResult},
    BoxedFrameMessage, CloseReasonMessage, ForwardMessage, FrameMessageBody, PacketContentMessage,
    PacketFragmentMessage, PacketOptionMessage,
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

pub struct StreamFramePacketMessage {
    pub frame_message: BoxedFrameMessage,
    pub packet: Vec<PacketFragmentMessage>,
    length: usize,
}

impl StreamFramePacketMessage {
    pub fn with(mut frame: BoxedFrameMessage) -> ProtocolResult<StreamFramePacketMessage> {
        let mut frame_body = match frame.body.as_mut() {
            Some(b) => b,
            _ => {
                return Err(ProtocolError::IoError(io::Error::from(
                    io::ErrorKind::InvalidInput,
                )));
            }
        };

        let packet_body = match &mut frame_body {
            &mut FrameMessageBody::Packet(ref mut p) => p,
            _ => {
                return Err(ProtocolError::IoError(io::Error::from(
                    io::ErrorKind::InvalidInput,
                )));
            }
        };

        if packet_body.content.is_empty()
            || packet_body.stream_id < 0
            || packet_body.padding_size as usize >= packet_body.content.len()
        {
            return Ok(StreamFramePacketMessage {
                frame_message: frame,
                packet: vec![],
                length: 0,
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
        packet_body.content.clear();

        let mut length = 0;
        for p in &packets.fragment {
            length += p.data.len();
        }

        Ok(StreamFramePacketMessage {
            frame_message: frame,
            packet: packets.fragment,
            length: length,
        })
    }

    pub fn get_packet_length(&self) -> usize {
        self.length
    }

    pub fn sub_frame(&self, start_offset: usize) -> StreamFramePacketMessage {
        let mut fragments = vec![];
        let mut left_offset = start_offset;
        for fragment in &self.packet {
            if left_offset > 0 {
                if left_offset >= fragment.data.len() {
                    left_offset -= fragment.data.len();
                } else {
                    let modify_fragment = PacketFragmentMessage {
                        packet_type: fragment.packet_type,
                        data: Vec::from(&fragment.data.as_slice()[left_offset..]),
                        fragment_flag: fragment.fragment_flag,
                        options: fragment.options.clone(),
                        labels: fragment.labels.clone(),
                        forward_for: fragment.forward_for.clone(),
                        close_reason: fragment.close_reason.clone(),
                    };
                    fragments.push(modify_fragment);
                    left_offset = 0;
                }
            } else {
                fragments.push(fragment.clone());
            }
        }

        let mut length = 0;
        for fragment in &fragments {
            length += fragment.data.len();
        }

        let mut frame_message = self.frame_message.clone();
        if self.length > length {
            if let Some(ref mut body) = frame_message.body.as_mut() {
                if let &mut FrameMessageBody::Packet(p) = body {
                    p.stream_offset += (self.length - length) as i64;
                }
            }
        }

        StreamFramePacketMessage {
            frame_message: frame_message,
            packet: fragments,
            length: length,
        }
    }
}
