// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io;
use std::ops::Bound::Included;
use std::rc::Rc;

use crate::prost::Message;

use super::{
    error::{ProtocolError, ProtocolResult},
    BoxedFrameMessage, CloseReasonMessage, ForwardMessage, FrameMessage, FrameMessageBody,
    FrameMessageHead, PacketContentMessage, PacketFlagType, PacketFragmentFlagType,
    PacketFragmentMessage, PacketMessage, PacketOptionMessage,
};

use super::decoder::Decoder;
use super::encoder::{Encoder, EncoderFrame};
use super::proto;
type InternalMessageType = proto::atbus::protocol::AtbusPacketType;

pub struct StreamConnectionContext {
    stream_id: i64,
    encoder: Encoder,
    frame_message_template: FrameMessage,
    frame_message_predict_size: usize,
    frame_message_has_data: bool,
    fragment_message_template: proto::atbus::protocol::PacketContent,
    fragment_message_predict_size: usize,
    packet_padding_size: usize,

    /// If packet_padding_size is power of 2, optimize the padding algorithm to bit shift
    packet_padding_bits: Option<usize>,
}

pub type SharedStreamConnectionContext = Rc<RefCell<StreamConnectionContext>>;

pub struct StreamMessage {
    pub packet_type: i32,
    pub stream_offset: i64,
    pub data: ::prost::bytes::Bytes,

    /// @see atbus.protocol.ATBUS_PACKET_FLAG_TYPE
    pub flags: i32,

    /// Only has value when has ATBUS_PACKET_FLAG_TYPE_FINISH_STREAM or ATBUS_PACKET_FLAG_TYPE_FINISH_CONNECTION
    pub close_reason: Option<Box<CloseReasonMessage>>,
}

pub struct StreamConnectionMessage {
    /// message
    message: StreamMessage,

    /// Connection context
    connection_context: SharedStreamConnectionContext,
}

pub struct StreamPacketInformation {
    pub head: Option<FrameMessageHead>,
    pub packet_flag: i32,
    pub timepoint_microseconds: i64,
}

pub type SharedStreamPacketInformation = Rc<StreamPacketInformation>;

pub struct StreamPacketFragmentMessage {
    pub packet: SharedStreamPacketInformation,
    pub offset: i64,
    pub data: PacketFragmentMessage,
}

pub struct StreamPacketFragmentUnpack {
    pub packet: SharedStreamPacketInformation,
    pub stream_offset: i64,
    pub fragment: ::prost::alloc::vec::Vec<StreamPacketFragmentMessage>,
}

struct StreamPacketUnfinishedFragment {
    stream_offset: i64,
    data: bytes::BytesMut,
    packet_flags: i32,
}

pub struct StreamPacketFragmentPack {
    pub frame_count: usize,
    pub consume_size: usize,
    unfinished_packet_fragment_data: Option<StreamPacketUnfinishedFragment>,
    next_packet_fragment_offset: i64,
}

impl StreamPacketInformation {
    pub fn has_packet_flag_finish_stream(&self) -> bool {
        (self.packet_flag & PacketFlagType::FinishStream as i32) != 0
    }

    pub fn has_packet_flag_finish_connection(&self) -> bool {
        (self.packet_flag & PacketFlagType::FinishConnection as i32) != 0
    }

    pub fn has_packet_flag_reset_offset(&self) -> bool {
        (self.packet_flag & PacketFlagType::ResetOffset as i32) != 0
    }

    pub fn is_tls_handshake(&self) -> bool {
        (self.packet_flag & PacketFlagType::TlsHandshake as i32) != 0
    }
}

impl Default for StreamPacketUnfinishedFragment {
    fn default() -> Self {
        StreamPacketUnfinishedFragment {
            stream_offset: 0,
            data: bytes::BytesMut::new(),
            packet_flags: 0,
        }
    }
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
            stream_id,
            encoder: Encoder::new(),
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
            frame_message_has_data: false,
            fragment_message_template: proto::atbus::protocol::PacketContent {
                fragment: vec![PacketFragmentMessage {
                    packet_type: InternalMessageType::Handshake as i32,
                    data: bytes::Bytes::new(),
                    fragment_flag: PacketFragmentFlagType::HasMore as i32,
                    options: options,
                    labels: labels,
                    forward_for: forward_for,
                    close_reason: None,
                }],
            },
            fragment_message_predict_size: 0,
            packet_padding_size: packet_padding_size,
            packet_padding_bits: None,
        };

        // Reserve varint for packet and content field.
        // Reserve encoder length
        ret.frame_message_predict_size =
            ret.frame_message_template.encoded_len() + ret.encoder.get_reserve_header_length();

        ret.fragment_message_predict_size = ret.fragment_message_template.encoded_len();

        // Optimize padding algorithm
        if ret.packet_padding_size > 1
            && ((ret.packet_padding_size - 1) & ret.packet_padding_size) == 0
        {
            let mut padding_bits = 0;
            let mut padding_size = ret.packet_padding_size;
            while padding_size > 1 {
                padding_bits += 1;
                padding_size >>= 1;
            }
            ret.packet_padding_bits = Some(padding_bits);
        }

        ret
    }

    pub fn reset_padding_size(&mut self, packet_padding_size: usize) {
        let mut restore_unpacked_frame_body: Option<PacketMessage> = None;
        if let Some(b) = self.frame_message_template.body.as_mut() {
            if let FrameMessageBody::Packet(ref mut p) = b {
                if self.frame_message_has_data {
                    restore_unpacked_frame_body = Some(p.clone());
                }
                p.stream_offset = 1;
                p.content = bytes::Bytes::new();
                p.flags = 16;
                p.padding_size = packet_padding_size as i32;
                p.timepoint_microseconds = 1;
            }
        }

        // Reserve varint for packet and content field.
        self.frame_message_predict_size =
            self.frame_message_template.encoded_len() + self.encoder.get_reserve_header_length();

        // Restore packet
        if let Some(rp) = restore_unpacked_frame_body {
            if let Some(b) = self.frame_message_template.body.as_mut() {
                if let FrameMessageBody::Packet(ref mut p) = b {
                    *p = rp;
                }
            }
        }

        self.packet_padding_size = packet_padding_size;
        // Optimize padding algorithm
        if self.packet_padding_size > 1
            && ((self.packet_padding_size - 1) & self.packet_padding_size) == 0
        {
            let mut padding_bits = 0;
            let mut padding_size = self.packet_padding_size;
            while padding_size > 1 {
                padding_bits += 1;
                padding_size >>= 1;
            }
            self.packet_padding_bits = Some(padding_bits);
        } else {
            self.packet_padding_bits = None;
        }
    }

    #[inline]
    pub fn get_padding_size(&self) -> usize {
        self.packet_padding_size
    }

    #[inline]
    pub fn is_fast_padding(&self) -> bool {
        self.packet_padding_bits.is_some()
    }

    pub fn clear_fragment_template_forward_for(&mut self) {
        let mut need_rebuild_predict_size = false;
        for f in self.fragment_message_template.fragment.iter_mut() {
            if f.forward_for.is_none() {
                continue;
            }

            need_rebuild_predict_size = true;
            f.forward_for = None;
        }

        if need_rebuild_predict_size {
            self.fragment_message_predict_size = self.fragment_message_template.encoded_len();
        }
    }

    /// Returns tha additional padding size
    pub(crate) fn construct_frame_message(
        &mut self,
        packer: &mut StreamPacketFragmentPack,
        timepoint_microseconds: i64,
    ) -> ProtocolResult<()> {
        if self.frame_message_has_data {
            return Err(ProtocolError::CacheFull);
        }

        let stream_offset = if let Some(p) = &packer.unfinished_packet_fragment_data {
            p.stream_offset
        } else {
            packer.next_packet_fragment_offset
        };

        let mut need_construct = true;
        if let Some(b) = self.frame_message_template.body.as_ref() {
            if let FrameMessageBody::Packet(_) = b {
                need_construct = false;
            }
        }

        if need_construct {
            self.frame_message_template.body = Some(FrameMessageBody::Packet(PacketMessage {
                stream_id: self.stream_id,
                stream_offset: stream_offset,
                content: bytes::Bytes::new(),
                flags: 16,
                padding_size: 0,
                timepoint_microseconds: timepoint_microseconds,
            }));
        }

        let (content, flags, padding_size) =
            if let Some(mut fragment_data) = packer.unfinished_packet_fragment_data.take() {
                // Padding
                let mut padding_size = 0;
                if self.packet_padding_size > 1 && !fragment_data.data.is_empty() {
                    let padding_ceil = self.padding_len_ceil(fragment_data.data.len());
                    if padding_ceil > fragment_data.data.len() {
                        // TODO better random filled value
                        padding_size = (padding_ceil - fragment_data.data.len()) as i32;
                        fragment_data.data.resize(padding_ceil, 0);
                    }
                }

                (
                    fragment_data.data.freeze(),
                    fragment_data.packet_flags,
                    padding_size,
                )
            } else {
                (bytes::Bytes::new(), 0, 0)
            };

        if let Some(b) = self.frame_message_template.body.as_mut() {
            if let FrameMessageBody::Packet(ref mut p) = b {
                p.stream_id = self.stream_id;
                p.stream_offset = stream_offset;
                p.padding_size = padding_size;
                p.content = content;
                p.flags = flags;

                p.timepoint_microseconds = timepoint_microseconds;
            }
        }

        self.frame_message_has_data = true;

        Ok(())
    }

    pub(crate) fn pack_frame_message<B>(
        &mut self,
        output: B,
        packer: &mut StreamPacketFragmentPack,
    ) -> ProtocolResult<(usize, B)>
    where
        B: bytes::BufMut,
    {
        if !self.frame_message_has_data {
            return Ok((0, output));
        }

        let (consume_size, next_output) = self
            .encoder
            .put_block(EncoderFrame::new(&self.frame_message_template), output)?;

        packer.consume_size += consume_size;
        packer.frame_count += 1;

        self.frame_message_has_data = false;

        Ok((consume_size, next_output))
    }

    /// Returns tha additional padding size
    pub(crate) fn append_fragment_message(
        &mut self,
        packet_size_limit: usize,
        packer: &mut StreamPacketFragmentPack,
        stream_connection_message: &StreamConnectionMessage,
        len: usize,
        force_packet_reset: bool,
    ) -> ProtocolResult<()> {
        if packer.next_packet_fragment_offset < stream_connection_message.get_message_begin_offset()
            || packer.next_packet_fragment_offset + (len as i64)
                > stream_connection_message.get_message_end_offset()
        {
            return Err(ProtocolError::IoError(io::Error::from(
                io::ErrorKind::InvalidInput,
            )));
        }

        if self.fragment_message_template.fragment.is_empty() {
            self.fragment_message_template
                .fragment
                .push(PacketFragmentMessage {
                    packet_type: InternalMessageType::Handshake as i32,
                    data: bytes::Bytes::new(),
                    fragment_flag: PacketFragmentFlagType::HasMore as i32,
                    options: None,
                    labels: HashMap::new(),
                    forward_for: None,
                    close_reason: None,
                });
        }

        let mut fragment = self.fragment_message_template.fragment.get_mut(0).unwrap();
        fragment.packet_type = stream_connection_message.message.packet_type;

        let start_idx = (packer.next_packet_fragment_offset
            - stream_connection_message.get_message_begin_offset())
            as usize;
        fragment.data = stream_connection_message
            .message
            .data
            .slice(start_idx..(start_idx + len));
        fragment.fragment_flag = stream_connection_message
            .get_fragment_fragment_flag(packer.next_packet_fragment_offset, len);
        fragment.close_reason =
            if let Some(cr) = stream_connection_message.message.close_reason.as_ref() {
                if packer.next_packet_fragment_offset + (len as i64)
                    >= stream_connection_message.get_message_end_offset()
                {
                    Some(cr.as_ref().clone())
                } else {
                    None
                }
            } else {
                None
            };

        if let Some(p) = packer.unfinished_packet_fragment_data.as_mut() {
            match self.fragment_message_template.encode(&mut p.data) {
                Ok(_) => {}
                Err(e) => {
                    return Err(ProtocolError::EncodeFailed(e));
                }
            }
            packer.next_packet_fragment_offset += len as i64;

            if force_packet_reset {
                p.packet_flags |= PacketFlagType::ResetOffset as i32;
            }
        } else {
            let mut new_unfinished_fragment = StreamPacketUnfinishedFragment {
                stream_offset: packer.next_packet_fragment_offset,
                data: bytes::BytesMut::with_capacity(packet_size_limit),
                packet_flags: stream_connection_message
                    .get_fragment_packet_flag(packer.next_packet_fragment_offset, len),
            };
            if force_packet_reset {
                new_unfinished_fragment.packet_flags |= PacketFlagType::ResetOffset as i32;
            }

            match self
                .fragment_message_template
                .encode(&mut new_unfinished_fragment.data)
            {
                Ok(_) => {}
                Err(e) => {
                    return Err(ProtocolError::EncodeFailed(e));
                }
            }
            packer.next_packet_fragment_offset += len as i64;

            packer.unfinished_packet_fragment_data = Some(new_unfinished_fragment);
        }

        Ok(())
    }

    fn padding_len_ceil(&self, len: usize) -> usize {
        if self.packet_padding_size <= 1 {
            len
        } else {
            if let Some(padding_bits) = self.packet_padding_bits.as_ref() {
                (len + self.packet_padding_size - 1) & !((1 << padding_bits) - 1)
            } else {
                let padding_mod = len % self.packet_padding_size;
                if padding_mod == 0 {
                    len
                } else {
                    len + self.packet_padding_size - padding_mod
                }
            }
        }
    }

    fn padding_len_floor(&self, len: usize) -> usize {
        if self.packet_padding_size <= 1 {
            len
        } else {
            if let Some(padding_bits) = self.packet_padding_bits.as_ref() {
                len & !((1 << padding_bits) - 1)
            } else {
                len - len % self.packet_padding_size
            }
        }
    }

    pub fn get_stream_id(&self) -> i64 {
        self.stream_id
    }
}

impl StreamMessage {
    pub fn new(
        packet_type: i32,
        stream_offset: i64,
        data: ::prost::bytes::Bytes,
        flags: i32,
        close_reason: Option<Box<CloseReasonMessage>>,
    ) -> Self {
        StreamMessage {
            packet_type,
            stream_offset,
            data,
            flags,
            close_reason,
        }
    }

    pub fn has_packet_flag_finish_stream(&self) -> bool {
        (self.flags & PacketFlagType::FinishStream as i32) != 0
    }

    pub fn has_packet_flag_finish_connection(&self) -> bool {
        (self.flags & PacketFlagType::FinishConnection as i32) != 0
    }

    pub fn has_packet_flag_reset_offset(&self) -> bool {
        (self.flags & PacketFlagType::ResetOffset as i32) != 0
    }

    pub fn is_tls_handshake(&self) -> bool {
        (self.flags & PacketFlagType::TlsHandshake as i32) != 0
    }
}

impl StreamConnectionMessage {
    pub fn new(
        connection_context: SharedStreamConnectionContext,
        packet_type: i32,
        stream_offset: i64,
        data: ::prost::bytes::Bytes,
        flags: i32,
        close_reason: Option<Box<CloseReasonMessage>>,
    ) -> Self {
        StreamConnectionMessage {
            message: StreamMessage::new(packet_type, stream_offset, data, flags, close_reason),
            connection_context,
        }
    }

    pub fn predict_frame_size(
        &self,
        stream_offset: i64,
        timepoint_microseconds: i64,
        close_reason: &Option<Box<CloseReasonMessage>>,
    ) -> (usize, usize) {
        let header_len = self.connection_context.borrow().frame_message_predict_size
            + prost::length_delimiter_len(if stream_offset > 0 {
                stream_offset as usize
            } else {
                0
            })
            - 1
            + prost::length_delimiter_len(if timepoint_microseconds > 0 {
                timepoint_microseconds as usize
            } else {
                0
            })
            - 1;

        let fragment_header_len = self.predict_fragment_size(&close_reason);

        // Reserve tag and length varint for packet_data's content field.
        // Reserve varint for encoder's length header.
        let max_fragment_data_length_size = prost::length_delimiter_len(
            header_len + fragment_header_len + self.message.data.len() + 1,
        );
        (
            header_len + max_fragment_data_length_size + max_fragment_data_length_size + 1,
            fragment_header_len,
        )
    }

    fn predict_fragment_size(&self, close_reason: &Option<Box<CloseReasonMessage>>) -> usize {
        let header_len;
        if let Some(cr) = close_reason {
            let encoded_len_of_cr = cr.encoded_len();
            header_len = self.connection_context.borrow().fragment_message_predict_size
            // Key tag use last 3 bits of first byte as wire type.
            + prost::length_delimiter_len(7 * 8) // 7 is the tag of close_reason
            + prost::length_delimiter_len(encoded_len_of_cr);
        } else {
            header_len = self
                .connection_context
                .borrow()
                .fragment_message_predict_size;
        }

        // Reserve tag and varint for fragment's data field.
        // Reserve varint of fragment field(already has 1 before).
        let max_fragment_data_length_size =
            prost::length_delimiter_len(self.message.data.len() + header_len + 1);
        header_len + max_fragment_data_length_size + max_fragment_data_length_size
    }

    pub fn get_message_length(&self) -> usize {
        self.message.data.len()
    }

    pub fn get_message_begin_offset(&self) -> i64 {
        self.message.stream_offset
    }

    pub fn get_message_end_offset(&self) -> i64 {
        self.message.stream_offset + self.message.data.len() as i64
    }

    pub fn get_fragment_packet_flag(&self, start_stream_offset: i64, len: usize) -> i32 {
        if start_stream_offset <= self.get_message_begin_offset()
            && (start_stream_offset + len as i64) >= self.get_message_end_offset()
        {
            self.message.flags
        } else {
            let mut ret = self.message.flags;
            if start_stream_offset > self.get_message_begin_offset() {
                ret &= !(PacketFlagType::ResetOffset as i32);
            }

            if (start_stream_offset + len as i64) < self.get_message_end_offset() {
                ret &= !(PacketFlagType::FinishConnection as i32
                    | PacketFlagType::FinishStream as i32);
            }

            ret
        }
    }

    pub fn get_fragment_fragment_flag(&self, start_stream_offset: i64, len: usize) -> i32 {
        if (start_stream_offset + len as i64) >= self.get_message_end_offset() {
            PacketFragmentFlagType::None as i32
        } else {
            PacketFragmentFlagType::HasMore as i32
        }
    }

    pub fn pack<B>(
        input: &BTreeMap<i64, Box<Self>>,
        output: B,
        start_stream_offset: i64,
        packet_size_limit: usize,
        timepoint_microseconds: i64,
    ) -> ProtocolResult<StreamPacketFragmentPack>
    where
        B: bytes::BufMut,
    {
        let mut ret = StreamPacketFragmentPack {
            frame_count: 0,
            consume_size: 0,
            unfinished_packet_fragment_data: None,
            next_packet_fragment_offset: start_stream_offset,
        };

        if input.is_empty() {
            return Ok(ret);
        }

        {
            let last_kv = input.last_key_value().unwrap();
            if ret.next_packet_fragment_offset >= *last_kv.0 + last_kv.1.message.data.len() as i64 {
                return Ok(ret);
            }
        }

        let mut force_reset =
            if ret.next_packet_fragment_offset < *input.first_key_value().unwrap().0 {
                ret.next_packet_fragment_offset = *input.first_key_value().unwrap().0;
                true
            } else {
                false
            };

        // Find the first element
        let start_element_offset = {
            let mut find_range = input
                .range((Included(0), Included(ret.next_packet_fragment_offset)))
                .rev();
            let mut first_offset = None;
            while let Some(element) = find_range.next() {
                if *element.0 <= ret.next_packet_fragment_offset {
                    first_offset = Some(*element.0);
                    break;
                }
            }

            if let Some(x) = first_offset {
                x
            } else {
                return Ok(ret);
            }
        };

        let mut next_output = output;
        let select_range = input.range(start_element_offset..);
        for current_message in select_range.clone() {
            let res = current_message.1.pack_internal(
                next_output,
                &mut ret,
                packet_size_limit,
                timepoint_microseconds,
                force_reset,
            )?;
            // Only first frame need force reset
            force_reset = false;

            // Full
            if ret.next_packet_fragment_offset < current_message.1.get_message_end_offset() {
                next_output = current_message
                    .1
                    .pack_finish(res.1, &mut ret, timepoint_microseconds)?
                    .1;
                break;
            }

            next_output = res.1;
        }

        // Last message unfinished, finish the frame
        if let Some(last_message) = select_range.last() {
            if ret.next_packet_fragment_offset >= last_message.1.get_message_end_offset() {
                let _ =
                    last_message
                        .1
                        .pack_finish(next_output, &mut ret, timepoint_microseconds)?;
            }
        }

        Ok(ret)
    }

    fn padding_len_ceil(&self, len: usize) -> usize {
        self.connection_context.borrow().padding_len_ceil(len)
    }

    fn padding_len_floor(&self, len: usize) -> usize {
        self.connection_context.borrow().padding_len_floor(len)
    }

    fn pack_internal<B>(
        &self,
        output: B,
        mut packer: &mut StreamPacketFragmentPack,
        packet_size_limit: usize,
        timepoint_microseconds: i64,
        force_packet_reset: bool,
    ) -> ProtocolResult<(usize, B)>
    where
        B: bytes::BufMut,
    {
        if packer.next_packet_fragment_offset >= self.get_message_end_offset()
            || packer.next_packet_fragment_offset < self.get_message_begin_offset()
        {
            return Err(ProtocolError::IoError(io::Error::from(
                io::ErrorKind::InvalidInput,
            )));
        }

        let (frame_head_reserve_size, fragment_head_reserve_size) = self.predict_frame_size(
            packer.next_packet_fragment_offset,
            timepoint_microseconds,
            &self.message.close_reason,
        );

        let padding_size = self.connection_context.borrow().get_padding_size();

        if packet_size_limit < frame_head_reserve_size + fragment_head_reserve_size + padding_size {
            return Err(ProtocolError::IoError(io::Error::from(
                io::ErrorKind::InvalidData,
            )));
        }

        let fragment_max_data_len = self.padding_len_floor(
            packet_size_limit - frame_head_reserve_size - fragment_head_reserve_size,
        );
        let mut consume_size = 0;
        let mut next_output = output;

        let mut need_finish_previous_package = false;
        while packer.next_packet_fragment_offset < self.get_message_end_offset() {
            if need_finish_previous_package {
                let res = self.pack_finish(next_output, &mut packer, timepoint_microseconds)?;
                consume_size += res.0;
                next_output = res.1;

                need_finish_previous_package = false;
                continue;
            }

            if let Some(upf) = packer.unfinished_packet_fragment_data.as_ref() {
                let unfinished_fragment_len_with_headers = self.padding_len_ceil(upf.data.len())
                    + frame_head_reserve_size
                    + fragment_head_reserve_size;

                // If current message need reset and it's the first fragment, do not reuse the previous frame.
                if unfinished_fragment_len_with_headers + padding_size >= packet_size_limit
                    || fragment_max_data_len <= upf.data.len() + padding_size
                    || ((self.message.flags & PacketFlagType::ResetOffset as i32) != 0
                        && packer.next_packet_fragment_offset == self.get_message_begin_offset())
                    || force_packet_reset
                {
                    need_finish_previous_package = true;
                    continue;
                }
            }

            let fragment_left_data_len =
                self.get_message_end_offset() - packer.next_packet_fragment_offset;

            // Insert into previous frame first
            if let Some(upf) = packer.unfinished_packet_fragment_data.as_mut() {
                // Full and exit
                if next_output.remaining_mut()
                    <= fragment_head_reserve_size
                        + frame_head_reserve_size
                        + padding_size
                        + self.padding_len_ceil(upf.data.len())
                {
                    return Ok((consume_size, next_output));
                }
                // After padding
                let left_output_data_len = self.padding_len_floor(
                    next_output.remaining_mut()
                        - fragment_head_reserve_size
                        - frame_head_reserve_size,
                );
                if left_output_data_len <= upf.data.len() + padding_size {
                    return Ok((consume_size, next_output));
                }

                let current_fragment_available_data_len = std::cmp::min(
                    fragment_max_data_len - upf.data.len(),
                    left_output_data_len - upf.data.len(),
                );

                // Left data can be all filled into current frame
                if current_fragment_available_data_len >= (fragment_left_data_len as usize) {
                    // Finish previous
                    if upf.packet_flags
                        != self.get_fragment_packet_flag(
                            packer.next_packet_fragment_offset,
                            fragment_left_data_len as usize,
                        )
                    {
                        need_finish_previous_package = true;
                        continue;
                    }

                    // Append to existed frame
                    let _ = self
                        .connection_context
                        .borrow_mut()
                        .append_fragment_message(
                            packet_size_limit,
                            &mut packer,
                            &self,
                            fragment_left_data_len as usize,
                            force_packet_reset,
                        )?;
                } else {
                    // Finish previous
                    need_finish_previous_package = true;
                    if upf.packet_flags
                        != self.get_fragment_packet_flag(
                            packer.next_packet_fragment_offset,
                            current_fragment_available_data_len,
                        )
                    {
                        continue;
                    }

                    // Append to existed frame
                    let _ = self
                        .connection_context
                        .borrow_mut()
                        .append_fragment_message(
                            packet_size_limit,
                            &mut packer,
                            &self,
                            current_fragment_available_data_len,
                            force_packet_reset,
                        )?;
                }
            } else {
                // Full and exit
                if next_output.remaining_mut()
                    <= fragment_head_reserve_size + frame_head_reserve_size
                {
                    return Ok((consume_size, next_output));
                }

                // After padding
                let left_output_data_len = self.padding_len_floor(
                    next_output.remaining_mut()
                        - fragment_head_reserve_size
                        - frame_head_reserve_size,
                );
                if left_output_data_len <= 0 {
                    return Ok((consume_size, next_output));
                }

                let current_fragment_available_data_len =
                    std::cmp::min(fragment_max_data_len, left_output_data_len);

                // Left data can be all filled into one frame
                if current_fragment_available_data_len >= (fragment_left_data_len as usize) {
                    // Append to new frame
                    let _ = self
                        .connection_context
                        .borrow_mut()
                        .append_fragment_message(
                            packet_size_limit,
                            &mut packer,
                            &self,
                            fragment_left_data_len as usize,
                            force_packet_reset,
                        )?;
                } else {
                    // Append to new frame
                    let _ = self
                        .connection_context
                        .borrow_mut()
                        .append_fragment_message(
                            packet_size_limit,
                            &mut packer,
                            &self,
                            current_fragment_available_data_len,
                            force_packet_reset,
                        )?;
                    need_finish_previous_package = true;
                }
            }
        }

        Ok((consume_size, next_output))
    }

    fn pack_finish<B>(
        &self,
        output: B,
        mut packer: &mut StreamPacketFragmentPack,
        timepoint_microseconds: i64,
    ) -> ProtocolResult<(usize, B)>
    where
        B: bytes::BufMut,
    {
        let (mut consume_size, next_output) =
            if self.connection_context.borrow().frame_message_has_data {
                let res = self
                    .connection_context
                    .borrow_mut()
                    .pack_frame_message(output, &mut packer)?;
                res
            } else {
                (0, output)
            };

        if !packer.unfinished_packet_fragment_data.is_some() {
            return Ok((consume_size, next_output));
        }

        let _ = self
            .connection_context
            .borrow_mut()
            .construct_frame_message(&mut packer, timepoint_microseconds)?;

        let res = self
            .connection_context
            .borrow_mut()
            .pack_frame_message(next_output, &mut packer)?;

        consume_size += res.0;
        Ok((consume_size, res.1))
    }
}

impl StreamPacketFragmentMessage {
    pub fn new(
        packet: Rc<StreamPacketInformation>,
        offset: i64,
        data: PacketFragmentMessage,
    ) -> Self {
        StreamPacketFragmentMessage {
            packet,
            offset,
            data,
        }
    }

    pub fn unpack_from_buffer<B>(
        decoder: &Decoder,
        buf: B,
        expect_stream_id: Option<i64>,
    ) -> ProtocolResult<(StreamPacketFragmentUnpack, usize)>
    where
        B: bytes::Buf,
    {
        match decoder.peek(buf) {
            Ok(f) => {
                let unpack = Self::unpack(f.message, expect_stream_id)?;
                Ok((unpack, f.consume_length))
            }
            Err(e) => Err(e.into()),
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
                packet: Rc::new(StreamPacketInformation {
                    head: frame.head,
                    packet_flag: packet_body.flags,
                    timepoint_microseconds: packet_body.timepoint_microseconds,
                }),
                stream_offset: packet_body.stream_offset,
                fragment: vec![],
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
            packet: Rc::new(StreamPacketInformation {
                head: frame.head,
                packet_flag: packet_body.flags,
                timepoint_microseconds: packet_body.timepoint_microseconds,
            }),
            stream_offset: packet_body.stream_offset,
            fragment: vec![],
        };
        ret.fragment.reserve(packets.fragment.len());

        let mut start_offset = packet_body.stream_offset;
        for p in packets.fragment {
            let length = p.data.len();

            ret.fragment.push(StreamPacketFragmentMessage::new(
                ret.packet.clone(),
                start_offset,
                p,
            ));

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
                self.packet.clone(),
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
    use super::super::ProtocolConst;
    use super::*;
    use crate::rand::{thread_rng, Rng};
    use std::cell::RefCell;
    use std::io;
    use std::ops::DerefMut;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::vec::Vec;

    fn create_context(
        need_forward_for: bool,
        padding_size: usize,
    ) -> SharedStreamConnectionContext {
        Rc::new(RefCell::new(StreamConnectionContext::new(
            FrameMessageHead {
                source: String::from("relaysvr:node-random-name-abcdefg"),
                destination: String::from("server:node-random-name-abcdefg"),
                forward_for_source: String::from("client:node-random-name-abcdefg"),
                forward_for_connection_id: 5321,
            },
            0,
            padding_size,
            Some(PacketOptionMessage {
                token: Some(String::from("0123456789abcdef").into_bytes().into()),
            }),
            HashMap::new(),
            if need_forward_for {
                Some(ForwardMessage {
                    version: ProtocolConst::Version as i32,
                    source: String::from("client:node-random-name-abcdefg"),
                    scheme: String::from("udp"),
                    address: String::from("fe80:820c:8210:a342:7587:26a4:b232:2e99"),
                    port: 16359,
                    connection_id: 5321,
                    attributes: HashMap::new(),
                })
            } else {
                None
            },
        )))
    }

    fn create_stream_messages(
        ctx: &SharedStreamConnectionContext,
        start_offset: i64,
        message_sizes: &[i64],
    ) -> BTreeMap<i64, Box<StreamConnectionMessage>> {
        let mut ret = BTreeMap::new();
        let mut offset = start_offset;
        for s in message_sizes {
            let data_buffer: Vec<u8> = if *s > 0 {
                let mut res = vec![b'0'; *s as usize];
                thread_rng().fill(res.deref_mut());
                res
            } else {
                Vec::new()
            };

            ret.insert(
                offset,
                Box::new(StreamConnectionMessage::new(
                    ctx.clone(),
                    super::InternalMessageType::Data as i32,
                    offset,
                    data_buffer.into(),
                    0,
                    None,
                )),
            );

            offset += *s;
        }

        ret
    }

    #[test]
    fn test_padding_size() {
        let ctx1 = create_context(false, 256);
        let ctx2 = create_context(false, 384);

        assert_eq!(ctx1.borrow().get_padding_size(), 256);
        assert!(ctx1.borrow().is_fast_padding());

        assert_eq!(ctx2.borrow().get_padding_size(), 384);
        assert!(!ctx2.borrow().is_fast_padding());
    }

    #[test]
    fn test_clear_fragment_template_forward_for() {
        let ctx = create_context(true, 256);
        assert!(ctx.borrow().fragment_message_predict_size >= 115);
        let before_fragment_message_predict_size = ctx.borrow().fragment_message_predict_size;

        assert!(ctx.borrow().fragment_message_template.fragment.len() > 0);
        for f in ctx.borrow().fragment_message_template.fragment.iter() {
            assert!(f.forward_for.is_some());
        }

        ctx.try_borrow_mut()
            .unwrap()
            .clear_fragment_template_forward_for();

        assert!(ctx.borrow().fragment_message_template.fragment.len() > 0);
        for f in ctx.borrow().fragment_message_template.fragment.iter() {
            assert!(f.forward_for.is_none());
        }

        assert!(ctx.borrow().fragment_message_predict_size < before_fragment_message_predict_size);
        assert!(ctx.borrow().fragment_message_predict_size >= 26);
    }

    #[test]
    fn test_resize_padding_size() {
        let ctx = create_context(false, 0);
        assert!(ctx.borrow().frame_message_predict_size >= 129);
        assert!(ctx.borrow().fragment_message_predict_size >= 26);

        assert_eq!(ctx.borrow().get_padding_size(), 0);
        assert!(!ctx.borrow().is_fast_padding());

        let before_frame_message_predict_size = ctx.borrow().frame_message_predict_size;
        ctx.try_borrow_mut().unwrap().reset_padding_size(256);
        let after_frame_message_predict_size = ctx.borrow().frame_message_predict_size;
        assert!(after_frame_message_predict_size > before_frame_message_predict_size);

        assert_eq!(ctx.borrow().get_padding_size(), 256);
        assert!(ctx.borrow().is_fast_padding());

        // Restore
        ctx.try_borrow_mut().unwrap().reset_padding_size(0);
        assert!(ctx.borrow().frame_message_predict_size < after_frame_message_predict_size);
        assert_eq!(
            ctx.borrow().frame_message_predict_size,
            before_frame_message_predict_size
        );

        assert_eq!(ctx.borrow().get_padding_size(), 0);
        assert!(!ctx.borrow().is_fast_padding());
    }

    #[test]
    fn test_pack_empty_stream_message() {
        let packet_size_limit = 508;
        let start_offset = 15;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let messages: BTreeMap<i64, Box<StreamConnectionMessage>> = BTreeMap::new();

        let mut output: Vec<u8> = Vec::with_capacity(4096);

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 0);
        assert_eq!(pack_result.consume_size, 0);
        assert_eq!(pack_result.next_packet_fragment_offset, start_offset);
    }

    #[test]
    fn test_pack_unfinish_stream_message() {
        let packet_size_limit = 508;
        let start_offset = 15;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length = 256;
        let ctx = create_context(false, 32);
        let messages = create_stream_messages(&ctx, start_offset, &[data_length]);

        // predict length
        let (frame_head_reserve_size, fragment_head_reserve_size) = messages
            .first_key_value()
            .unwrap()
            .1
            .predict_frame_size(start_offset, timepoint, &None);

        let mut output_buffer = [0 as u8; 4096];
        let output_len =
            frame_head_reserve_size + fragment_head_reserve_size + data_length as usize - 50;
        let mut output: &mut [u8] = &mut output_buffer[0..output_len];

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 1);
        assert!(pack_result.consume_size > 0);
        assert!(pack_result.consume_size <= output_len);
        assert!(pack_result.next_packet_fragment_offset > start_offset);
        assert!(pack_result.unfinished_packet_fragment_data.is_none());

        // Decode
        let decoder = Decoder::new();

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output_buffer[..pack_result.consume_size],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data = unpack_result.unwrap();

        assert_eq!(pack_result.consume_size, unpack_data.1);

        // Check data
        {
            let origin_frame_message = messages.first_key_value().unwrap().1;

            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );

            assert_eq!(
                unpack_data.0.stream_offset,
                origin_frame_message.get_message_begin_offset()
            );

            assert_eq!(unpack_data.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data.0.packet.packet_flag,
                origin_frame_message.message.flags
            );

            assert_eq!(1, unpack_data.0.fragment.len());
            assert_eq!(
                unpack_data.0.stream_offset,
                unpack_data.0.fragment[0].offset
            );

            let ref unpack_frame_message = unpack_data.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message.packet_type,
                origin_frame_message.message.packet_type
            );

            assert_eq!(
                unpack_frame_message.fragment_flag,
                PacketFragmentFlagType::HasMore as i32
            );
            assert_eq!(
                unpack_frame_message.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            assert_eq!(
                unpack_frame_message.data,
                origin_frame_message
                    .message
                    .data
                    .slice(..unpack_frame_message.data.len())
            );
            assert!(unpack_frame_message.data.len() < origin_frame_message.message.data.len());

            assert_eq!(
                pack_result.next_packet_fragment_offset,
                start_offset + unpack_frame_message.data.len() as i64
            );
        }
    }

    #[test]
    fn test_pack_one_stream_message() {
        let packet_size_limit = 508;
        let start_offset = 15;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length = 256;
        let ctx = create_context(false, 32);
        let messages = create_stream_messages(&ctx, start_offset, &[data_length]);

        let mut output: Vec<u8> = Vec::with_capacity(4096);

        // predict length
        let (frame_head_reserve_size, fragment_head_reserve_size) = messages
            .first_key_value()
            .unwrap()
            .1
            .predict_frame_size(start_offset, timepoint, &None);

        {
            let mut clone_framgment_message = ctx.borrow().fragment_message_template.clone();
            clone_framgment_message.fragment[0].data =
                messages.first_key_value().unwrap().1.message.data.clone();
            let calc_fragment_size = clone_framgment_message.encoded_len();
            assert!(fragment_head_reserve_size + data_length as usize >= calc_fragment_size);
            assert!(fragment_head_reserve_size + data_length as usize <= calc_fragment_size + 1);

            let mut clone_frame_message = ctx.borrow().frame_message_template.clone();
            if let Some(b) = clone_frame_message.body.as_mut() {
                if let FrameMessageBody::Packet(ref mut p) = b {
                    p.content = clone_framgment_message.encode_to_vec().into();
                    assert_eq!(calc_fragment_size, p.content.len());
                }
            }
            let calc_frame_size = clone_frame_message.encoded_len();
            let variable_varint_addon = prost::encoding::encoded_len_varint(start_offset as u64)
                - 1
                + prost::encoding::encoded_len_varint(timepoint as u64)
                - 1;

            let encoder_reserve_length = ctx.borrow().encoder.get_reserve_header_length();

            assert!(
                frame_head_reserve_size + fragment_head_reserve_size + data_length as usize
                    >= calc_frame_size + variable_varint_addon + encoder_reserve_length
            );
            assert!(
                frame_head_reserve_size + fragment_head_reserve_size + data_length as usize
                    <= calc_frame_size + variable_varint_addon + encoder_reserve_length + 4
            );
        }

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 1);
        assert_eq!(pack_result.consume_size, output.len());
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert_eq!(
            pack_result.next_packet_fragment_offset,
            start_offset + data_length
        );

        assert!(
            frame_head_reserve_size + fragment_head_reserve_size + data_length as usize
                >= pack_result.consume_size
        );

        // Decode
        let decoder = Decoder::new();

        // Stream id not matched
        {
            let unpack_result =
                StreamPacketFragmentMessage::unpack_from_buffer(&decoder, &output[..], Some(375));
            assert!(unpack_result.is_err());
            if let Err(e) = unpack_result {
                if let ProtocolError::IoError(io_error) = e {
                    assert_eq!(io_error.kind(), io::ErrorKind::InvalidInput);
                } else {
                    assert!(false);
                }
            }
        }

        // Length not enough
        {
            let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
                &decoder,
                &output[..output.len() - 1],
                Some(ctx.borrow().stream_id),
            );
            assert!(unpack_result.is_err());
            if let Err(e) = unpack_result {
                if let ProtocolError::TruncatedHash = e {
                    assert!(true);
                } else {
                    assert!(false);
                }
            }
        }

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data = unpack_result.unwrap();
        assert_eq!(pack_result.consume_size, unpack_data.1);

        // Check data
        {
            let origin_frame_message = messages.first_key_value().unwrap().1;

            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_data
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source
            );
            assert_eq!(
                unpack_data
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id
            );

            assert_eq!(
                unpack_data.0.stream_offset,
                origin_frame_message.get_message_begin_offset()
            );
            assert_eq!(unpack_data.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data.0.packet.packet_flag,
                origin_frame_message.message.flags
            );

            assert_eq!(1, unpack_data.0.fragment.len());
            assert_eq!(
                unpack_data.0.stream_offset,
                unpack_data.0.fragment[0].offset
            );

            let ref unpack_frame_message = unpack_data.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message.packet_type,
                origin_frame_message.message.packet_type
            );
            assert_eq!(
                unpack_frame_message.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(unpack_frame_message.data, origin_frame_message.message.data);
        }
    }

    // pack middle message
    #[test]
    fn test_pack_middle_stream_message() {
        let packet_size_limit = 508;
        let start_offset = 15;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let already_sent_data_length = 153;
        let data_length = 256;
        let ctx = create_context(false, 32);
        let messages =
            create_stream_messages(&ctx, start_offset, &[already_sent_data_length, data_length]);

        let mut output: Vec<u8> = Vec::with_capacity(4096);

        // predict length
        let (frame_head_reserve_size, fragment_head_reserve_size) = messages
            .last_key_value()
            .unwrap()
            .1
            .predict_frame_size(start_offset, timepoint, &None);

        {
            let mut clone_framgment_message = ctx.borrow().fragment_message_template.clone();
            clone_framgment_message.fragment[0].data =
                messages.last_key_value().unwrap().1.message.data.clone();
            let calc_fragment_size = clone_framgment_message.encoded_len();
            assert!(fragment_head_reserve_size + data_length as usize >= calc_fragment_size);
            assert!(fragment_head_reserve_size + data_length as usize <= calc_fragment_size + 1);

            let mut clone_frame_message = ctx.borrow().frame_message_template.clone();
            if let Some(b) = clone_frame_message.body.as_mut() {
                if let FrameMessageBody::Packet(ref mut p) = b {
                    p.content = clone_framgment_message.encode_to_vec().into();
                    assert_eq!(calc_fragment_size, p.content.len());
                }
            }
            let calc_frame_size = clone_frame_message.encoded_len();
            let variable_varint_addon = prost::encoding::encoded_len_varint(start_offset as u64)
                - 1
                + prost::encoding::encoded_len_varint(timepoint as u64)
                - 1;

            let encoder_reserve_length = ctx.borrow().encoder.get_reserve_header_length();

            assert!(
                frame_head_reserve_size + fragment_head_reserve_size + data_length as usize
                    >= calc_frame_size + variable_varint_addon + encoder_reserve_length
            );
            assert!(
                frame_head_reserve_size + fragment_head_reserve_size + data_length as usize
                    <= calc_frame_size + variable_varint_addon + encoder_reserve_length + 4
            );
        }

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset + already_sent_data_length,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 1);
        assert_eq!(pack_result.consume_size, output.len());
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert_eq!(
            pack_result.next_packet_fragment_offset,
            start_offset + already_sent_data_length + data_length
        );

        assert!(
            frame_head_reserve_size + fragment_head_reserve_size + data_length as usize
                >= pack_result.consume_size
        );

        // Decode
        let decoder = Decoder::new();

        // Stream id not matched
        {
            let unpack_result =
                StreamPacketFragmentMessage::unpack_from_buffer(&decoder, &output[..], Some(375));
            assert!(unpack_result.is_err());
            if let Err(e) = unpack_result {
                if let ProtocolError::IoError(io_error) = e {
                    assert_eq!(io_error.kind(), io::ErrorKind::InvalidInput);
                } else {
                    assert!(false);
                }
            }
        }

        // Length not enough
        {
            let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
                &decoder,
                &output[..output.len() - 1],
                Some(ctx.borrow().stream_id),
            );
            assert!(unpack_result.is_err());
            if let Err(e) = unpack_result {
                if let ProtocolError::TruncatedHash = e {
                    assert!(true);
                } else {
                    assert!(false);
                }
            }
        }

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data = unpack_result.unwrap();
        assert_eq!(pack_result.consume_size, unpack_data.1);

        // Check data
        {
            let origin_frame_message = messages.last_key_value().unwrap().1;

            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_data
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source
            );
            assert_eq!(
                unpack_data
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id
            );

            assert_eq!(
                unpack_data.0.stream_offset,
                origin_frame_message.get_message_begin_offset()
            );
            assert_eq!(unpack_data.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data.0.packet.packet_flag,
                origin_frame_message.message.flags
            );

            assert_eq!(1, unpack_data.0.fragment.len());
            assert_eq!(
                unpack_data.0.stream_offset,
                unpack_data.0.fragment[0].offset
            );

            let ref unpack_frame_message = unpack_data.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message.packet_type,
                origin_frame_message.message.packet_type
            );
            assert_eq!(
                unpack_frame_message.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(unpack_frame_message.data, origin_frame_message.message.data);
        }
    }

    // Split into multiple frame
    #[test]
    fn test_pack_stream_message_into_multiple_fragments() {
        let start_offset = 15;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length = 256;
        let ctx = create_context(false, 32);
        let messages = create_stream_messages(&ctx, start_offset, &[data_length]);

        let mut output: Vec<u8> = Vec::with_capacity(4096);

        // predict length
        let (frame_head_reserve_size, fragment_head_reserve_size) = messages
            .first_key_value()
            .unwrap()
            .1
            .predict_frame_size(start_offset, timepoint, &None);

        let packet_size_limit =
            frame_head_reserve_size + fragment_head_reserve_size + data_length as usize - 20;

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 2);
        assert_eq!(pack_result.consume_size, output.len());
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert_eq!(
            pack_result.next_packet_fragment_offset,
            start_offset + data_length
        );

        assert!(
            2 * (frame_head_reserve_size + fragment_head_reserve_size) + data_length as usize
                >= pack_result.consume_size
        );

        // Decode
        let decoder = Decoder::new();

        // Length not enough
        {
            let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
                &decoder,
                &output[..output.len() - 1],
                Some(ctx.borrow().stream_id),
            );
            assert!(unpack_result.is_ok());
            let unpack_data = unpack_result.unwrap();
            assert!(pack_result.consume_size > unpack_data.1);
            assert_eq!(unpack_data.0.fragment.len(), 1);
        }

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_frame1 = unpack_result.unwrap();

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[unpack_frame1.1..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_frame2 = unpack_result.unwrap();

        assert_eq!(pack_result.consume_size, unpack_frame1.1 + unpack_frame2.1);

        // Check data
        {
            let origin_frame_message = messages.first_key_value().unwrap().1;

            assert_eq!(
                unpack_frame1.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_frame2.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_frame1.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_frame2.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_frame1
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source
            );
            assert_eq!(
                unpack_frame2
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source
            );
            assert_eq!(
                unpack_frame1
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id
            );
            assert_eq!(
                unpack_frame2
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id
            );

            assert_eq!(
                unpack_frame1.0.stream_offset,
                origin_frame_message.get_message_begin_offset()
            );
            assert_eq!(
                unpack_frame2.0.stream_offset,
                origin_frame_message.get_message_begin_offset()
                    + unpack_frame1.0.fragment[0].data.data.len() as i64
            );

            assert_eq!(unpack_frame1.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(unpack_frame2.0.packet.timepoint_microseconds, timepoint);

            assert_eq!(
                unpack_frame1.0.packet.packet_flag,
                origin_frame_message.message.flags
            );
            assert_eq!(
                unpack_frame2.0.packet.packet_flag,
                origin_frame_message.message.flags
            );

            assert_eq!(1, unpack_frame1.0.fragment.len());
            assert_eq!(1, unpack_frame2.0.fragment.len());
            assert_eq!(
                unpack_frame1.0.stream_offset,
                unpack_frame1.0.fragment[0].offset
            );
            assert_eq!(
                unpack_frame2.0.stream_offset,
                unpack_frame2.0.fragment[0].offset
            );

            let ref unpack_frame_message1 = unpack_frame1.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message1.packet_type,
                unpack_frame_message1.packet_type
            );
            assert_eq!(
                unpack_frame_message1.fragment_flag,
                PacketFragmentFlagType::HasMore as i32
            );
            assert_eq!(
                unpack_frame_message1.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            let ref unpack_frame_message2 = unpack_frame2.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message2.packet_type,
                unpack_frame_message2.packet_type
            );
            assert_eq!(
                unpack_frame_message2.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message2.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            assert_eq!(
                unpack_frame_message1.data.len() + unpack_frame_message2.data.len(),
                origin_frame_message.message.data.len()
            );
            assert_eq!(
                unpack_frame_message1.data,
                origin_frame_message
                    .message
                    .data
                    .slice(..unpack_frame_message1.data.len())
            );
            assert_eq!(
                unpack_frame_message2.data,
                origin_frame_message
                    .message
                    .data
                    .slice(unpack_frame_message1.data.len()..)
            );
        }
    }

    // Pack multiple stream message into multiple fragment in one frame
    #[test]
    fn test_pack_multiple_stream_message() {
        let packet_size_limit = 16384;
        let start_offset = 379;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length1 = 153;
        let data_length2 = 256;
        let ctx = create_context(false, 32);
        let messages = create_stream_messages(&ctx, start_offset, &[data_length1, data_length2]);

        let mut output: Vec<u8> = Vec::with_capacity(4096);

        // predict length
        let (frame_head_reserve_size, fragment_head_reserve_size) = messages
            .last_key_value()
            .unwrap()
            .1
            .predict_frame_size(start_offset, timepoint, &None);

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 1);
        assert_eq!(pack_result.consume_size, output.len());
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert_eq!(
            pack_result.next_packet_fragment_offset,
            start_offset + data_length1 + data_length2
        );

        assert!(
            frame_head_reserve_size
                + 2 * fragment_head_reserve_size
                + data_length1 as usize
                + data_length2 as usize
                >= pack_result.consume_size
        );

        // Decode
        let decoder = Decoder::new();

        // Length not enough
        {
            let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
                &decoder,
                &output[..output.len() - 1],
                Some(ctx.borrow().stream_id),
            );
            assert!(unpack_result.is_err());
            if let Err(e) = unpack_result {
                if let ProtocolError::TruncatedHash = e {
                    assert!(true);
                } else {
                    assert!(false);
                }
            }
        }

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data = unpack_result.unwrap();
        assert_eq!(pack_result.consume_size, unpack_data.1);

        // Check data
        {
            let origin_frame_message1 = messages.first_key_value().unwrap().1;
            let origin_frame_message2 = messages.last_key_value().unwrap().1;

            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_data
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_source
            );
            assert_eq!(
                unpack_data
                    .0
                    .packet
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .forward_for_connection_id
            );

            assert_eq!(
                unpack_data.0.stream_offset,
                origin_frame_message1.get_message_begin_offset()
            );
            assert_eq!(unpack_data.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data.0.packet.packet_flag,
                origin_frame_message1.message.flags
            );

            assert_eq!(2, unpack_data.0.fragment.len());
            assert_eq!(
                unpack_data.0.stream_offset,
                unpack_data.0.fragment[0].offset
            );
            assert_eq!(
                unpack_data.0.stream_offset + unpack_data.0.fragment[0].data.data.len() as i64,
                unpack_data.0.fragment[1].offset
            );

            let ref unpack_frame_message1 = unpack_data.0.fragment[0].data;
            let ref unpack_frame_message2 = unpack_data.0.fragment[1].data;
            assert_eq!(
                unpack_frame_message1.packet_type,
                origin_frame_message1.message.packet_type
            );
            assert_eq!(
                unpack_frame_message2.packet_type,
                origin_frame_message2.message.packet_type
            );
            assert_eq!(
                unpack_frame_message1.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message2.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message1.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(
                unpack_frame_message2.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            assert_eq!(
                unpack_frame_message1.data,
                origin_frame_message1.message.data
            );
            assert_eq!(
                unpack_frame_message2.data,
                origin_frame_message2.message.data
            );
        }
    }

    // Split into multiple frame and with reset flag
    #[test]
    fn test_pack_multiple_stream_message_with_reset_flag() {
        let packet_size_limit = 16384;
        let start_offset = 379;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length1 = 153;
        let data_length2 = 256;
        let ctx = create_context(false, 32);
        let mut messages =
            create_stream_messages(&ctx, start_offset, &[data_length1, data_length2]);
        messages.last_entry().unwrap().get_mut().message.flags = PacketFlagType::ResetOffset as i32;
        assert!(messages
            .last_entry()
            .unwrap()
            .get()
            .message
            .has_packet_flag_reset_offset());

        let mut output: Vec<u8> = Vec::with_capacity(4096);

        // predict length
        let (frame_head_reserve_size, fragment_head_reserve_size) = messages
            .last_key_value()
            .unwrap()
            .1
            .predict_frame_size(start_offset, timepoint, &None);

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 2);
        assert_eq!(pack_result.consume_size, output.len());
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert_eq!(
            pack_result.next_packet_fragment_offset,
            start_offset + data_length1 + data_length2
        );

        assert!(
            2 * (frame_head_reserve_size + fragment_head_reserve_size)
                + data_length1 as usize
                + data_length2 as usize
                >= pack_result.consume_size
        );

        // Decode
        let decoder = Decoder::new();

        // Length not enough
        {
            let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
                &decoder,
                &output[..output.len() - 1],
                Some(ctx.borrow().stream_id),
            );
            assert!(unpack_result.is_ok());
            let unpack_data = unpack_result.unwrap();
            assert!(pack_result.consume_size > unpack_data.1);
        }

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data1 = unpack_result.unwrap();

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[unpack_data1.1..],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data2 = unpack_result.unwrap();

        assert_eq!(pack_result.consume_size, unpack_data1.1 + unpack_data2.1);

        // Check data
        {
            let origin_frame_message1 = messages.first_key_value().unwrap().1;
            let origin_frame_message2 = messages.last_key_value().unwrap().1;

            assert_eq!(
                unpack_data1.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data2.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data1.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_data2.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );

            assert_eq!(
                unpack_data1.0.stream_offset,
                origin_frame_message1.get_message_begin_offset()
            );
            assert_eq!(
                unpack_data2.0.stream_offset,
                origin_frame_message2.get_message_begin_offset()
            );

            assert_eq!(unpack_data1.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(unpack_data2.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data1.0.packet.packet_flag,
                origin_frame_message1.message.flags
            );
            assert_eq!(
                unpack_data2.0.packet.packet_flag,
                origin_frame_message2.message.flags
            );
            assert_eq!(
                unpack_data2.0.packet.packet_flag,
                PacketFlagType::ResetOffset as i32
            );
            assert!(unpack_data2.0.packet.has_packet_flag_reset_offset());

            assert_eq!(1, unpack_data1.0.fragment.len());
            assert_eq!(1, unpack_data2.0.fragment.len());
            assert_eq!(
                unpack_data1.0.stream_offset,
                unpack_data1.0.fragment[0].offset
            );
            assert_eq!(
                unpack_data2.0.stream_offset,
                unpack_data2.0.fragment[0].offset
            );

            let ref unpack_frame_message1 = unpack_data1.0.fragment[0].data;
            let ref unpack_frame_message2 = unpack_data2.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message1.packet_type,
                origin_frame_message1.message.packet_type
            );
            assert_eq!(
                unpack_frame_message2.packet_type,
                origin_frame_message2.message.packet_type
            );
            assert_eq!(
                unpack_frame_message1.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message2.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message1.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(
                unpack_frame_message2.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            assert_eq!(
                unpack_frame_message1.data,
                origin_frame_message1.message.data
            );
            assert_eq!(
                unpack_frame_message2.data,
                origin_frame_message2.message.data
            );
        }
    }

    // Partly pack multiple frame message
    #[test]
    fn test_partly_pack_multiple_stream_message() {
        let packet_size_limit = 3072;
        let start_offset = 379;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length1 = 2048;
        let data_length2 = 1987;
        let ctx = create_context(false, 32);
        let messages = create_stream_messages(&ctx, start_offset, &[data_length1, data_length2]);

        let mut output: Vec<u8> = Vec::with_capacity(8192);

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output,
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 2);
        assert_eq!(pack_result.consume_size, output.len());
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert_eq!(
            pack_result.next_packet_fragment_offset,
            start_offset + data_length1 + data_length2
        );

        // Decode
        let decoder = Decoder::new();

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..pack_result.consume_size],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data1 = unpack_result.unwrap();

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[unpack_data1.1..pack_result.consume_size],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data2 = unpack_result.unwrap();

        assert_eq!(pack_result.consume_size, unpack_data1.1 + unpack_data2.1);

        // Check data
        {
            let origin_frame_message1 = messages.first_key_value().unwrap().1;
            let origin_frame_message2 = messages.last_key_value().unwrap().1;

            assert_eq!(
                unpack_data1.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data2.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data1.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );
            assert_eq!(
                unpack_data2.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );

            assert_eq!(
                unpack_data1.0.stream_offset,
                origin_frame_message1.get_message_begin_offset()
            );

            assert_eq!(unpack_data1.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(unpack_data2.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data1.0.packet.packet_flag,
                origin_frame_message1.message.flags
            );
            assert_eq!(
                unpack_data2.0.packet.packet_flag,
                origin_frame_message2.message.flags
            );

            assert_eq!(2, unpack_data1.0.fragment.len());
            assert_eq!(1, unpack_data2.0.fragment.len());
            assert_eq!(
                unpack_data1.0.stream_offset,
                unpack_data1.0.fragment[0].offset
            );
            assert_eq!(
                unpack_data2.0.stream_offset,
                unpack_data2.0.fragment[0].offset
            );

            let ref unpack_frame_message1 = unpack_data1.0.fragment[0].data;
            let ref unpack_frame_message21 = unpack_data1.0.fragment[1].data;
            let ref unpack_frame_message22 = unpack_data2.0.fragment[0].data;
            assert_eq!(
                unpack_frame_message1.packet_type,
                origin_frame_message1.message.packet_type
            );
            assert_eq!(
                unpack_frame_message21.packet_type,
                origin_frame_message2.message.packet_type
            );
            assert_eq!(
                unpack_frame_message22.packet_type,
                origin_frame_message2.message.packet_type
            );
            assert_eq!(
                unpack_frame_message1.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message21.fragment_flag,
                PacketFragmentFlagType::HasMore as i32
            );
            assert_eq!(
                unpack_frame_message22.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message1.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(
                unpack_frame_message21.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(
                unpack_frame_message22.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            assert_eq!(
                unpack_frame_message1.data,
                origin_frame_message1.message.data
            );
            assert_eq!(
                unpack_frame_message21.data,
                origin_frame_message2
                    .message
                    .data
                    .slice(..unpack_frame_message21.data.len())
            );
            assert_eq!(
                unpack_frame_message22.data,
                origin_frame_message2
                    .message
                    .data
                    .slice(unpack_frame_message21.data.len()..)
            );
        }
    }

    // Partly pack partly frame message
    #[test]
    fn test_partly_pack_partly_stream_message() {
        let packet_size_limit = 16384;
        let start_offset = 379;
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let data_length1 = 2048;
        let data_length2 = 1987;
        let ctx = create_context(false, 32);
        let messages = create_stream_messages(&ctx, start_offset, &[data_length1, data_length2]);

        let mut output: [u8; 3072] = [0 as u8; 3072];

        let pack_result = StreamConnectionMessage::pack(
            &messages,
            &mut output[..],
            start_offset,
            packet_size_limit,
            timepoint,
        );

        assert!(pack_result.is_ok());

        let pack_result = pack_result.unwrap();
        assert_eq!(pack_result.frame_count, 1);
        assert!(pack_result.unfinished_packet_fragment_data.is_none());
        assert!(pack_result.next_packet_fragment_offset > start_offset + data_length1);
        assert!(
            pack_result.next_packet_fragment_offset < start_offset + data_length1 + data_length2
        );

        // Decode
        let decoder = Decoder::new();

        let unpack_result = StreamPacketFragmentMessage::unpack_from_buffer(
            &decoder,
            &output[..pack_result.consume_size],
            Some(ctx.borrow().stream_id),
        );
        assert!(unpack_result.is_ok());
        let unpack_data1 = unpack_result.unwrap();

        assert_eq!(pack_result.consume_size, unpack_data1.1);

        // Check data
        {
            let origin_frame_message1 = messages.first_key_value().unwrap().1;
            let origin_frame_message2 = messages.last_key_value().unwrap().1;

            assert_eq!(
                unpack_data1.0.packet.head.as_ref().unwrap().source,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .source
            );
            assert_eq!(
                unpack_data1.0.packet.head.as_ref().unwrap().destination,
                ctx.borrow()
                    .frame_message_template
                    .head
                    .as_ref()
                    .unwrap()
                    .destination
            );

            assert_eq!(
                unpack_data1.0.stream_offset,
                origin_frame_message1.get_message_begin_offset()
            );

            assert_eq!(unpack_data1.0.packet.timepoint_microseconds, timepoint);
            assert_eq!(
                unpack_data1.0.packet.packet_flag,
                origin_frame_message1.message.flags
            );

            assert_eq!(2, unpack_data1.0.fragment.len());
            assert_eq!(
                unpack_data1.0.stream_offset,
                unpack_data1.0.fragment[0].offset
            );

            let ref unpack_frame_message1 = unpack_data1.0.fragment[0].data;
            let ref unpack_frame_message21 = unpack_data1.0.fragment[1].data;
            assert_eq!(
                unpack_frame_message1.packet_type,
                origin_frame_message1.message.packet_type
            );
            assert_eq!(
                unpack_frame_message21.packet_type,
                origin_frame_message2.message.packet_type
            );
            assert_eq!(
                unpack_frame_message1.fragment_flag,
                PacketFragmentFlagType::None as i32
            );
            assert_eq!(
                unpack_frame_message21.fragment_flag,
                PacketFragmentFlagType::HasMore as i32
            );
            assert_eq!(
                unpack_frame_message1.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );
            assert_eq!(
                unpack_frame_message21.options,
                ctx.borrow().fragment_message_template.fragment[0].options
            );

            assert_eq!(
                unpack_frame_message1.data,
                origin_frame_message1.message.data
            );
            assert_eq!(
                unpack_frame_message21.data,
                origin_frame_message2
                    .message
                    .data
                    .slice(..unpack_frame_message21.data.len())
            );
            assert!(unpack_frame_message21.data.len() < origin_frame_message2.message.data.len());
        }
    }
}
