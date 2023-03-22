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

pub struct StreamMessage {
    pub packet_type: i32,
    pub stream_offset: i64,
    pub data: ::prost::bytes::Bytes,

    /// @see atbus.protocol.ATBUS_PACKET_FLAG_TYPE
    pub flags: i32,

    /// Only has value when has ATBUS_PACKET_FLAG_TYPE_FINISH_STREAM or ATBUS_PACKET_FLAG_TYPE_FINISH_CONNECTION
    pub close_reason: Option<Box<CloseReasonMessage>>,

    /// Connection context
    pub connection_context: Rc<RefCell<StreamConnectionContext>>,
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
            stream_id: stream_id,
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
            ret.frame_message_template.encoded_len() + ret.encoder.get_reserve_header_length() + 20;

        // Reserve varint for fragment and data field.
        ret.fragment_message_predict_size = ret.fragment_message_template.encoded_len() + 20;

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
        self.frame_message_predict_size = self.frame_message_template.encoded_len()
            + self.encoder.get_reserve_header_length()
            + 20;

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
                        fragment_data.data.resize(padding_ceil, 0);
                        padding_size = (padding_ceil - fragment_data.data.len()) as i32;
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
        stream_message: &StreamMessage,
        len: usize,
        force_packet_reset: bool,
    ) -> ProtocolResult<()> {
        if packer.next_packet_fragment_offset < stream_message.get_message_begin_offset()
            || packer.next_packet_fragment_offset + (len as i64)
                > stream_message.get_message_end_offset()
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
        fragment.packet_type = stream_message.packet_type;

        let start_idx = (packer.next_packet_fragment_offset
            - stream_message.get_message_begin_offset()) as usize;
        fragment.data = stream_message.data.slice(start_idx..(start_idx + len));
        fragment.fragment_flag =
            stream_message.get_fragment_fragment_flag(packer.next_packet_fragment_offset, len);
        fragment.close_reason = if let Some(cr) = stream_message.close_reason.as_ref() {
            if packer.next_packet_fragment_offset + (len as i64)
                >= stream_message.get_message_end_offset()
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
                packet_flags: stream_message
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
            let padding_mod = if let Some(padding_bits) = self.packet_padding_bits.as_ref() {
                len & ((1 << padding_bits) - 1)
            } else {
                len % self.packet_padding_size
            };

            if padding_mod == 0 {
                len
            } else {
                len + self.packet_padding_size - padding_mod
            }
        }
    }

    fn padding_len_floor(&self, len: usize) -> usize {
        if self.packet_padding_size <= 1 {
            len
        } else {
            if let Some(padding_bits) = self.packet_padding_bits.as_ref() {
                len & ((1 << padding_bits) - 1)
            } else {
                len - len % self.packet_padding_size
            }
        }
    }
}

impl StreamMessage {
    pub fn predict_frame_size(&self, stream_offset: i64, timepoint_microseconds: i64) -> usize {
        self.connection_context.borrow().frame_message_predict_size
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

    pub fn predict_fragment_size(&self, close_reason: &Option<Box<CloseReasonMessage>>) -> usize {
        if let Some(cr) = close_reason {
            let encoded_len_of_cr = cr.encoded_len();
            // Key tag use last 3 bits of first byte as wire type.
            self.connection_context.borrow().fragment_message_predict_size
                + prost::length_delimiter_len(7 * 8) // 7 is the tag of close_reason
                + prost::length_delimiter_len(encoded_len_of_cr)
        } else {
            self.connection_context
                .borrow()
                .fragment_message_predict_size
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

    pub fn get_fragment_packet_flag(&self, start_stream_offset: i64, len: usize) -> i32 {
        if start_stream_offset <= self.get_message_begin_offset()
            && (start_stream_offset + len as i64) >= self.get_message_end_offset()
        {
            self.flags
        } else {
            let mut ret = self.flags;
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
            if ret.next_packet_fragment_offset >= *last_kv.0 + last_kv.1.data.len() as i64 {
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

        let frame_head_reserve_size =
            self.predict_frame_size(packer.next_packet_fragment_offset, timepoint_microseconds);
        let fragment_head_reserve_size = self.predict_fragment_size(&self.close_reason);

        if packet_size_limit < frame_head_reserve_size + fragment_head_reserve_size {
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
                if unfinished_fragment_len_with_headers >= packet_size_limit
                    || fragment_max_data_len <= upf.data.len()
                    || ((self.flags & PacketFlagType::ResetOffset as i32) != 0
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
                        + fragment_max_data_len
                        + self.padding_len_ceil(upf.data.len())
                {
                    return Ok((consume_size, next_output));
                }
                // After padding
                let left_output_data_len = self.padding_len_floor(
                    next_output.remaining_mut()
                        - fragment_head_reserve_size
                        - fragment_max_data_len,
                );
                if left_output_data_len <= upf.data.len() {
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
                    if upf.packet_flags
                        != self.get_fragment_packet_flag(
                            packer.next_packet_fragment_offset,
                            current_fragment_available_data_len,
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
                            current_fragment_available_data_len,
                            force_packet_reset,
                        )?;
                }
            } else {
                // Full and exit
                if next_output.remaining_mut() <= fragment_head_reserve_size + fragment_max_data_len
                {
                    return Ok((consume_size, next_output));
                }

                // After padding
                let left_output_data_len = self.padding_len_floor(
                    next_output.remaining_mut()
                        - fragment_head_reserve_size
                        - fragment_max_data_len,
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
    pub fn new(offset: i64, data: PacketFragmentMessage) -> Self {
        StreamPacketFragmentMessage { offset, data }
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
