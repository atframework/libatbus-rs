// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::BTreeMap;
use std::ops::Bound::Included;

use libatbus_protocol::{
    error::ProtocolResult, BoxedFrameMessage, BoxedStreamMessage, PacketFlagType,
    PacketFragmentFlagType, StreamPacketFragmentMessage,
};

pub struct StreamReceiveResult {
    pub packet_begin_offset: i64,
    pub packet_end_offset: i64,
    pub packet_flag: i32,
    pub timepoint_microseconds: i64,
}

pub struct Stream {
    stream_id: i64,

    // Send window, dynamic length
    send_frames: BTreeMap<i64, BoxedStreamMessage>,
    send_frames_acknowledge_offset: usize,

    // Receive window, dynamic length
    received_frames: BTreeMap<i64, StreamPacketFragmentMessage>,

    // All datas before received_acknowledge_offset are all received.
    received_acknowledge_offset: i64,
    // Cached flag to find out if a packet is finished quickly.
    received_packet_finished: bool,
}

impl Stream {
    pub fn get_acknowledge_offset(&self) -> i64 {
        self.received_acknowledge_offset
    }

    pub fn get_receive_max_offset(&self) -> i64 {
        match self.received_frames.last_key_value() {
            Some(last_packet) => last_packet.0 + (last_packet.1.get_message_length() as i64),
            None => self.received_acknowledge_offset,
        }
    }

    pub fn acknowledge_send_buffer(&mut self, offset: i64) {
        if offset > self.send_frames_acknowledge_offset as i64 {
            self.send_frames_acknowledge_offset = offset as usize;
        }

        loop {
            if self.send_frames.is_empty() {
                break;
            }

            let first = self.send_frames.first_key_value().unwrap();
            if self.send_frames_acknowledge_offset
                < (*first.0 as usize) + first.1.as_ref().data.len()
            {
                break;
            }

            self.send_frames.pop_first();
        }
    }

    pub fn receive(&mut self, frame: BoxedFrameMessage) -> ProtocolResult<StreamReceiveResult> {
        let frame_messages = StreamPacketFragmentMessage::unpack(frame, Some(self.stream_id))?;

        // Drop unfinished packet when got ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET.
        if frame_messages.stream_offset >= 0
            && frame_messages.packet_flag & (PacketFlagType::ResetOffset as i32) != 0
        {
            self.reset_acknowledge_offset(frame_messages.stream_offset);
        }

        let this_frame_message_start = frame_messages.stream_offset;
        let mut this_frame_message_end = this_frame_message_start;
        for fragment in frame_messages.fragment {
            // if received_frames already contains this frame, just ingnore this one.
            {
                let check_contained = self
                    .received_frames
                    .range((Included(0), Included(fragment.get_message_begin_offset())));
                match check_contained.last() {
                    Some(checked) => {
                        if checked.1.get_message_begin_offset()
                            <= fragment.get_message_begin_offset()
                            && checked.1.get_message_end_offset()
                                >= fragment.get_message_end_offset()
                        {
                            continue;
                        }
                    }
                    None => {}
                }
            }

            // if this frame contains next frame, remove next one.
            let mut pending_to_drop = vec![];
            {
                let check_contained = self
                    .received_frames
                    .range(fragment.get_message_begin_offset()..);
                for checked in check_contained {
                    if checked.1.get_message_end_offset() <= fragment.get_message_end_offset() {
                        pending_to_drop.push(*checked.0);
                    }
                }
            }
            for drop_key in pending_to_drop {
                self.received_frames.remove(&drop_key);
            }

            this_frame_message_end = fragment.get_message_end_offset();

            let _ = self
                .received_frames
                .insert(fragment.get_message_begin_offset(), fragment);
        }

        // check and reset received_packet_finished
        if this_frame_message_start <= self.received_acknowledge_offset
            && this_frame_message_end > self.received_acknowledge_offset
        {
            self.move_received_acknowledge_offset();
        }

        // TODO: 提取内部指令数据包
        // TODO: 处理Handshake包，即便在正常数据流过程中也可能夹杂Handshake包，用于换密钥。

        Ok(StreamReceiveResult {
            packet_begin_offset: this_frame_message_start,
            packet_end_offset: this_frame_message_end,
            packet_flag: frame_messages.packet_flag,
            timepoint_microseconds: frame_messages.timepoint_microseconds,
        })
    }

    fn move_received_acknowledge_offset(&mut self) {
        let check_contained = self
            .received_frames
            .range(self.received_acknowledge_offset..);
        for checked in check_contained {
            if checked.1.get_message_begin_offset() > self.received_acknowledge_offset {
                break;
            }

            if checked.1.get_message_begin_offset() <= self.received_acknowledge_offset
                && checked.1.get_message_end_offset() > self.received_acknowledge_offset
            {
                self.received_acknowledge_offset = checked.1.get_message_end_offset();

                if !self.received_packet_finished {
                    if checked
                        .1
                        .check_fragment_flag(PacketFragmentFlagType::HasMore)
                    {
                        self.received_packet_finished = true;
                    }
                }
            }
        }
    }

    fn reset_acknowledge_offset(&mut self, offset: i64) {
        if self.received_acknowledge_offset < offset {
            self.received_acknowledge_offset = offset;
        }

        // Remove all frames less than offset
        while !self.received_frames.is_empty() {
            let checked = self.received_frames.first_key_value().unwrap();
            if checked.1.get_message_end_offset() > offset {
                break;
            }

            self.received_frames.pop_first();
        }

        // Remove all frames contains offset and select the largest one
        let mut strip_frame = None;
        while !self.received_frames.is_empty() {
            let checked = self.received_frames.first_key_value().unwrap();
            if checked.1.get_message_begin_offset() >= offset {
                break;
            }

            if strip_frame.is_none() {
                strip_frame = checked
                    .1
                    .sub_frame((offset - checked.1.get_message_begin_offset()) as usize);
            } else {
                if checked.1.get_message_end_offset()
                    > strip_frame.as_ref().unwrap().get_message_end_offset()
                {
                    strip_frame = checked
                        .1
                        .sub_frame((offset - checked.1.get_message_begin_offset()) as usize);
                }
            }

            self.received_frames.pop_first();
        }

        // Insert striped frame.
        match strip_frame {
            Some(f) => {
                if !f.is_empty() {
                    self.received_frames.insert(f.get_message_begin_offset(), f);
                }
            }
            None => {}
        }
    }
}
