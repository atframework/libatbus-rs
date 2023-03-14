// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::BTreeMap;
use std::ops::Bound::Included;

use libatbus_protocol::{
    BoxedFrameMessage, BoxedStreamMessage, CloseReasonMessage, ForwardMessage, FrameMessageBody,
    PacketFlagType, PacketFragmentFlagType, PacketMessage, PacketOptionMessage,
    StreamFramePacketMessage,
};

pub struct Stream {
    stream_id: i64,

    // Send window, dynamic length
    send_frames: BTreeMap<i64, BoxedStreamMessage>,
    send_frames_acknowledge_offset: usize,

    // Receive window, dynamic length
    received_frames: BTreeMap<i64, StreamFramePacketMessage>,

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
            Some(last_packet) => last_packet.0 + (last_packet.1.get_packet_length() as i64),
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

    pub fn receive(&mut self, frame: BoxedFrameMessage) {
        let frame_body = match &frame.body {
            Some(b) => b,
            _ => {
                return;
            }
        };
        let packet_body = match &frame_body {
            FrameMessageBody::Packet(p) => p,
            _ => {
                return;
            }
        };

        if packet_body.stream_id != self.stream_id {
            return;
        }
        let this_frame_message_start = packet_body.stream_offset;
        let packet_flag = packet_body.flags;

        // Drop unfinished packet when got ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET.
        if packet_flag & (PacketFlagType::ResetOffset as i32) != 0 {
            self.reset_acknowledge_offset(this_frame_message_start);
        }

        // TODO: 处理Handshake阶段

        // Maybe a empty package with ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET, to just skip some fragments.
        if packet_body.content.is_empty() {
            return;
        }

        let frame_message = if let Ok(p) = StreamFramePacketMessage::with(frame) {
            p
        } else {
            return;
        };

        if frame_message.get_packet_length() == 0 {
            return;
        }

        let this_frame_message_end =
            this_frame_message_start + frame_message.get_packet_length() as i64;

        // if received_frames already contains this frame, just ingnore this one.
        {
            let check_contained = self
                .received_frames
                .range((Included(0), Included(this_frame_message_start)));
            match check_contained.last() {
                Some(checked) => {
                    if *checked.0 <= this_frame_message_start
                        && checked.0 + (checked.1.get_packet_length() as i64)
                            >= this_frame_message_end
                    {
                        return;
                    }
                }
                None => {}
            }
        }

        // if this frame contains next frame, remove next one.
        let mut pending_to_drop = vec![];
        {
            let check_contained = self.received_frames.range(this_frame_message_start..);
            for checked in check_contained {
                if checked.0 + (checked.1.get_packet_length() as i64) <= this_frame_message_end {
                    pending_to_drop.push(*checked.0);
                }
            }
        }
        for drop_key in pending_to_drop {
            self.received_frames.remove(&drop_key);
        }

        let _ = self
            .received_frames
            .insert(this_frame_message_start, frame_message);

        // check and reset received_packet_finished
        if this_frame_message_start <= self.received_acknowledge_offset
            && this_frame_message_end > self.received_acknowledge_offset
        {
            self.move_received_acknowledge_offset();
        }
    }

    fn move_received_acknowledge_offset(&mut self) {
        let check_contained = self
            .received_frames
            .range(self.received_acknowledge_offset..);
        for checked in check_contained {
            let buffer_start = *checked.0;
            let buffer_end = buffer_start + (checked.1.get_packet_length() as i64);
            if buffer_start > self.received_acknowledge_offset {
                break;
            }

            if buffer_start <= self.received_acknowledge_offset
                && buffer_end > self.received_acknowledge_offset
            {
                self.received_acknowledge_offset = buffer_end;

                if !self.received_packet_finished {
                    let mut has_finished_packet = false;
                    for fragment in &checked.1.packet {
                        if (fragment.fragment_flag & PacketFragmentFlagType::HasMore as i32) != 0 {
                            has_finished_packet = true;
                            break;
                        }
                    }
                    if has_finished_packet {
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
            let buffer_start = *checked.0;
            let buffer_end = buffer_start + (checked.1.get_packet_length() as i64);
            if buffer_end > offset {
                break;
            }

            self.received_frames.remove(&buffer_start);
        }

        // Remove all frames contains offset and select the largest one
        let mut strip_frame = None;
        while !self.received_frames.is_empty() {
            let checked = self.received_frames.first_key_value().unwrap();
            let buffer_start = *checked.0;
            if buffer_start >= offset {
                break;
            }

            if strip_frame.is_none() {
                strip_frame = Some(checked.1.sub_frame((offset - buffer_start) as usize));
            } else {
                let buffer_end = buffer_start + (checked.1.get_packet_length() as i64);
                if buffer_end > offset + strip_frame.as_ref().unwrap().get_packet_length() as i64 {
                    strip_frame = Some(checked.1.sub_frame((offset - buffer_start) as usize));
                }
            }

            self.received_frames.remove(&buffer_start);
        }

        // Insert striped frame.
        match strip_frame {
            Some(f) => {
                if f.get_packet_length() > 0 {
                    self.received_frames.insert(offset, f);
                }
            }
            None => {}
        }
    }
}
