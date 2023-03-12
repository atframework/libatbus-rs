// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::BTreeMap;
use std::collections::HashMap;

use libatbus_protocol::{
    BoxedFrameMessage, BoxedStreamMessage, CloseReasonMessage, ForwardMessage, PacketOptionMessage,
};

pub struct Stream {
    // Send window, dynamic length
    send_frames: BTreeMap<i64, BoxedStreamMessage>,
    send_frames_acknowledge_offset: usize,

    // Receive window, dynamic length
    received_frames: BTreeMap<i64, BoxedFrameMessage>,
    // All datas before received_acknowledge_offset are all received.
    received_acknowledge_offset: i64,
    // Cached flag to find out if a packet is finished quickly.
    received_packet_finished: bool,
}

impl Stream {
    pub fn get_acknowledge_offset(&self) -> i64 {
        self.received_acknowledge_offset
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

    pub fn receive(_frame: &BoxedFrameMessage) {
        // TODO: if received_frames already contains this frame, just ingnore this one.
        // TODO: if this frame contains next frame, remove next one.
        // TODO: drop unfinished packet when got ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET.
    }
}
