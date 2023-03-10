// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::BTreeMap;

use libatbus_protocol::BoxedFrameMessage;

pub struct Stream {
  // Send buffer, dynamic length
  send_buffer: Vec<u8>,
  // Start offset of send_buffer[0]
  send_buffer_start_offset: usize,
  // Acknowledged offet, buffer can be reused between [send_buffer_start_offset, send_buffer_acknowledge_offset)
  send_buffer_acknowledge_offset: usize,
  received_frames: BTreeMap<i64, BoxedFrameMessage>,
  // Sum of length in received_frames
  received_size_cache: i64,
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
    if offset > self.send_buffer_acknowledge_offset as i64 {
      self.send_buffer_acknowledge_offset = offset as usize;
    }
  }

  pub fn receive(_frame: &BoxedFrameMessage) {
    // TODO: if received_frames already contains this frame, just ingnore this one.
    // TODO: if this frame contains next frame, remove next one.
  }
}
