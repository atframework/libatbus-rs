// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::BTreeMap;
use std::collections::LinkedList;
use std::ops::Bound::Included;

use libatbus_protocol::{
    error::ProtocolResult, BoxedStreamMessage, PacketFlagType, PacketFragmentFlagType,
    StreamConnectionContext, StreamConnectionMessage, StreamMessage, StreamPacketFragmentMessage,
    StreamPacketFragmentUnpack,
};

use crate::bytes;

pub struct StreamPushResult {
    pub packet_begin_offset: i64,
    pub packet_end_offset: i64,
}

pub struct StreamReadResult {
    pub message: StreamMessage,
    pub fragment_count: usize,
    pub first_timepoint_microseconds: i64,
    pub last_timepoint_microseconds: i64,
}

pub type BoxedStreamReadResult = Box<StreamReadResult>;

struct StreamConnection {
    context: StreamConnectionContext,
    sent_offset: i64,
}

pub struct Stream {
    stream_id: i64,

    // Send window, dynamic length
    send_messages: BTreeMap<i64, Box<StreamConnectionMessage>>,
    send_acknowledge_offset: i64,

    // Receive window, dynamic length
    received_fragments: BTreeMap<i64, StreamPacketFragmentMessage>,
    // Received message, pending to be read by caller
    received_messages: LinkedList<BoxedStreamReadResult>,
    received_message_total_length: usize,

    // All datas before received_acknowledge_offset are all received.
    received_acknowledge_offset: i64,
}

impl Stream {
    pub fn new(stream_id: i64) -> Self {
        Stream {
            stream_id,
            send_messages: BTreeMap::new(),
            send_acknowledge_offset: 0,
            received_fragments: BTreeMap::new(),
            received_messages: LinkedList::new(),
            received_message_total_length: 0,
            received_acknowledge_offset: 0,
        }
    }

    #[inline]
    pub fn get_stream_id(&self) -> i64 {
        self.stream_id
    }

    pub fn get_acknowledge_offset(&self) -> i64 {
        self.received_acknowledge_offset
    }

    pub fn get_send_start_offset(&self) -> i64 {
        if let Some(x) = self.send_messages.last_key_value() {
            x.1.get_message_end_offset()
        } else {
            self.received_acknowledge_offset
        }
    }

    pub fn get_receive_max_offset(&self) -> i64 {
        match self.received_fragments.last_key_value() {
            Some(last_packet) => last_packet.0 + (last_packet.1.get_message_length() as i64),
            None => self.received_acknowledge_offset,
        }
    }

    pub fn send_message(&mut self, mut message: BoxedStreamMessage) -> ProtocolResult<()> {
        message.stream_offset = self.get_send_start_offset();

        self.send_messages.insert(
            message.stream_offset,
            StreamConnectionMessage::new(message).into(),
        );

        // TODO Active all connections to send data.
        Ok(())
    }

    pub fn acknowledge_send_offset(&mut self, offset: i64) {
        if offset > self.send_acknowledge_offset {
            self.send_acknowledge_offset = offset;
        }

        loop {
            if self.send_messages.is_empty() {
                break;
            }

            let first = self.send_messages.first_key_value().unwrap();
            if self.send_acknowledge_offset < first.1.get_message_end_offset() {
                break;
            }

            self.send_messages.pop_first();
        }
    }

    ///
    /// Receive and push fragment into this stream.
    ///
    pub fn receive_push(
        &mut self,
        frame_messages: StreamPacketFragmentUnpack,
    ) -> ProtocolResult<StreamPushResult> {
        // Drop unfinished packet when got ATBUS_PACKET_FLAG_TYPE_RESET_OFFSET.
        if frame_messages.stream_offset >= 0
            && frame_messages.packet.packet_flag & (PacketFlagType::ResetOffset as i32) != 0
        {
            self.reset_acknowledge_offset(frame_messages.stream_offset);
        }

        let this_frame_message_start = frame_messages.stream_offset;
        let mut this_frame_message_end = this_frame_message_start;
        for fragment in frame_messages.fragment {
            // if received_fragments already contains this frame, just ingnore this one.
            {
                let check_contained = self
                    .received_fragments
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
                    .received_fragments
                    .range(fragment.get_message_begin_offset()..);
                for checked in check_contained {
                    if checked.1.get_message_end_offset() <= fragment.get_message_end_offset() {
                        pending_to_drop.push(*checked.0);
                    }
                }
            }
            for drop_key in pending_to_drop {
                self.received_fragments.remove(&drop_key);
            }

            this_frame_message_end = fragment.get_message_end_offset();

            let _ = self
                .received_fragments
                .insert(fragment.get_message_begin_offset(), fragment);
        }

        // check and reset received_acknowledge_offset
        if this_frame_message_start <= self.received_acknowledge_offset
            && this_frame_message_end > self.received_acknowledge_offset
        {
            self.move_received_acknowledge_offset(this_frame_message_start);
        }

        // TODO: 提取内部指令数据包
        // TODO: 处理Handshake包，即便在正常数据流过程中也可能夹杂Handshake包，用于换密钥。

        Ok(StreamPushResult {
            packet_begin_offset: this_frame_message_start,
            packet_end_offset: this_frame_message_end,
        })
    }

    /// Pop received fragments and construct a full message.
    fn receive_pop_fragments(&mut self, current_message_end: i64) -> Option<BoxedStreamReadResult> {
        let (
            current_message_begin,
            packet_type,
            mut packet_flags,
            mut first_timepoint_microseconds,
        ) = if let Some(checked) = self.received_fragments.first_key_value() {
            (
                checked.1.get_message_begin_offset(),
                checked.1.data.packet_type,
                checked.1.packet.packet_flag,
                checked.1.packet.timepoint_microseconds,
            )
        } else {
            return None;
        };

        let mut last_timepoint_microseconds = first_timepoint_microseconds;

        let mut close_reason = None;
        let mut data =
            bytes::BytesMut::with_capacity((current_message_end - current_message_begin) as usize);
        let mut fragment_count = 0;
        loop {
            if let Some(m) = self.received_fragments.first_key_value() {
                if m.1.get_message_end_offset() <= current_message_end {
                    if let Some(kv) = self.received_fragments.pop_first() {
                        packet_flags |= kv.1.packet.packet_flag;

                        if kv.1.get_message_end_offset() > current_message_begin + data.len() as i64
                        {
                            let valid_start = current_message_begin as usize + data.len()
                                - kv.1.get_message_begin_offset() as usize;
                            data.extend_from_slice(&kv.1.data.data[valid_start..]);
                        }

                        if kv.1.packet.timepoint_microseconds > last_timepoint_microseconds {
                            last_timepoint_microseconds = kv.1.packet.timepoint_microseconds;
                        }

                        if kv.1.packet.timepoint_microseconds < first_timepoint_microseconds {
                            first_timepoint_microseconds = kv.1.packet.timepoint_microseconds;
                        }

                        if let Some(cr) = kv.1.data.close_reason {
                            close_reason = Some(cr);
                        }

                        fragment_count += 1;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Some(Box::new(StreamReadResult {
            message: StreamMessage::new(
                packet_type,
                current_message_begin,
                data.into(),
                packet_flags,
                close_reason.map(|v| v.into()),
            ),
            fragment_count,
            first_timepoint_microseconds,
            last_timepoint_microseconds,
        }))
    }

    fn move_received_acknowledge_offset(&mut self, this_frame_message_start: i64) {
        loop {
            let last_fragment = if let Some(x) = self.received_fragments.last_key_value() {
                x
            } else {
                break;
            };

            if last_fragment.1.get_message_end_offset() <= self.received_acknowledge_offset {
                break;
            }

            let mut received_packet_finished_offset = None;
            {
                let check_contained = self.received_fragments.range(this_frame_message_start..);
                for checked in check_contained {
                    if checked.1.get_message_begin_offset() > self.received_acknowledge_offset {
                        break;
                    }

                    if checked.1.get_message_begin_offset() <= self.received_acknowledge_offset
                        && checked.1.get_message_end_offset() > self.received_acknowledge_offset
                    {
                        self.received_acknowledge_offset = checked.1.get_message_end_offset();

                        if !checked
                            .1
                            .check_fragment_flag(PacketFragmentFlagType::HasMore)
                        {
                            received_packet_finished_offset =
                                Some(checked.1.get_message_end_offset());
                            break;
                        }
                    }
                }
            }

            if let Some(this_message_offset_end) = received_packet_finished_offset {
                if let Some(new_read_result) = self.receive_pop_fragments(this_message_offset_end) {
                    self.received_message_total_length += new_read_result.message.data.len();
                    self.received_messages.push_back(new_read_result);
                }
            } else {
                break;
            }
        }
    }

    fn reset_acknowledge_offset(&mut self, offset: i64) {
        if self.received_acknowledge_offset < offset {
            self.received_acknowledge_offset = offset;
        }

        // Remove all frames less than offset
        while !self.received_fragments.is_empty() {
            let checked = self.received_fragments.first_key_value().unwrap();
            if checked.1.get_message_end_offset() > offset {
                break;
            }

            self.received_fragments.pop_first();
        }

        // Remove all frames contains offset and select the largest one
        let mut strip_frame = None;
        while !self.received_fragments.is_empty() {
            let checked = self.received_fragments.first_key_value().unwrap();
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

            self.received_fragments.pop_first();
        }

        // Insert striped frame.
        match strip_frame {
            Some(f) => {
                if !f.is_empty() {
                    self.received_fragments
                        .insert(f.get_message_begin_offset(), f);
                }
            }
            None => {}
        }
    }

    pub fn receive_read(&mut self) -> Option<BoxedStreamReadResult> {
        if let Some(x) = self.received_messages.pop_front() {
            self.received_message_total_length -= x.message.data.len();
            Some(x)
        } else {
            None
        }
    }

    pub fn is_receive_readable(&self) -> bool {
        !self.received_messages.is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::rand::{thread_rng, Rng};

    use libatbus_protocol::{
        AtbusPacketType, FrameMessageHead, PacketFragmentMessage, StreamPacketInformation,
    };

    use std::collections::HashMap;
    use std::ops::DerefMut;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn generate_message_data_buffer(size: usize) -> bytes::Bytes {
        let mut ret = vec![b'0'; size as usize];

        thread_rng().fill(ret.deref_mut());

        ret.into()
    }

    fn generate_message_data<S>(
        source: &bytes::Bytes,
        mut stream_offset: usize,
        fragment_sizes: S,
        packet_flag: i32,
        timepoint_microseconds: i64,
        finish_last_fragment: bool,
    ) -> StreamPacketFragmentUnpack
    where
        S: AsRef<[usize]>,
    {
        let mut ret = StreamPacketFragmentUnpack {
            packet: Rc::new(StreamPacketInformation {
                head: Some(FrameMessageHead {
                    source: String::from("relaysvr:node-random-name-abcdefg"),
                    destination: String::from("server:node-random-name-abcdefg"),
                    forward_for_source: String::from("client:node-random-name-abcdefg"),
                    forward_for_connection_id: 5321,
                }),
                packet_flag,
                timepoint_microseconds,
            }),
            stream_offset: stream_offset as i64,
            fragment: Vec::with_capacity(fragment_sizes.as_ref().len()),
        };

        for i in 0..fragment_sizes.as_ref().len() {
            let fragment_size = fragment_sizes.as_ref()[i];
            if stream_offset >= source.len() {
                break;
            }

            if stream_offset + fragment_size >= source.len() {
                ret.fragment.push(StreamPacketFragmentMessage {
                    packet: ret.packet.clone(),
                    offset: stream_offset as i64,
                    data: PacketFragmentMessage {
                        packet_type: AtbusPacketType::Data as i32,
                        data: source.slice(stream_offset..source.len()),
                        fragment_flag: if finish_last_fragment {
                            0
                        } else {
                            PacketFragmentFlagType::HasMore as i32
                        },
                        options: None,
                        labels: HashMap::new(),
                        forward_for: None,
                        close_reason: None,
                    },
                });
                break;
            } else {
                ret.fragment.push(StreamPacketFragmentMessage {
                    packet: ret.packet.clone(),
                    offset: stream_offset as i64,
                    data: PacketFragmentMessage {
                        packet_type: AtbusPacketType::Data as i32,
                        data: source.slice(stream_offset..stream_offset + fragment_size),
                        fragment_flag: if finish_last_fragment
                            && i + 1 == fragment_sizes.as_ref().len()
                        {
                            0
                        } else {
                            PacketFragmentFlagType::HasMore as i32
                        },
                        options: None,
                        labels: HashMap::new(),
                        forward_for: None,
                        close_reason: None,
                    },
                });
                stream_offset += fragment_size;
            }
        }

        ret
    }

    #[test]
    fn receive_message() {
        let mut stream = Stream::new(137);
        assert_eq!(137, stream.get_stream_id());
        assert_eq!(false, stream.is_receive_readable());

        let message_data_buffer = generate_message_data_buffer(8000);
        let timepoint_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let unpack_message = generate_message_data(
            &message_data_buffer,
            256,
            &[1024, 1024],
            PacketFlagType::ResetOffset as i32,
            timepoint_start,
            false,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(256, receive_result.packet_begin_offset);
        assert_eq!(256 + 2048, receive_result.packet_end_offset);

        assert_eq!(256 + 2048, stream.get_acknowledge_offset());
        assert_eq!(256 + 2048, stream.get_receive_max_offset());
        assert_eq!(false, stream.is_receive_readable());
        assert!(stream.receive_read().is_none());

        // Hole
        let unpack_message = generate_message_data(
            &message_data_buffer,
            256 + 2048 + 2048,
            &[2048],
            0,
            timepoint_start + 1,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(256 + 2048 + 2048, receive_result.packet_begin_offset);
        assert_eq!(256 + 2048 + 2048 + 2048, receive_result.packet_end_offset);
        assert_eq!(false, stream.is_receive_readable());
        assert!(stream.receive_read().is_none());

        assert_eq!(256 + 2048, stream.get_acknowledge_offset());
        assert_eq!(256 + 2048 + 2048 + 2048, stream.get_receive_max_offset());

        // Fill hole
        let unpack_message = generate_message_data(
            &message_data_buffer,
            256 + 2048,
            &[2048],
            0,
            timepoint_start + 2,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(256 + 2048, receive_result.packet_begin_offset);
        assert_eq!(256 + 2048 + 2048, receive_result.packet_end_offset);
        assert_eq!(true, stream.is_receive_readable());

        assert_eq!(256 + 2048 + 2048 + 2048, stream.get_acknowledge_offset());
        assert_eq!(256 + 2048 + 2048 + 2048, stream.get_receive_max_offset());
        assert_eq!(2048 + 2048 + 2048, stream.received_message_total_length);

        // Verify message
        // receive first
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(read_result.message.has_packet_flag_reset_offset());
        assert_eq!(256, read_result.message.stream_offset);
        assert_eq!(3, read_result.fragment_count);
        assert_eq!(timepoint_start, read_result.first_timepoint_microseconds);
        assert_eq!(timepoint_start + 2, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(256..256 + 4096));

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(2048, stream.received_message_total_length);

        // receive second
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert_eq!(256 + 4096, read_result.message.stream_offset);
        assert_eq!(1, read_result.fragment_count);
        assert_eq!(
            timepoint_start + 1,
            read_result.first_timepoint_microseconds
        );
        assert_eq!(timepoint_start + 1, read_result.last_timepoint_microseconds);
        assert!(
            read_result.message.data == message_data_buffer.slice(256 + 4096..256 + 4096 + 2048)
        );

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);
    }

    #[test]
    fn receive_reset_offset() {
        let mut stream = Stream::new(138);
        assert_eq!(138, stream.get_stream_id());
        assert_eq!(false, stream.is_receive_readable());

        let message_data_buffer = generate_message_data_buffer(2048);
        let timepoint_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let unpack_message =
            generate_message_data(&message_data_buffer, 0, &[256], 0, timepoint_start, false);

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(0, receive_result.packet_begin_offset);
        assert_eq!(256, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());
        assert!(stream.receive_read().is_none());

        // Hole
        let unpack_message = generate_message_data(
            &message_data_buffer,
            512 + 512,
            &[512],
            0,
            timepoint_start + 1,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(512 + 512, receive_result.packet_begin_offset);
        assert_eq!(512 + 512 + 512, receive_result.packet_end_offset);
        assert_eq!(false, stream.is_receive_readable());
        assert!(stream.receive_read().is_none());

        // Reset offset
        let unpack_message = generate_message_data(
            &message_data_buffer,
            512,
            &[512],
            PacketFlagType::ResetOffset as i32,
            timepoint_start + 2,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(512, receive_result.packet_begin_offset);
        assert_eq!(512 + 512, receive_result.packet_end_offset);

        // Verify message
        // receive first
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(read_result.message.has_packet_flag_reset_offset());
        assert_eq!(512, read_result.message.stream_offset);
        assert_eq!(1, read_result.fragment_count);
        assert_eq!(
            timepoint_start + 2,
            read_result.first_timepoint_microseconds
        );
        assert_eq!(timepoint_start + 2, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(512..512 + 512));

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(512, stream.received_message_total_length);

        // receive second
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert_eq!(1024, read_result.message.stream_offset);
        assert_eq!(1, read_result.fragment_count);
        assert_eq!(
            timepoint_start + 1,
            read_result.first_timepoint_microseconds
        );
        assert_eq!(timepoint_start + 1, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(1024..1024 + 512));

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);
    }

    #[test]
    fn receive_reset_offset_with_unreceived_message() {
        let mut stream = Stream::new(139);
        assert_eq!(139, stream.get_stream_id());
        assert_eq!(false, stream.is_receive_readable());

        let message_data_buffer = generate_message_data_buffer(2048);
        let timepoint_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let unpack_message =
            generate_message_data(&message_data_buffer, 0, &[256], 0, timepoint_start, true);

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(0, receive_result.packet_begin_offset);
        assert_eq!(256, receive_result.packet_end_offset);

        assert_eq!(true, stream.is_receive_readable());

        // Hole
        let unpack_message = generate_message_data(
            &message_data_buffer,
            512 + 512,
            &[512],
            0,
            timepoint_start + 1,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(512 + 512, receive_result.packet_begin_offset);
        assert_eq!(512 + 512 + 512, receive_result.packet_end_offset);

        // Reset offset
        let unpack_message = generate_message_data(
            &message_data_buffer,
            512,
            &[512],
            PacketFlagType::ResetOffset as i32,
            timepoint_start + 2,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(512, receive_result.packet_begin_offset);
        assert_eq!(512 + 512, receive_result.packet_end_offset);

        // Verify message
        // receive first
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(!read_result.message.has_packet_flag_reset_offset());
        assert_eq!(0, read_result.message.stream_offset);
        assert_eq!(1, read_result.fragment_count);
        assert_eq!(timepoint_start, read_result.first_timepoint_microseconds);
        assert_eq!(timepoint_start, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(..256));

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(1024, stream.received_message_total_length);

        // receive second
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(read_result.message.has_packet_flag_reset_offset());
        assert_eq!(512, read_result.message.stream_offset);
        assert_eq!(1, read_result.fragment_count);
        assert_eq!(
            timepoint_start + 2,
            read_result.first_timepoint_microseconds
        );
        assert_eq!(timepoint_start + 2, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(512..512 + 512));

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(512, stream.received_message_total_length);

        // receive third
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert_eq!(1024, read_result.message.stream_offset);
        assert_eq!(1, read_result.fragment_count);
        assert_eq!(
            timepoint_start + 1,
            read_result.first_timepoint_microseconds
        );
        assert_eq!(timepoint_start + 1, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(1024..1024 + 512));

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);
    }

    #[test]
    fn receive_overlap() {
        let mut stream = Stream::new(139);
        assert_eq!(139, stream.get_stream_id());
        assert_eq!(false, stream.is_receive_readable());

        let message_data_buffer = generate_message_data_buffer(1024);
        let timepoint_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let unpack_message =
            generate_message_data(&message_data_buffer, 0, &[256], 0, timepoint_start, false);

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(0, receive_result.packet_begin_offset);
        assert_eq!(256, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());

        // tail
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128 + 256,
            &[256],
            0,
            timepoint_start + 1,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128 + 256, receive_result.packet_begin_offset);
        assert_eq!(128 + 256 + 256, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());

        // Overlap
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128,
            &[256],
            0,
            timepoint_start + 2,
            false,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128, receive_result.packet_begin_offset);
        assert_eq!(128 + 256, receive_result.packet_end_offset);

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(128 + 512, stream.received_message_total_length);

        // Verify message
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(!read_result.message.has_packet_flag_reset_offset());
        assert_eq!(0, read_result.message.stream_offset);
        assert_eq!(3, read_result.fragment_count);
        assert_eq!(timepoint_start, read_result.first_timepoint_microseconds);
        assert_eq!(timepoint_start + 2, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(..128 + 512));

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);
    }

    #[test]
    fn receive_overwrite_small_fragment() {
        let mut stream = Stream::new(139);
        assert_eq!(139, stream.get_stream_id());
        assert_eq!(false, stream.is_receive_readable());

        let message_data_buffer = generate_message_data_buffer(1024);
        let timepoint_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let unpack_message =
            generate_message_data(&message_data_buffer, 0, &[256], 0, timepoint_start, false);

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(0, receive_result.packet_begin_offset);
        assert_eq!(256, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());

        // tail
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128 + 256,
            &[256],
            0,
            timepoint_start + 1,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128 + 256, receive_result.packet_begin_offset);
        assert_eq!(128 + 256 + 256, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());

        // Overwrite small
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128,
            &[250],
            0,
            timepoint_start + 2,
            false,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128, receive_result.packet_begin_offset);
        assert_eq!(128 + 250, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);

        // Use large
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128,
            &[256],
            0,
            timepoint_start + 3,
            false,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128, receive_result.packet_begin_offset);
        assert_eq!(128 + 256, receive_result.packet_end_offset);

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(128 + 512, stream.received_message_total_length);

        // Verify message
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(!read_result.message.has_packet_flag_reset_offset());
        assert_eq!(0, read_result.message.stream_offset);
        assert_eq!(3, read_result.fragment_count);
        assert_eq!(timepoint_start, read_result.first_timepoint_microseconds);
        assert_eq!(timepoint_start + 3, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(..128 + 512));

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);
    }

    #[test]
    fn receive_drop_small_fragment() {
        let mut stream = Stream::new(139);
        assert_eq!(139, stream.get_stream_id());
        assert_eq!(false, stream.is_receive_readable());

        let message_data_buffer = generate_message_data_buffer(1024);
        let timepoint_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;
        let unpack_message = generate_message_data(
            &message_data_buffer,
            0,
            &[256 + 128],
            0,
            timepoint_start,
            false,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(0, receive_result.packet_begin_offset);
        assert_eq!(256 + 128, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());

        // drop small fragment
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128,
            &[250],
            0,
            timepoint_start + 2,
            false,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128, receive_result.packet_begin_offset);
        // Push nothing so begin == end
        assert_eq!(128, receive_result.packet_end_offset);

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);

        // tail
        let unpack_message = generate_message_data(
            &message_data_buffer,
            128 + 256,
            &[256],
            0,
            timepoint_start + 1,
            true,
        );

        let receive_result = stream.receive_push(unpack_message);
        assert!(receive_result.is_ok());
        let receive_result = receive_result.unwrap();

        assert_eq!(128 + 256, receive_result.packet_begin_offset);
        assert_eq!(128 + 256 + 256, receive_result.packet_end_offset);

        assert_eq!(true, stream.is_receive_readable());
        assert_eq!(128 + 512, stream.received_message_total_length);

        // Verify message
        let read_result = stream.receive_read();
        assert!(read_result.is_some());
        let read_result = read_result.unwrap();
        assert!(!read_result.message.has_packet_flag_reset_offset());
        assert_eq!(0, read_result.message.stream_offset);
        assert_eq!(2, read_result.fragment_count);
        assert_eq!(timepoint_start, read_result.first_timepoint_microseconds);
        assert_eq!(timepoint_start + 1, read_result.last_timepoint_microseconds);
        assert!(read_result.message.data == message_data_buffer.slice(..128 + 512));

        assert_eq!(false, stream.is_receive_readable());
        assert_eq!(0, stream.received_message_total_length);
    }
}
