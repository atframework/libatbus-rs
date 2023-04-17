// Copyright 2023 atframework
// Licensed under the MIT licenses.

use bytes::BytesMut;
use prost::Message;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use criterion::{black_box, criterion_group, Criterion, Throughput};

use ::libatbus_protocol::encoder::{Encoder, EncoderFrame};
use ::libatbus_protocol::{
    FrameMessage, FrameMessageBody, FrameMessageHead, PacketContentMessage, PacketFlagType,
    PacketFragmentFlagType, PacketFragmentMessage, PacketMessage,
};

use super::utility::generate_uuid;

fn generate_packet_message(content_length: usize) -> FrameMessage {
    let mut user_data: Vec<u8> = vec![0; content_length];
    thread_rng().fill(user_data.as_mut_slice());

    let content = PacketContentMessage {
        fragment: vec![PacketFragmentMessage {
            packet_type: 0,
            data: user_data.into(),
            fragment_flag: PacketFragmentFlagType::HasMore as i32,
            options: None,
            labels: HashMap::new(),
            forward_for: None,
            close_reason: None,
        }],
    };

    FrameMessage {
        head: Some(FrameMessageHead {
            source: generate_uuid(),
            destination: generate_uuid(),
            forward_for_source: String::default(),
            forward_for_connection_id: 0,
        }),
        body: Some(FrameMessageBody::Packet(PacketMessage {
            stream_id: 123,
            stream_offset: 456,
            content: content.encode_to_vec().into(),
            flags: PacketFlagType::ResetOffset as i32,
            padding_size: 32,
            timepoint_microseconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
        })),
    }
}

fn encoder_message(c: &mut Criterion, group_name: &str, message_size: usize) {
    {
        let tmpl = generate_packet_message(message_size);
        let mut small_group = c.benchmark_group(format!("{}(QPS)", group_name));
        small_group.throughput(Throughput::Elements(1));

        small_group.bench_function(format!("message size: {}", message_size).as_str(), |b| {
            b.iter(|| {
                let frame = EncoderFrame::new(&tmpl);
                let encoder = Encoder::new();
                let output = black_box(BytesMut::with_capacity(frame.get_total_length()));
                let _ = encoder.put_block(frame, output);
                1
            })
        });
    }

    {
        let tmpl = generate_packet_message(message_size);
        let mut small_group = c.benchmark_group(format!("{}(Throughput)", group_name));
        small_group.throughput(Throughput::Bytes(message_size as u64));

        small_group.bench_function(format!("message size: {}", message_size).as_str(), |b| {
            b.iter(|| {
                let frame = EncoderFrame::new(&tmpl);
                let encoder = Encoder::new();
                let output = black_box(BytesMut::with_capacity(frame.get_total_length()));
                let _ = encoder.put_block(frame, output);
                message_size
            })
        });
    }
}

fn encoder_message_small(c: &mut Criterion) {
    encoder_message(c, "Encoder -> encode small message", 64);
    encoder_message(c, "Encoder -> encode small message", 128);
    encoder_message(c, "Encoder -> encode small message", 256);
    encoder_message(c, "Encoder -> encode small message", 400);
    encoder_message(c, "Encoder -> encode small message", 1024);
}

fn encoder_message_large(c: &mut Criterion) {
    encoder_message(c, "Encoder -> encode large message", 4096);
    encoder_message(c, "Encoder -> encode large message", 16000);
    encoder_message(c, "Encoder -> encode large message", 65000);
}

criterion_group! {
    name = encoder_small;
    config = Criterion::default();
        // .warm_up_time(Duration::from_micros(256))
    targets = encoder_message_small
}

criterion_group! {
    name = encoder_large;
    config = Criterion::default();
        // .warm_up_time(Duration::from_micros(256));
    targets = encoder_message_large
}
