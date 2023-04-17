// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ops::DerefMut;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use std::collections::HashMap;

use crate::criterion::{criterion_group, Criterion, Throughput};
use crate::rand::{thread_rng, Rng};

use crate::libatbus_utility_dev::benchmark::BenchmarkProfiler;

use ::libatbus_protocol::decoder::Decoder;
use ::libatbus_protocol::{
    AtbusPacketType, FrameMessageHead, SharedStreamConnectionContext, StreamConnectionContext,
    StreamMessage, StreamPacketFragmentMessage,
};

use super::utility::generate_uuid;

fn create_context(padding_size: usize) -> SharedStreamConnectionContext {
    Rc::new(RefCell::new(StreamConnectionContext::new(
        FrameMessageHead {
            source: format!("S:{}", generate_uuid()),
            destination: format!("C:{}", generate_uuid()),
            forward_for_source: String::default(),
            forward_for_connection_id: 0,
        },
        0,
        padding_size,
        None,
        HashMap::new(),
        None,
    )))
}

fn prepare_message_pool(messige_size: usize, count: usize) -> Vec<::prost::bytes::Bytes> {
    let mut ret = Vec::with_capacity(count);

    for _ in 0..count {
        let mut data_buffer: Vec<u8> = vec![b'0'; messige_size];
        thread_rng().fill(data_buffer.deref_mut());

        ret.push(data_buffer.into());
    }

    ret
}

fn insert_stream_messages(
    ctx: &SharedStreamConnectionContext,
    start_offset: i64,
    message_pool: &Vec<::prost::bytes::Bytes>,
    pool_index: usize,
    simulator_stream_messages: &mut BTreeMap<i64, Box<StreamMessage>>,
) {
    simulator_stream_messages.insert(
        start_offset,
        Box::new(StreamMessage {
            packet_type: AtbusPacketType::Data as i32,
            stream_offset: start_offset,
            data: message_pool[pool_index].clone(),
            flags: 0,
            close_reason: None,
            connection_context: ctx.clone(),
        }),
    );
}

fn stream_message_benchmark(c: &mut Criterion, group_name: &str, message_size: usize) {
    let count = 1024;
    let ctx = create_context(32);
    let message_pool = prepare_message_pool(message_size, count);
    let mut message_index: usize = 0;
    let mut current_offset = 0;
    let mut simulator_stream_messages: BTreeMap<i64, Box<StreamMessage>> = BTreeMap::new();

    let mut output_buffers = Vec::with_capacity(count);
    {
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let mut group = c.benchmark_group(format!("{}(Pack QPS)", group_name));
        group.throughput(Throughput::Elements(1));

        group.bench_function(format!("message size: {}", message_size).as_str(), |b| {
            b.iter(|| {
                insert_stream_messages(
                    &ctx,
                    current_offset,
                    &message_pool,
                    message_index,
                    &mut simulator_stream_messages,
                );

                let mut output: Vec<u8> = Vec::with_capacity(message_size + 4096);
                let pack_result = StreamMessage::pack(
                    &simulator_stream_messages,
                    &mut output,
                    current_offset,
                    message_size + 256,
                    timepoint,
                );

                simulator_stream_messages.remove(&current_offset);
                message_index += 1;
                message_index %= count;
                current_offset += message_size as i64;

                assert!(pack_result.is_ok());

                if output_buffers.len() < count {
                    output_buffers.push(output);
                }

                1
            })
        });
    }

    {
        let timepoint = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as i64;

        let mut group = c.benchmark_group(format!("{}(Pack throughput)", group_name));
        group.throughput(Throughput::Bytes(message_size as u64));

        group.bench_function(format!("message size: {}", message_size).as_str(), |b| {
            b.iter(|| {
                insert_stream_messages(
                    &ctx,
                    current_offset,
                    &message_pool,
                    message_index,
                    &mut simulator_stream_messages,
                );

                let mut output: Vec<u8> = Vec::with_capacity(message_size + 4096);
                let pack_result = StreamMessage::pack(
                    &simulator_stream_messages,
                    &mut output,
                    current_offset,
                    message_size + 256,
                    timepoint,
                );

                simulator_stream_messages.remove(&current_offset);
                message_index += 1;
                message_index %= count;
                current_offset += message_size as i64;

                assert!(pack_result.is_ok());

                if output_buffers.len() < count {
                    output_buffers.push(output);
                }

                message_size
            })
        });
    }

    {
        let mut output_index = 0;
        let decoder = Decoder::new();

        let mut group = c.benchmark_group(format!("{}(Unpack QPS)", group_name));
        group.throughput(Throughput::Elements(1));

        group.bench_function(format!("message size: {}", message_size).as_str(), |b| {
            b.iter(|| {
                let result = StreamPacketFragmentMessage::unpack_from_buffer(
                    &decoder,
                    &output_buffers[output_index][..],
                    Some(ctx.borrow().get_stream_id()),
                );

                assert!(result.unwrap().1 >= message_size);

                output_index += 1;
                output_index %= output_buffers.len();

                1
            })
        });
    }

    {
        let mut output_index = 0;
        let decoder = Decoder::new();

        let mut group = c.benchmark_group(format!("{}(Unpack throughput)", group_name));
        group.throughput(Throughput::Bytes(message_size as u64));

        group.bench_function(format!("message size: {}", message_size).as_str(), |b| {
            b.iter(|| {
                let result = StreamPacketFragmentMessage::unpack_from_buffer(
                    &decoder,
                    &output_buffers[output_index][..],
                    Some(ctx.borrow().get_stream_id()),
                );

                assert!(result.unwrap().1 >= message_size);

                output_index += 1;
                output_index %= output_buffers.len();

                message_size
            })
        });
    }
}

fn stream_message_encode_and_decode_small(c: &mut Criterion) {
    stream_message_benchmark(c, "StreamMessage -> small message", 64);
    stream_message_benchmark(c, "StreamMessage -> small message", 128);
    stream_message_benchmark(c, "StreamMessage -> small message", 256);
    stream_message_benchmark(c, "StreamMessage -> small message", 400);
    stream_message_benchmark(c, "StreamMessage -> small message", 1024);
}

fn stream_message_encode_and_decode_large(c: &mut Criterion) {
    stream_message_benchmark(c, "StreamMessage -> large message", 4096);
    stream_message_benchmark(c, "StreamMessage -> large message", 16000);
    stream_message_benchmark(c, "StreamMessage -> large message", 65000);
}

criterion_group! {
    name = stream_message_small;
    config = Criterion::default().with_profiler(BenchmarkProfiler::new(1000));
        // .warm_up_time(Duration::from_micros(256))
    targets = stream_message_encode_and_decode_small
}

criterion_group! {
    name = stream_message_large;
    config = Criterion::default().with_profiler(BenchmarkProfiler::new(1000));
        // .warm_up_time(Duration::from_micros(256));
    targets = stream_message_encode_and_decode_large
}
