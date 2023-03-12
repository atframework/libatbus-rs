// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::HashMap;

extern crate bytes;
extern crate libatbus_utility;
extern crate murmur3;
extern crate prost;
extern crate rand;
// extern crate quote;
// extern crate syn;
// https://doc.rust-lang.org/book/ch19-06-macros.html?highlight=derive#how-to-write-a-custom-derive-macro

mod frame_block;

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod proto;

pub type FrameMessage = proto::atbus::protocol::FrameMessage;
pub type BoxedFrameMessage = Box<FrameMessage>;

pub type PingMessage = proto::atbus::protocol::PingData;
pub type ForwardMessage = proto::atbus::protocol::ForwardData;
pub type StreamAcknowledgeMessage = proto::atbus::protocol::StreamAcknowledge;
pub type PacketMessage = proto::atbus::protocol::PacketData;
pub type PacketOptionMessage = proto::atbus::protocol::PacketOptions;
pub type CloseReasonMessage = proto::atbus::protocol::CloseReasonData;

pub type PacketFlagType = proto::atbus::protocol::AtbusPacketFlagType;

pub struct StreamMessage {
    pub start_stream_offset: i64,
    pub data: Vec<u8>,

    /// @see atbus.protocol.ATBUS_PACKET_FLAG_TYPE
    pub flags: i32,

    pub options: Option<Box<PacketOptionMessage>>,
    pub labels: Option<Box<HashMap<String, String>>>,
    pub forward_data: Option<Box<ForwardMessage>>,
    pub close_reason: Option<Box<CloseReasonMessage>>,
}

pub type BoxedStreamMessage = Box<StreamMessage>;
