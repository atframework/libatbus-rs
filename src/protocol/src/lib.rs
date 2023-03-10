// Copyright 2023 atframework
// Licensed under the MIT licenses.

extern crate bytes;
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
