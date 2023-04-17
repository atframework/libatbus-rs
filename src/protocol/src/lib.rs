// Copyright 2023 atframework
// Licensed under the MIT licenses.

extern crate bytes;
extern crate libatbus_utility;
extern crate xxhash_rust;
extern crate prost;
extern crate rand;
extern crate once_cell;

// extern crate quote;
// extern crate syn;
// https://doc.rust-lang.org/book/ch19-06-macros.html?highlight=derive#how-to-write-a-custom-derive-macro

mod frame_block;

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod proto;
pub mod stream_message;

pub type ProtocolConst = proto::atbus::protocol::AtbusProtocolConst;
pub type FrameMessage = proto::atbus::protocol::FrameMessage;
pub type BoxedFrameMessage = Box<FrameMessage>;
pub type FrameMessageBody = proto::atbus::protocol::frame_message::Body;
pub type FrameMessageHead = proto::atbus::protocol::MessageHead;

pub type PingMessage = proto::atbus::protocol::PingData;
pub type ForwardMessage = proto::atbus::protocol::ForwardData;
pub type StreamAcknowledgeMessage = proto::atbus::protocol::StreamAcknowledge;
pub type PacketMessage = proto::atbus::protocol::PacketData;
pub type PacketContentMessage = proto::atbus::protocol::PacketContent;
pub type PacketFragmentMessage = proto::atbus::protocol::packet_content::FragmentType;
pub type PacketOptionMessage = proto::atbus::protocol::PacketOptions;
pub type CloseReasonMessage = proto::atbus::protocol::CloseReasonData;

pub type CloseReasonCode = proto::atbus::protocol::AtbusCloseReason;
pub type AtbusPacketType = proto::atbus::protocol::AtbusPacketType;

pub type PacketFlagType = proto::atbus::protocol::AtbusPacketFlagType;
pub type PacketFragmentFlagType = proto::atbus::protocol::AtbusPacketFragmentFlagType;

pub type StreamMessage = stream_message::StreamMessage;
pub type BoxedStreamMessage = Box<StreamMessage>;
pub type StreamPacketFragmentMessage = stream_message::StreamPacketFragmentMessage;
pub type StreamConnectionContext = stream_message::StreamConnectionContext;
pub type SharedStreamConnectionContext = stream_message::SharedStreamConnectionContext;
pub type StreamPacketFragmentPack = stream_message::StreamPacketFragmentPack;
pub type StreamPacketFragmentUnpack = stream_message::StreamPacketFragmentUnpack;
