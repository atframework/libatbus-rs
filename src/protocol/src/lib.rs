extern crate bytes;
extern crate murmur3;
extern crate protobuf;
extern crate rand;
// extern crate quote;
// extern crate syn;
// https://doc.rust-lang.org/book/ch19-06-macros.html?highlight=derive#how-to-write-a-custom-derive-macro

mod frame_block;

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod proto;

pub type FrameMessage = proto::libatbus_protocol::message;
pub type BoxedFrameMessage = Box<FrameMessage>;
