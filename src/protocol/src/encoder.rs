use super::error::{ProtocolError, ProtocolResult};
use super::frame_block;
use super::{BoxedFrameMessage, FrameMessage};

pub struct Encoder {}

impl Encoder {
    pub fn put<T: AsMut<[u8]>>(msg: &FrameMessage, output: &T) -> ProtocolResult<usize> {
        //let msg_length = msg.compute_size();
        //let varint_length = frame_block::
        //let total_size =
        Ok(0)
    }
}
