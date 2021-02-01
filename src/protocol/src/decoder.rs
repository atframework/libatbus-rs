use bytes::BytesMut;

use super::error::{ProtocolError, ProtocolResult};
use super::frame_block;

pub enum DecoderState {
    /// Decode frame length
    DecodeLength,
    /// Frame length already decoded and it's a small packet
    ReceiveCompactFrame(usize, u64),
    /// Frame length already decoded and it's a large packet
    ReceiveStandaloneFrame(Box<BytesMut>, u64),
}

pub struct Decoder {
    state: DecoderState,
    frame_consume_offset: usize,
    frame_consume_length: usize,
    frame_compact_buffer: BytesMut,
}

impl Decoder {
    pub fn new() -> Decoder {
        let result = Decoder {
            state: DecoderState::DecodeLength,
            frame_consume_offset: 0,
            frame_consume_length: 0,
            frame_compact_buffer: BytesMut::new(),
        };

        result.resize_compact_buffer(60 * 1024);
        result
    }

    pub fn has_packet(&self) -> bool {
        match self.state {
            DecoderState::DecodeLength => false,
            &DecoderState::ReceiveCompactFrame(consume, length) => {
                self.frame_consume_length
                    >= self.frame_consume_offset + consume + frame_block::FRAME_HASH_SIZE + length
            }
            &DecoderState::ReceiveStandaloneFrame(buf_block, length) => {
                buf_block.len() >= frame_block::FRAME_HASH_SIZE + length
            }
        }
    }

    pub fn pick_packet(&mut self) -> ProtocolResult<frame_block::FrameBlock> {
        match self.state {
            DecoderState::DecodeLength => Err(ProtocolError::TruncatedPacket),
            &DecoderState::ReceiveCompactFrame(consume, length) => {
                if self.frame_consume_length
                    >= self.frame_consume_offset + consume + frame_block::FRAME_HASH_SIZE + length
                {
                    Ok(frame_block::FrameBlock::new())
                } else {
                    Err(ProtocolError::TruncatedPacket)
                }
            }
            &DecoderState::ReceiveStandaloneFrame(buf_block, length) => {
                if buf_block.len() >= frame_block::FRAME_HASH_SIZE + length {
                    Ok(frame_block::FrameBlock::new())
                } else {
                    Err(ProtocolError::TruncatedPacket)
                }
            }
        }
        Ok(FrameBlock::new())
    }

    pub fn resize_compact_buffer(&mut self, new_len: usize) {
        // At lease 16 bytes for frame length(at most 10 bytes)
        if new_len < 16 {
            self.frame_compact_buffer.resize(16, 0);
        } else {
            self.frame_compact_buffer.resize(new_len, 0);
        }
    }
}
