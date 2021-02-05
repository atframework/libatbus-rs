#![cfg(test)]

extern crate bytes;
extern crate rand;
extern crate test;

use bytes::BytesMut;
use rand::{thread_rng, Rng};
use test::Bencher;

use ::libatbus_protocol::encoder::{Encoder, EncoderFrame};
//use ::libatbus_protocol:error::ProtocolError;
use ::libatbus_protocol::proto::libatbus_protocol;
//use ::libatbus_protocol::decoder::Decoder;
use ::libatbus_protocol::FrameMessage;

fn generate_uuid() -> Vec<u8> {
    let mut ret = Vec::new();
    ret.resize(32, 0 as u8);
    thread_rng().fill(&mut ret[16..]);
    for i in 0..16 {
        let c = ret[i + 16];
        let lc = c % 16;
        let hc = c / 16;
        ret[i << 1] = if lc >= 10 {
            lc - 10 + 'a' as u8
        } else {
            lc + '0' as u8
        };
        ret[(i << 1) + 1] = if hc >= 10 {
            hc - 10 + 'a' as u8
        } else {
            hc + '0' as u8
        };
    }

    ret
}

fn generate_packet_message(content_length: usize) -> FrameMessage {
    let mut ret = FrameMessage::new();
    ret.mut_head().set_source(generate_uuid());
    ret.mut_head().set_destination(generate_uuid());
    ret.mut_head()
        .set_version(libatbus_protocol::ATBUS_PROTOCOL_CONST::ATBUS_PROTOCOL_VERSION as i32);

    let body = ret.mut_packet();
    body.set_packet_sequence(123);
    body.set_packet_acknowledge(456);
    body.set_flags(
        libatbus_protocol::ATBUS_PACKET_FLAG_TYPE::ATBUS_PACKET_FLAG_RESET_SEQUENCE as i32,
    );
    body.mut_content().resize(content_length, 0);
    thread_rng().fill(body.mut_content().as_mut_slice());

    ret
}

#[bench]
fn encoder_message_128B(b: &mut Bencher) {
    let tmpl = generate_packet_message(128);

    b.iter(|| {
        let frame = EncoderFrame::new(&tmpl);
        let encoder = Encoder::new();
        let output = BytesMut::with_capacity(frame.get_total_length());
        encoder.put_bytes(frame, &mut output).unwrap()
    })
}
