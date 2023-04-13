// Copyright 2023 atframework
// Licensed under the MIT licenses.

extern crate bytes;
extern crate criterion;
extern crate rand;

use criterion::criterion_main;

mod encoder;
mod stream_message;
mod utility;

criterion_main! {
  encoder::encoder_small,
  encoder::encoder_large
}
