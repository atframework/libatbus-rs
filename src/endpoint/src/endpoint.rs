// Copyright 2023 atframework
// Licensed under the MIT licenses.

use super::stream;
use std::collections::HashMap;

pub struct Endpoint {
    streams: HashMap<i64, stream::Stream>,
}

impl Endpoint {
    pub fn has_stream(&self, stream_id: i64) -> bool {
        self.streams.contains_key(&stream_id)
    }

    pub fn get_stream(&self, stream_id: i64) -> Option<&stream::Stream> {
        self.streams.get(&stream_id)
    }

    pub fn mut_stream(&mut self, stream_id: i64) -> Option<&mut stream::Stream> {
        self.streams.get_mut(&stream_id)
    }
}
