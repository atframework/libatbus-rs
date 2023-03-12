// Copyright 2023 atframework
// Licensed under the MIT licenses.

pub struct EndpointConfigure {
    pub send_window_max_size: usize,
    pub receive_window_max_size: usize,

    pub stream_message_max_size: usize,

    // Max size for each [varint: version]+[varint: length]+libatbus_protocol::FrameMessage+[Hash]
    pub protocol_message_max_size: usize,
}
