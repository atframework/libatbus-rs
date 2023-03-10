// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::collections::HashMap;
use super::stream;

pub struct Endpoint {
  streams : HashMap<i64, stream::Stream>
}
