// Copyright 2023 atframework
// Licensed under the MIT licenses.

use core::sync::atomic::{AtomicI64, Ordering};
use std::time;

use crate::once_cell;
use crate::uuid;

static LOCAL_UNIQUE_ID_ALLOCATOR: once_cell::sync::Lazy<AtomicI64> =
    once_cell::sync::Lazy::new(|| {
        let now = time::SystemTime::now();
        // 2022-01-01 00:00:00 UTC -> 1640995200
        let base_offset = 1640995200000000 as i64;
        let offset = if let Ok(x) = now.duration_since(time::UNIX_EPOCH) {
            x.as_micros() as i64
        } else {
            1
        };
        let final_offset = if offset > base_offset {
            offset - base_offset
        } else {
            offset
        };
        AtomicI64::new(final_offset)
    });

pub fn generate_local_unique_id() -> i64 {
    LOCAL_UNIQUE_ID_ALLOCATOR.fetch_add(1, Ordering::AcqRel)
}

pub fn generate_stanard_uuid_v4() -> uuid::Bytes {
    uuid::Uuid::new_v4().into_bytes()
}

pub fn generate_stanard_uuid_v4_string(hyphenated: bool) -> String {
    if hyphenated {
        uuid::Uuid::new_v4().hyphenated().to_string()
    } else {
        uuid::Uuid::new_v4().simple().to_string()
    }
}
