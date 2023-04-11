// Copyright 2023 atframework
// Licensed under the MIT licenses.

use libc::c_char;

#[repr(C)]
pub struct DataBlock {
    pub data: *const u8,
    pub length: u64,
}

pub type CString = *const c_char;

#[repr(C)]
pub struct StringView {
    pub data: CString,
    pub length: u64,
}
