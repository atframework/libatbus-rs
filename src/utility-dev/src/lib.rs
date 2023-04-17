// Copyright 2023 atframework
// Licensed under the MIT licenses.

extern crate criterion;

#[cfg(all(target_family = "unix"))]
extern crate pprof;

pub mod benchmark;
