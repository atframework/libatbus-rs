// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::path::Path;

use criterion::profiler::Profiler;

pub struct NormalProfiler {}

impl NormalProfiler {
    pub fn new(_frequency: i32) -> Self {
        NormalProfiler {}
    }
}

impl Profiler for NormalProfiler {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {}

    fn stop_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {}
}
