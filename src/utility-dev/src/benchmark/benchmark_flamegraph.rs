// Copyright 2023 atframework
// Licensed under the MIT licenses.

use std::{fs::File, os::raw::c_int, path::Path, env};

use criterion::profiler::Profiler;
use pprof::ProfilerGuard;

/// Small custom profiler that can be used with Criterion to create a flamegraph for benchmarks.
/// Also see [the Criterion documentation on this][custom-profiler].
///
/// ## Example on how to enable the custom profiler:
///
/// ```
/// mod perf;
/// use perf::FlamegraphProfiler;
///
/// fn fibonacci_profiled(criterion: &mut Criterion) {
///     // Use the criterion struct as normal here.
/// }
///
///
/// criterion_group! {
///     name = benches;
///     config = Criterion::default().with_profiler(FlamegraphProfiler::new(1000));
///     targets = fibonacci_profiled
/// }
/// ```
pub struct FlamegraphProfiler<'a> {
    frequency: c_int,
    active_profiler: Option<ProfilerGuard<'a>>,
}

impl<'a> FlamegraphProfiler<'a> {
    #[allow(dead_code)]
    pub fn new(default_frequency: i32) -> Self {
        let final_frequency: i32 =  if let Ok(x) = env::var("CARGO_PROFILE_SAMPLE_FREQUENCY") {
            x.parse().unwrap_or(default_frequency)
        } else {
            default_frequency
        };

        FlamegraphProfiler {
            frequency: final_frequency as c_int,
            active_profiler: None,
        }
    }
}

impl<'a> Profiler for FlamegraphProfiler<'a> {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        self.active_profiler = Some(ProfilerGuard::new(self.frequency).unwrap());
    }

    fn stop_profiling(&mut self, _benchmark_id: &str, benchmark_dir: &Path) {
        std::fs::create_dir_all(benchmark_dir).unwrap();
        let flamegraph_path = benchmark_dir.join("flamegraph.svg");
        let flamegraph_file = File::create(&flamegraph_path)
            .expect("File system error while creating flamegraph.svg");
        if let Some(profiler) = self.active_profiler.take() {
            profiler
                .report()
                .build()
                .unwrap()
                .flamegraph(flamegraph_file)
                .expect("Error writing flamegraph");
        }
    }
}
