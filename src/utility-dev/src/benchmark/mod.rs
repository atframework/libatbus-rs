// Copyright 2023 atframework
// Licensed under the MIT licenses.

#[cfg(target_family = "unix")]
mod benchmark_flamegraph;

#[cfg(not(target_family = "unix"))]
mod benchmark_normal;

#[cfg(target_family = "unix")]
pub type BenchmarkProfiler<'a> = benchmark_flamegraph::FlamegraphProfiler<'a>;

#[cfg(not(target_family = "unix"))]
pub type BenchmarkProfiler = benchmark_normal::NormalProfiler;
