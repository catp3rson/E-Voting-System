// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use certificate_stark::schnorr::get_example;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 6] = [1, 2, 4, 8, 16, 32];

fn schnorr_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(400));

    for &size in SIZES.iter() {
        let schnorr = get_example(size);
        
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| schnorr.prove());
        });

        let proof = schnorr.prove();

        println!("Proof size for schnorr/prove/{}: {} bytes", size, proof.to_bytes().len());

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| schnorr.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(schnorr_group, schnorr_bench);
criterion_main!(schnorr_group);
