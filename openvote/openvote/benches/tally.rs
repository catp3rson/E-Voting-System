// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use openvote::tally::{get_example, naive_verify_tally_result};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 1] = [8];//, 16, 32, 64, 128];

fn tally_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("tally");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(400));

    for &size in SIZES.iter() {
        let tally = get_example(size);
        
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| tally.prove());
        });

        let proof = tally.prove();

        println!("Proof size for tally/prove/{}: {} bytes", size, proof.to_bytes().len());

        group.bench_function(BenchmarkId::new("naive", size), |bench| {
            bench.iter(|| naive_verify_tally_result(&tally.encrypted_votes, tally.tally_result));
        });

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| tally.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(tally_group, tally_bench);
criterion_main!(tally_group);
