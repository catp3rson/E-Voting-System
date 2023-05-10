// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use certificate_stark::merkle_proof::get_example;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 5] = [1, 4, 16, 64, 256];

fn merkle_proof_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(100));

    for &size in SIZES.iter() {
        let merkle_proof = get_example(size);
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| merkle_proof.prove());
        });
        let proof = merkle_proof.prove();

        println!("Proof size for merkle_proof/prove/{}: {} bytes", size, proof.to_bytes().len());

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| merkle_proof.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(merkle_proof_group, merkle_proof_bench);
criterion_main!(merkle_proof_group);
