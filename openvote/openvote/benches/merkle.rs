// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use openvote::merkle::{get_example, naive_verify_merkle_proofs};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 5] = [8, 16, 32, 64, 128];

fn merkle_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(100));

    for &size in SIZES.iter() {
        let merkle = get_example(size);
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| merkle.prove());
        });
        let proof = merkle.prove();

        println!("Proof size for merkle/prove/{}: {} bytes", size, proof.to_bytes().len());

        group.bench_function(BenchmarkId::new("naive", size), |bench| {
            bench.iter(|| naive_verify_merkle_proofs(
                &merkle.tree_root,
                &merkle.voting_keys,
                &merkle.branches,
                &merkle.hash_indices));
        });

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| merkle.verify(proof.clone()));
        });
    }
    group.finish();
}

criterion_group!(merkle_group, merkle_bench);
criterion_main!(merkle_group);
