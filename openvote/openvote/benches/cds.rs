// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use openvote::cds::{get_example, naive_verify_cds_proofs};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

const SIZES: [usize; 5] = [8, 16, 32, 64, 128];

fn cds_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("cds");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(400));

    for &size in SIZES.iter() {
        let (cds, (voting_keys, encrypted_votes, proof_scalars, proof_points)) = get_example(size);
        
        group.bench_function(BenchmarkId::new("prove", size), |bench| {
            bench.iter(|| cds.prove());
        });

        let (pub_inputs, proof) = cds.prove();

        println!("Proof size for cds/prove/{}: {} bytes", size, proof.to_bytes().len());

        group.bench_function(BenchmarkId::new("naive", size), |bench| {
            bench.iter(|| naive_verify_cds_proofs(
                &voting_keys, &encrypted_votes, &proof_scalars, &proof_points
            ));
        });

        group.bench_function(BenchmarkId::new("verify", size), |bench| {
            bench.iter(|| cds.verify(proof.clone(), pub_inputs.clone()));
        });
    }
    group.finish();
}

criterion_group!(cds_group, cds_bench);
criterion_main!(cds_group);
