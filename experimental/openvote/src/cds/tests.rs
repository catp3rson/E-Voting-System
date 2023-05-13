// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn cds_test_basic_proof_verification() {
    let cds = super::CDSExample::new(build_options(1), 2).0;
    let (pub_inputs, proof) = cds.prove();
    assert!(cds.verify(proof, pub_inputs).is_ok());
}

#[test]
fn cds_test_basic_proof_verification_quadratic_extension() {
    let cds = Box::new(super::CDSExample::new(build_options(2), 2).0);
    let (pub_inputs, proof) = cds.prove();
    assert!(cds.verify(proof, pub_inputs).is_ok());
}

#[test]
fn cds_test_basic_proof_verification_cubic_extension() {
    let cds = Box::new(super::CDSExample::new(build_options(3), 2).0);
    let (pub_inputs, proof) = cds.prove();
    assert!(cds.verify(proof, pub_inputs).is_ok());
}

#[test]
fn cds_test_basic_proof_verification_fail() {
    let cds = super::CDSExample::new(build_options(1), 2).0;
    let (pub_inputs, proof) = cds.prove();
    let verified = cds.verify_with_wrong_inputs(proof, pub_inputs);
    assert!(verified.is_err());
}

fn build_options(extension: u8) -> ProofOptions {
    ProofOptions::new(
        42,
        8,
        0,
        HashFunction::Blake3_192,
        match extension {
            2 => FieldExtension::Quadratic,
            3 => FieldExtension::Cubic,
            _ => FieldExtension::None,
        },
        4,
        256,
    )
}
