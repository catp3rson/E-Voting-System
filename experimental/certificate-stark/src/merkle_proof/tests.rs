// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) 2021-2022 Toposware, Inc.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{FieldExtension, HashFunction, ProofOptions};

#[test]
fn merkle_test_basic_proof_verification() {
    let merkle = super::MerkleExample::new(build_options(1), 8);
    let proof = merkle.prove();
    let res = merkle.verify(proof);
    println!("{:?}", res.unwrap());
}

#[test]
fn merkle_test_basic_proof_verification_quadratic_extension() {
    let merkle = Box::new(super::MerkleExample::new(build_options(2), 8));
    let proof = merkle.prove();
    assert!(merkle.verify(proof).is_ok());
}

#[test]
fn merkle_test_basic_proof_verification_cubic_extension() {
    let merkle = Box::new(super::MerkleExample::new(build_options(3), 8));
    let proof = merkle.prove();
    assert!(merkle.verify(proof).is_ok());
}

#[test]
fn merkle_test_basic_proof_verification_fail() {
    let merkle = super::MerkleExample::new(build_options(1), 8);
    let proof = merkle.prove();
    let verified = merkle.verify_with_wrong_inputs(proof);
    assert!(verified.is_err());
}


fn build_options(extension: u8) -> ProofOptions {
    ProofOptions::new(
        42,
        8,
        0,
        HashFunction::Blake3_256,
        match extension {
            2 => FieldExtension::Quadratic,
            3 => FieldExtension::Cubic,
            _ => FieldExtension::None,
        },
        4,
        256,
    )
}

