// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) 2021-2022 Toposware, Inc.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::schnorr::constants::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH};
use crate::utils::rescue::{self, RATE_WIDTH};
use crate::utils::rescue::{Hash, Rescue63};
use core::usize;
use log::debug;
use rand_core::{OsRng, RngCore};
use std::time::Instant;
use winterfell::crypto::Hasher;
use winterfell::{
    math::{fields::f63::BaseElement, log2, FieldElement},
    FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, Trace, TraceTable,
    VerifierError,
};

pub(crate) mod constants;
mod trace;

mod air;
use air::{MerkleAir, PublicInputs};

mod prover;
pub(crate) use prover::MerkleProver;

use self::constants::TREE_DEPTH;

#[cfg(test)]
mod tests;

/// Outputs a new `MerkleExample` with `num_keys` Merkle proofs of membership on random public keys.
pub fn get_example(num_keys: usize) -> MerkleExample {
    MerkleExample::new(
        ProofOptions::new(
            42,
            8,
            0,
            HashFunction::Blake3_192,
            FieldExtension::None,
            4,
            256,
        ),
        num_keys,
    )
}

/// Merkle example
#[derive(Clone, Debug)]
pub struct MerkleExample {
    options: ProofOptions,
    tree_root: [BaseElement; RATE_WIDTH],
    public_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    branches: Vec<[BaseElement; TREE_DEPTH * RATE_WIDTH]>,
    hash_indices: Vec<usize>,
}

impl MerkleExample {
    /// create random public keys and a Merkle tree that contains
    /// these keys
    pub fn new(options: ProofOptions, num_keys: usize) -> MerkleExample {
        let (tree_root, public_keys, branches, hash_indices) = build_merkle_tree(num_keys);

        // verify the Merkle proofs
        #[cfg(feature = "std")]
        let now = Instant::now();

        assert!(naive_verify_merkle_proofs(
            &tree_root,
            &public_keys,
            &branches,
            &hash_indices,
        ));

        #[cfg(feature = "std")]
        debug!(
            "Verified {} Merkle proofs in {} ms",
            public_keys.len(),
            now.elapsed().as_millis(),
        );

        MerkleExample {
            options,
            tree_root,
            public_keys,
            branches,
            hash_indices,
        }
    }

    /// Generate STARK proof for verification of Merkle proof of membership
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for proving membership in a Merkle tree of depth {}\n\
            ---------------------",
            TREE_DEPTH
        );
        // create the prover
        let prover = MerkleProver::new(
            self.options.clone(),
            self.tree_root,
            self.public_keys.clone(),
        );

        // generate the execution trace
        let now = Instant::now();
        let trace = prover.build_trace(self.branches.clone(), self.hash_indices.clone());

        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

    /// Verify with correct inputs
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            tree_root: self.tree_root.clone(),
            public_keys: self.public_keys.clone(),
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let mut rng = OsRng;
        let fault_index = (rng.next_u32() as usize) % self.public_keys.len();
        let fault_position = (rng.next_u32() as usize) % AFFINE_POINT_WIDTH;
        let mut pub_inputs = PublicInputs {
            tree_root: self.tree_root.clone(),
            public_keys: self.public_keys.clone(),
        };
        pub_inputs.public_keys[fault_index][fault_position] += BaseElement::ONE;
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
/// Create a random Merkle tree of public keys
/// and return (tree_root, public_keys, branches, hash_indices)
fn build_merkle_tree(
    num_keys: usize,
) -> (
    [BaseElement; RATE_WIDTH],
    Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    Vec<[BaseElement; TREE_DEPTH * RATE_WIDTH]>,
    Vec<usize>,
) {
    let num_leaves = usize::pow(2, TREE_DEPTH as u32);
    let mut leaves = vec![[BaseElement::ZERO; RATE_WIDTH]; num_leaves];
    let mut rng = OsRng;

    let public_keys = (0..num_keys)
        .into_iter()
        .map(|_| random_array::<AFFINE_POINT_WIDTH>())
        .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();

    let key_hashes = public_keys
        .iter()
        .map(|public_key| hash_public_key(public_key))
        .collect::<Vec<[BaseElement; RATE_WIDTH]>>();

    let mut hash_indices = Vec::with_capacity(num_keys);
    while hash_indices.len() < num_keys {
        let hash_index = (rng.next_u32() as usize) % num_leaves;

        if !hash_indices.contains(&hash_index) {
            hash_indices.push(hash_index);
        }
    }

    for index in 0..num_leaves {
        if !hash_indices.contains(&index) {
            leaves[index] = random_array::<RATE_WIDTH>();
        }
    }

    let mut branches = vec![[BaseElement::ZERO; TREE_DEPTH * RATE_WIDTH]; num_keys];

    for (&hash_index, key_hash) in hash_indices.iter().zip(key_hashes.into_iter()) {
        leaves[hash_index] = key_hash;
    }

    let tree_root = calculate_merkle_proof(&leaves, &mut branches, &hash_indices, 0);

    (tree_root, public_keys, branches, hash_indices)
}

/// Naively verify Merkle proofs of membership
fn naive_verify_merkle_proofs(
    tree_root: &[BaseElement; RATE_WIDTH],
    public_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    branches: &Vec<[BaseElement; TREE_DEPTH * RATE_WIDTH]>,
    hash_indices: &Vec<usize>,
) -> bool {
    for i in 0..public_keys.len() {
        let public_key = public_keys[i];
        let branch = branches[i];
        let hash_index = hash_indices[i];
        let mut h = hash_public_key(&public_key);

        for j in 0..TREE_DEPTH {
            let hash_bit_index = (hash_index >> j) & 1;
            let mut branch_node = [BaseElement::ZERO; RATE_WIDTH];
            branch_node.copy_from_slice(&branch[j * RATE_WIDTH..(j + 1) * RATE_WIDTH]);

            if hash_bit_index == 0 {
                h = merge_hash(&h, &branch_node);
            } else {
                h = merge_hash(&branch_node, &h);
            }
        }

        if h != *tree_root {
            return false;
        }
    }

    true
}

fn calculate_merkle_proof(
    tree: &[[BaseElement; RATE_WIDTH]],
    branches: &mut Vec<[BaseElement; TREE_DEPTH * RATE_WIDTH]>,
    hash_indices: &Vec<usize>,
    branch_index: usize,
) -> [BaseElement; RATE_WIDTH] {
    if tree.len() == 1 {
        return tree[0];
    }

    let half_length = tree.len() / 2;
    let branch_node_index = log2(half_length) as usize;
    let left = calculate_merkle_proof(
        &tree[..half_length],
        branches,
        hash_indices,
        branch_index << 1,
    );
    let right = calculate_merkle_proof(
        &tree[half_length..],
        branches,
        hash_indices,
        (branch_index << 1) + 1,
    );

    for (branch, &hash_index) in branches.iter_mut().zip(hash_indices.iter()) {
        let hash_index = hash_index >> branch_node_index;
        if hash_index >> 1 == branch_index {
            let bit_index = hash_index & 1;
            branch[branch_node_index * RATE_WIDTH..(branch_node_index + 1) * RATE_WIDTH]
                .copy_from_slice(if bit_index == 0 { &right } else { &left });
        }
    }

    merge_hash(&left, &right)
}

/// Generate a random array of length NREGS
fn random_array<const NREGS: usize>() -> [BaseElement; NREGS] {
    let mut point = [BaseElement::ZERO; NREGS];
    let mut rng = OsRng;
    for i in 0..NREGS {
        point[i] = BaseElement::from(rng.next_u64());
    }

    point
}

fn hash_public_key(public_key: &[BaseElement; AFFINE_POINT_WIDTH]) -> [BaseElement; RATE_WIDTH] {
    let mut hash_message = [BaseElement::ZERO; RATE_WIDTH];
    hash_message[..POINT_COORDINATE_WIDTH].copy_from_slice(&public_key[..POINT_COORDINATE_WIDTH]);
    let mut h = Rescue63::digest(&hash_message);
    let message_chunk = rescue::Hash::new(
        public_key[POINT_COORDINATE_WIDTH],
        public_key[POINT_COORDINATE_WIDTH + 1],
        public_key[POINT_COORDINATE_WIDTH + 2],
        public_key[POINT_COORDINATE_WIDTH + 3],
        public_key[POINT_COORDINATE_WIDTH + 4],
        public_key[POINT_COORDINATE_WIDTH + 5],
        BaseElement::ZERO,
    );
    h = Rescue63::merge(&[h, message_chunk]);

    h.to_elements()
}

fn merge_hash(
    left: &[BaseElement; RATE_WIDTH],
    right: &[BaseElement; RATE_WIDTH],
) -> [BaseElement; RATE_WIDTH] {
    let h_left = Hash::new(
        left[0], left[1], left[2], left[3], left[4], left[5], left[6],
    );
    let h_right = Hash::new(
        right[0], right[1], right[2], right[3], right[4], right[5], right[6],
    );
    let h = Rescue63::merge(&[h_left, h_right]);

    h.to_elements()
}
