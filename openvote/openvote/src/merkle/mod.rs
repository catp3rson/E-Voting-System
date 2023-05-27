// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) 2021-2022 Toposware, Inc.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use self::constants::*;
use crate::utils::rescue::{self, Hash, Rescue63};
use core::usize;
use log::debug;
use rand_core::{OsRng, RngCore};
use std::time::Instant;
use winterfell::{
    crypto::Hasher,
    math::{fields::f63::BaseElement, log2, FieldElement},
    FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, Trace, TraceTable,
    VerifierError,
};

pub(crate) mod constants;
mod trace;

mod air;
pub(crate) use air::{MerkleAir, PublicInputs};

mod prover;
pub(crate) use prover::MerkleProver;

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
    /// Root of Merkle tree
    pub tree_root: [BaseElement; DIGEST_SIZE],
    /// List of public keys of which memberships need to be proved
    pub voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// Siblings on the path from public key's leaf to root
    pub branches: Vec<[BaseElement; TREE_DEPTH * DIGEST_SIZE]>,
    /// Hash index to determine the path
    pub hash_indices: Vec<usize>,
}

impl MerkleExample {
    /// create random public keys and a Merkle tree that contains
    /// these keys
    pub fn new(options: ProofOptions, num_keys: usize) -> MerkleExample {
        let (tree_root, voting_keys, branches, hash_indices) = build_merkle_tree(num_keys);

        // verify the Merkle proofs
        #[cfg(feature = "std")]
        let now = Instant::now();

        assert!(naive_verify_merkle_proofs(
            &tree_root,
            &voting_keys,
            &branches,
            &hash_indices,
        ));

        #[cfg(feature = "std")]
        debug!(
            "Verified {} Merkle proofs in {} ms",
            voting_keys.len(),
            now.elapsed().as_millis(),
        );

        MerkleExample {
            options,
            tree_root,
            voting_keys,
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
            self.voting_keys.clone(),
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
            voting_keys: self.voting_keys.clone(),
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_voting_key(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let mut rng = OsRng;
        let fault_index = (rng.next_u32() as usize) % self.voting_keys.len();
        let fault_position = (rng.next_u32() as usize) % AFFINE_POINT_WIDTH;
        let mut pub_inputs = PublicInputs {
            tree_root: self.tree_root.clone(),
            voting_keys: self.voting_keys.clone(),
        };
        pub_inputs.voting_keys[fault_index][fault_position] += BaseElement::ONE;
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_root(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let mut rng = OsRng;
        let fault_position = (rng.next_u32() as usize) % DIGEST_SIZE;
        let mut wrong_tree_root = self.tree_root.clone();
        wrong_tree_root[fault_position] += BaseElement::ONE;
        let pub_inputs = PublicInputs {
            tree_root: wrong_tree_root,
            voting_keys: self.voting_keys.clone(),
        };
        winterfell::verify::<MerkleAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
/// Create a random Merkle tree of public keys
/// and return (tree_root, voting_keys, branches, hash_indices)
fn build_merkle_tree(
    num_keys: usize,
) -> (
    [BaseElement; DIGEST_SIZE],
    Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    Vec<[BaseElement; TREE_DEPTH * DIGEST_SIZE]>,
    Vec<usize>,
) {
    let voting_keys = (0..num_keys)
        .into_iter()
        .map(|_| random_array::<AFFINE_POINT_WIDTH>())
        .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();
    let (tree_root, branches, hash_indices) = build_merkle_tree_from(&voting_keys);
    (tree_root, voting_keys, branches, hash_indices)
}

pub(crate) fn build_merkle_tree_from(
    voting_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
) -> (
    [BaseElement; DIGEST_SIZE],
    Vec<[BaseElement; TREE_DEPTH * DIGEST_SIZE]>,
    Vec<usize>,
) {
    let num_keys = voting_keys.len();
    let mut rng = OsRng;
    let num_leaves = usize::pow(2, TREE_DEPTH as u32);
    let mut leaves = vec![[BaseElement::ZERO; DIGEST_SIZE]; num_leaves];

    let key_hashes = voting_keys
        .iter()
        .map(|voting_key| hash_voting_key(voting_key))
        .collect::<Vec<[BaseElement; DIGEST_SIZE]>>();

    let mut hash_indices = Vec::with_capacity(num_keys);
    while hash_indices.len() < num_keys {
        let hash_index = (rng.next_u32() as usize) % num_leaves;

        if !hash_indices.contains(&hash_index) {
            hash_indices.push(hash_index);
        }
    }

    for index in 0..num_leaves {
        if !hash_indices.contains(&index) {
            leaves[index] = random_array::<DIGEST_SIZE>();
        }
    }

    let mut branches = vec![[BaseElement::ZERO; TREE_DEPTH * DIGEST_SIZE]; num_keys];

    for (&hash_index, key_hash) in hash_indices.iter().zip(key_hashes.into_iter()) {
        leaves[hash_index] = key_hash;
    }

    let tree_root = calculate_merkle_proof(&leaves, &mut branches, &hash_indices, 0);

    (tree_root, branches, hash_indices)
}

/// Naively verify Merkle proofs of membership
pub fn naive_verify_merkle_proofs(
    tree_root: &[BaseElement; DIGEST_SIZE],
    voting_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    branches: &Vec<[BaseElement; TREE_DEPTH * DIGEST_SIZE]>,
    hash_indices: &Vec<usize>,
) -> bool {
    for i in 0..voting_keys.len() {
        if !verify_merlke_proof(tree_root, &voting_keys[i], &branches[i], hash_indices[i]) {
            return false;
        }
    }
    true
}

/// Verify a Merkle proof
#[inline]
pub(crate) fn verify_merlke_proof(
    tree_root: &[BaseElement; DIGEST_SIZE],
    voting_key: &[BaseElement; AFFINE_POINT_WIDTH],
    branch: &[BaseElement; TREE_DEPTH * DIGEST_SIZE],
    hash_index: usize,
) -> bool {
    let mut h = hash_voting_key(&voting_key);

    for i in 0..TREE_DEPTH {
        let hash_bit_index = (hash_index >> i) & 1;
        let mut branch_node = [BaseElement::ZERO; DIGEST_SIZE];
        branch_node.copy_from_slice(&branch[i * DIGEST_SIZE..(i + 1) * DIGEST_SIZE]);
        if hash_bit_index == 0 {
            h = merge_hash(&h, &branch_node);
        } else {
            h = merge_hash(&branch_node, &h);
        }
    }

    h == *tree_root
}

fn calculate_merkle_proof(
    tree: &[[BaseElement; DIGEST_SIZE]],
    branches: &mut Vec<[BaseElement; TREE_DEPTH * DIGEST_SIZE]>,
    hash_indices: &Vec<usize>,
    branch_index: usize,
) -> [BaseElement; DIGEST_SIZE] {
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
            branch[branch_node_index * DIGEST_SIZE..(branch_node_index + 1) * DIGEST_SIZE]
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

fn hash_voting_key(voting_key: &[BaseElement; AFFINE_POINT_WIDTH]) -> [BaseElement; DIGEST_SIZE] {
    let mut hash_message = [BaseElement::ZERO; DIGEST_SIZE];
    hash_message[..POINT_COORDINATE_WIDTH].copy_from_slice(&voting_key[..POINT_COORDINATE_WIDTH]);
    let mut h = Rescue63::digest(&hash_message);
    let message_chunk = rescue::Hash::new(
        voting_key[POINT_COORDINATE_WIDTH],
        voting_key[POINT_COORDINATE_WIDTH + 1],
        voting_key[POINT_COORDINATE_WIDTH + 2],
        voting_key[POINT_COORDINATE_WIDTH + 3],
        voting_key[POINT_COORDINATE_WIDTH + 4],
        voting_key[POINT_COORDINATE_WIDTH + 5],
        BaseElement::ZERO,
    );
    h = Rescue63::merge(&[h, message_chunk]);

    h.to_elements()
}

fn merge_hash(
    left: &[BaseElement; DIGEST_SIZE],
    right: &[BaseElement; DIGEST_SIZE],
) -> [BaseElement; DIGEST_SIZE] {
    let h_left = Hash::new(
        left[0], left[1], left[2], left[3], left[4], left[5], left[6],
    );
    let h_right = Hash::new(
        right[0], right[1], right[2], right[3], right[4], right[5], right[6],
    );
    let h = Rescue63::merge(&[h_left, h_right]);

    h.to_elements()
}
