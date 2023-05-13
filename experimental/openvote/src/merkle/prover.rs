// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::{
    schnorr::constants::{AFFINE_POINT_WIDTH, POINT_COORDINATE_WIDTH},
    utils::rescue::RATE_WIDTH,
};

use super::{
    constants::{MERKLE_CYCLE_LENGTH, TRACE_WIDTH, TREE_DEPTH},
    trace::{init_merkle_verification_state, update_merkle_verification_state},
    BaseElement, FieldElement, MerkleAir, ProofOptions, Prover, PublicInputs, TraceTable,
};

// MERKLE PROVER
// ================================================================================================

pub struct MerkleProver {
    options: ProofOptions,
    tree_root: [BaseElement; RATE_WIDTH],
    voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
}

impl MerkleProver {
    pub fn new(
        options: ProofOptions,
        tree_root: [BaseElement; RATE_WIDTH],
        voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    ) -> Self {
        Self {
            options,
            tree_root,
            voting_keys,
        }
    }

    pub fn build_trace(
        &self,
        // contains the siblings of the nodes on the path
        // from root to corresponding public key
        branches: Vec<[BaseElement; TREE_DEPTH * RATE_WIDTH]>,
        hash_indices: Vec<usize>,
    ) -> TraceTable<BaseElement> {
        debug_assert!(
            branches.len().is_power_of_two(),
            "Number of Merkle proofs to verify must be a power of two."
        );
        // allocate memory to hold the trace table
        let trace_length = branches.len() * MERKLE_CYCLE_LENGTH;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        trace
            .fragments(MERKLE_CYCLE_LENGTH)
            .for_each(|mut merkle_trace| {
                let i = merkle_trace.index();

                let hash_index = hash_indices[i] << 1;
                let voting_key = self.voting_keys[i];
                let mut hash_message = [BaseElement::ZERO; (TREE_DEPTH + 1) * RATE_WIDTH];
                hash_message[..POINT_COORDINATE_WIDTH]
                    .copy_from_slice(&voting_key[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH]);
                hash_message[RATE_WIDTH..].copy_from_slice(&branches[i]);

                merkle_trace.fill(
                    |state| {
                        init_merkle_verification_state(&voting_key, state);
                    },
                    |step, state| {
                        update_merkle_verification_state(step, &hash_message, hash_index, state);
                    },
                );
            });

        trace
    }
}

impl Prover for MerkleProver {
    type BaseField = BaseElement;
    type Air = MerkleAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        PublicInputs {
            tree_root: self.tree_root,
            voting_keys: self.voting_keys.clone(),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
