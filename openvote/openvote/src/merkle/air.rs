// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) 2021-2022 Toposware, Inc.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::constants::*;
use super::{BaseElement, FieldElement};
use crate::utils::{field, is_binary, not, rescue, EvaluationResult};
use winterfell::{
    Air, AirContext, Assertion, ByteReader, ByteWriter, Deserializable, DeserializationError,
    EvaluationFrame, ProofOptions, Serializable, SliceReader, TraceInfo,
    TransitionConstraintDegree,
};

// MERKLE PATH VERIFICATION AIR
// ================================================================================================

pub struct PublicInputs {
    pub tree_root: [BaseElement; DIGEST_SIZE],
    pub voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        Serializable::write_batch_into(&self.tree_root, target);
        target.write_u32(self.voting_keys.len() as u32);
        for voting_key in self.voting_keys.iter() {
            Serializable::write_batch_into(voting_key, target);
        }
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut tree_root = [BaseElement::ZERO; DIGEST_SIZE];
        tree_root.copy_from_slice(&BaseElement::read_batch_from(source, DIGEST_SIZE)?);
        let num_voters = source.read_u32()? as usize;
        let mut voting_keys = Vec::with_capacity(num_voters);
        let mut voting_key = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
        for _ in 0..num_voters {
            voting_key.copy_from_slice(&BaseElement::read_batch_from(source, AFFINE_POINT_WIDTH)?);
            voting_keys.push(voting_key);
        }
        Ok(Self {
            tree_root,
            voting_keys,
        })
    }
}

impl PublicInputs {
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        let mut source = SliceReader::new(source);
        Self::read_from(&mut source)
    }
}

pub struct MerkleAir {
    context: AirContext<BaseElement>,
    tree_root: [BaseElement; DIGEST_SIZE],
    voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
}

impl Air for MerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = transition_constraint_degrees();
        assert_eq!(TRACE_WIDTH, trace_info.width());
        MerkleAir {
            context: AirContext::new(trace_info, degrees, options),
            tree_root: pub_inputs.tree_root,
            voting_keys: pub_inputs.voting_keys,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 4 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into masks and Rescue round constants
        let hash_flag = periodic_values[0];
        let cycle_mask = periodic_values[1];
        let ark = &periodic_values[2..];

        // when hash_flag = 1, constraints for Rescue round are enforced
        rescue::enforce_round(
            &mut result[1..HASH_STATE_WIDTH + 1],
            &current[1..HASH_STATE_WIDTH + 1],
            &next[1..HASH_STATE_WIDTH + 1],
            ark,
            cycle_mask * hash_flag,
        );

        // when hash_flag = 0, make sure accumulated hash is placed in the right place in the hash
        // state for the next round of hashing.
        let hash_init_flag = cycle_mask * not(hash_flag);
        let hash_index_bit = next[0];

        // ensure that index bit is binary
        result.agg_constraint(0, hash_init_flag, is_binary(hash_index_bit));

        // if index bit = 0, accumulated hash remains unchanged.
        field::enforce_copy::<HASH_RATE_WIDTH, E>(
            &mut result[1..HASH_RATE_WIDTH + 1],
            &current[1..HASH_RATE_WIDTH + 1],
            &next[1..HASH_RATE_WIDTH + 1],
            hash_init_flag * not(hash_index_bit),
        );

        // if index bit = 1, accumulated hash is stored in capacity registers.
        field::enforce_copy::<HASH_RATE_WIDTH, E>(
            &mut result[HASH_RATE_WIDTH + 1..HASH_STATE_WIDTH + 1],
            &current[1..HASH_RATE_WIDTH + 1],
            &next[HASH_RATE_WIDTH + 1..HASH_STATE_WIDTH + 1],
            hash_init_flag * hash_index_bit,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = vec![];

        // START OF TRACE
        // ensure that the hash pf public key is initiated correctly
        for (key_index, voting_key) in self.voting_keys.iter().enumerate() {
            for i in 0..POINT_COORDINATE_WIDTH {
                assertions.push(Assertion::single(
                    i + 1,
                    key_index * MERKLE_CYCLE_LENGTH,
                    voting_key[i],
                ));
                assertions.push(Assertion::single(
                    i + HASH_RATE_WIDTH + 1,
                    key_index * MERKLE_CYCLE_LENGTH + HASH_CYCLE_LENGTH,
                    voting_key[i + POINT_COORDINATE_WIDTH],
                ));
            }
            for i in POINT_COORDINATE_WIDTH + 1..HASH_STATE_WIDTH + 1 {
                assertions.push(Assertion::single(
                    i,
                    key_index * MERKLE_CYCLE_LENGTH,
                    BaseElement::ZERO,
                ));
            }
            assertions.push(Assertion::single(
                0,
                key_index * MERKLE_CYCLE_LENGTH + HASH_CYCLE_LENGTH,
                BaseElement::ZERO,
            ));
        }

        // END OF TRACE
        let last_cycle_step = MERKLE_CYCLE_LENGTH - 1;

        for i in 0..HASH_RATE_WIDTH {
            assertions.push(Assertion::periodic(
                i + 1,
                last_cycle_step,
                MERKLE_CYCLE_LENGTH,
                self.tree_root[i],
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![rescue::HASH_CYCLE_MASK.to_vec()];
        let mut cycle_mask = vec![BaseElement::ONE; MERKLE_CYCLE_LENGTH];
        cycle_mask[MERKLE_CYCLE_LENGTH - 1] = BaseElement::ZERO;
        result.push(cycle_mask);
        result.append(&mut rescue::get_round_constants());
        result
    }
}

pub(crate) fn transition_constraint_degrees() -> Vec<TransitionConstraintDegree> {
    // First scalar multiplication
    let mut degrees = vec![TransitionConstraintDegree::with_cycles(
        2,
        vec![HASH_CYCLE_LENGTH, MERKLE_CYCLE_LENGTH],
    )];
    degrees.append(&mut vec![
        TransitionConstraintDegree::with_cycles(
            3,
            vec![HASH_CYCLE_LENGTH, MERKLE_CYCLE_LENGTH]
        );
        TRACE_WIDTH - 1
    ]);

    degrees
}
