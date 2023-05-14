use crate::{cds::hash_message_bytes, utils::ecc};

use super::{air::CDSAir, constants::*, diff_registers};
use bitvec::{order::Lsb0, view::AsBits};
use winterfell::{
    math::{curves::curve_f63::Scalar, fields::f63::BaseElement, FieldElement},
    ProofOptions, Prover, Trace, TraceTable,
};

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;

use super::trace::*;
use super::PublicInputs;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// CDS PROVER
// ================================================================================================

// the voters' public keys are public (known by prover and verifier)
pub struct CDSProver {
    options: ProofOptions,
    // x = g^{x_i}
    voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    // y = h^{x_i} * G^{v_i}, v_i \in {-1, 1}
    encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    // a1, b1, a2, b2
    proof_points: Vec<[BaseElement; PROOF_NUM_POINTS * AFFINE_POINT_WIDTH]>,
    // d1, d2, r1, r2
    proof_scalars: Vec<[Scalar; PROOF_NUM_SCALARS]>,
}

// assume that
impl CDSProver {
    pub fn new(
        options: ProofOptions,
        voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
        encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
        proof_points: Vec<[BaseElement; AFFINE_POINT_WIDTH * PROOF_NUM_POINTS]>,
        proof_scalars: Vec<[Scalar; PROOF_NUM_SCALARS]>,
    ) -> Self {
        Self {
            options,
            voting_keys,
            encrypted_votes,
            proof_points,
            proof_scalars,
        }
    }

    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        let num_proofs = self.voting_keys.len();
        debug_assert!(num_proofs >= 2, "Number of proofs cannot be less than 2.");
        debug_assert!(
            num_proofs.is_power_of_two(),
            "Number of proofs must be a power of 2."
        );
        // allocate memory to hold the trace table
        let trace_length: usize = CDS_CYCLE_LENGTH * num_proofs;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);
        // compute the initial blinding key
        let mut blinding_keys = Vec::with_capacity(num_proofs);
        let mut blinding_key = ecc::IDENTITY;

        for voting_key in self.voting_keys[1..].iter() {
            ecc::compute_add_mixed(&mut blinding_key, &ecc::compute_negation_affine(voting_key));
        }

        for i in 0..num_proofs {
            blinding_keys.push(ecc::reduce_to_affine(&blinding_key));
            if i + 1 < num_proofs {
                ecc::compute_add_mixed(&mut blinding_key, &self.voting_keys[i]);
                ecc::compute_add_mixed(&mut blinding_key, &self.voting_keys[i + 1]);
            }
        }

        trace.fragments(CDS_CYCLE_LENGTH).for_each(|mut cds_trace| {
            // voter index
            let i = cds_trace.index();

            let (encrypted_vote_1, encrypted_vote_2) =
                prepare_encrypted_votes(&self.encrypted_votes[i]);

            let (d1_bytes, d2_bytes, r1_bytes, r2_bytes) =
                decompose_scalars(&self.proof_scalars[i]);
            let d1_bits = d1_bytes.as_bits::<Lsb0>();
            let d2_bits = d2_bytes.as_bits::<Lsb0>();
            let r1_bits = r1_bytes.as_bits::<Lsb0>();
            let r2_bits = r2_bytes.as_bits::<Lsb0>();

            // hash_msg = [i, vk, ev, a1, b1, a2, b2]
            let hash_msg = prepare_hash_message(
                i,
                &self.voting_keys[i],
                &self.encrypted_votes[i],
                &self.proof_points[i],
            );

            let c_bytes = hash_message_bytes(&hash_msg);
            let c_bits = c_bytes.as_bits::<Lsb0>();

            cds_trace.fill(
                |state| {
                    init_cds_verification_state(i, state);
                },
                |step, state| {
                    update_cds_verification_state(
                        step,
                        &hash_msg,
                        &self.voting_keys[i],
                        &blinding_keys[i],
                        &encrypted_vote_1,
                        &encrypted_vote_2,
                        d1_bits,
                        d2_bits,
                        r1_bits,
                        r2_bits,
                        c_bits,
                        state,
                    );
                },
            );
        });
        trace
    }
}

impl Prover for CDSProver {
    type BaseField = BaseElement;
    type Air = CDSAir;
    type Trace = TraceTable<BaseElement>;

    // This method should use the existing trace to extract the public inputs to be given
    // to the verifier.
    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let mut proofs = Vec::with_capacity(self.voting_keys.len());
        let mut outputs = Vec::with_capacity(self.voting_keys.len());

        for i in 0..self.voting_keys.len() {
            // truncate CDS proof
            let mut proof = [BaseElement::ZERO; AFFINE_POINT_WIDTH * 6];
            proof[..AFFINE_POINT_WIDTH].copy_from_slice(&self.voting_keys[i]);
            proof[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2]
                .copy_from_slice(&self.encrypted_votes[i]);
            proof[AFFINE_POINT_WIDTH * 2..].copy_from_slice(&self.proof_points[i]);
            proofs.push(proof);

            // get the output of CDS proof verifications from execution trace
            let mut output = [BaseElement::ZERO; AFFINE_POINT_WIDTH * 5];
            let mut row = [BaseElement::ZERO; TRACE_WIDTH];

            trace.read_row_into(SCALAR_MUL_LENGTH + CDS_CYCLE_LENGTH * i + 1, &mut row);

            // validate a1
            output[..AFFINE_POINT_WIDTH].copy_from_slice(&diff_registers::<AFFINE_POINT_WIDTH>(
                &row[PROJECTIVE_POINT_WIDTH + 1..PROJECTIVE_POINT_WIDTH + AFFINE_POINT_WIDTH + 1],
                &self.proof_points[i][..AFFINE_POINT_WIDTH],
            ));

            // validate b1
            output[AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2].copy_from_slice(&diff_registers::<
                AFFINE_POINT_WIDTH,
            >(
                &row[2 * PROJECTIVE_POINT_WIDTH + 1
                    ..2 * PROJECTIVE_POINT_WIDTH + AFFINE_POINT_WIDTH + 1],
                &self.proof_points[i][AFFINE_POINT_WIDTH..AFFINE_POINT_WIDTH * 2],
            ));

            trace.read_row_into(
                SCALAR_MUL_LENGTH + NROWS_PER_PHASE + CDS_CYCLE_LENGTH * i + 1,
                &mut row,
            );

            // validate a2
            output[AFFINE_POINT_WIDTH * 2..AFFINE_POINT_WIDTH * 3].copy_from_slice(
                &diff_registers::<AFFINE_POINT_WIDTH>(
                    &row[PROJECTIVE_POINT_WIDTH + 1
                        ..PROJECTIVE_POINT_WIDTH + AFFINE_POINT_WIDTH + 1],
                    &self.proof_points[i][AFFINE_POINT_WIDTH * 2..AFFINE_POINT_WIDTH * 3],
                ),
            );

            // validate b2
            output[AFFINE_POINT_WIDTH * 3..AFFINE_POINT_WIDTH * 4].copy_from_slice(
                &diff_registers::<AFFINE_POINT_WIDTH>(
                    &row[2 * PROJECTIVE_POINT_WIDTH + 1
                        ..2 * PROJECTIVE_POINT_WIDTH + AFFINE_POINT_WIDTH + 1],
                    &self.proof_points[i][AFFINE_POINT_WIDTH * 3..AFFINE_POINT_WIDTH * 4],
                ),
            );

            // validate x and z coordinates of (c - d1 - d2) * vk
            output[AFFINE_POINT_WIDTH * 4..AFFINE_POINT_WIDTH * 4 + POINT_COORDINATE_WIDTH]
                .copy_from_slice(&row[..POINT_COORDINATE_WIDTH]);
            output[AFFINE_POINT_WIDTH * 4 + POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH * 5]
                .copy_from_slice(&row[AFFINE_POINT_WIDTH..PROJECTIVE_POINT_WIDTH]);

            outputs.push(output);
        }

        PublicInputs { proofs, outputs }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}
