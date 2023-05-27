// Copyright (c) 2021-2022 Toposware, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use self::constants::*;
use super::utils::{
    ecc, field,
    rescue::{self, Rescue63},
};
use bitvec::{order::Lsb0, view::AsBits};
use rand_core::OsRng;
use web3::types::Address;
use winterfell::{
    crypto::Hasher,
    math::{
        curves::curve_f63::{AffinePoint, ProjectivePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement,
    },
    FieldExtension, HashFunction, ProofOptions, Prover, StarkProof, VerifierError,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use std::time::Instant;
#[cfg(feature = "std")]
use winterfell::{math::log2, Trace};

pub(crate) mod constants;
mod trace;

mod air;
pub(crate) use air::{PublicInputs, SchnorrAir};

mod prover;
pub(crate) use prover::SchnorrProver;

#[cfg(test)]
mod tests;

// SCHNORR SIGNATURE EXAMPLE
// ================================================================================================

/// Outputs a new `SchnorrExample` with `num_signatures` signatures on random messages.
pub fn get_example(num_signatures: usize) -> SchnorrExample {
    SchnorrExample::new(
        // TODO: make it customizable
        ProofOptions::new(
            42,
            8,
            0,
            HashFunction::Blake3_192,
            FieldExtension::None,
            4,
            256,
        ),
        num_signatures,
    )
}

/// A struct to perform Schnorr signature valid
/// verification proof among a set of signed messages.
#[derive(Clone, Debug)]
pub struct SchnorrExample {
    options: ProofOptions,
    /// Voting keys
    pub voting_keys: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// Ethereum addresses
    pub addresses: Vec<Address>,
    /// Schnorr signatures
    pub signatures: Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
}

impl SchnorrExample {
    /// Outputs a new `SchnorrExample` with `num_signatures` signatures on random messages.
    pub fn new(options: ProofOptions, num_signatures: usize) -> SchnorrExample {
        let (secret_keys, voting_keys) = random_key_pairs(num_signatures);
        let addresses = (0..num_signatures)
            .map(|_| Address::random())
            .collect::<Vec<Address>>();

        // compute the Schnorr signatures
        #[cfg(feature = "std")]
        let now = Instant::now();

        let signatures = sign_messages(&voting_keys, &addresses, &secret_keys);

        #[cfg(feature = "std")]
        debug!(
            "Computed {} Schnorr signatures in {} ms",
            num_signatures,
            now.elapsed().as_millis(),
        );

        // verify the Schnorr signatures
        #[cfg(feature = "std")]
        let now = Instant::now();

        assert!(naive_verify_signatures(
            &voting_keys,
            &addresses,
            &signatures
        ));

        #[cfg(feature = "std")]
        debug!(
            "Verified {} Schnorr signatures in {} ms",
            num_signatures,
            now.elapsed().as_millis(),
        );

        SchnorrExample {
            options,
            voting_keys,
            addresses,
            signatures,
        }
    }

    /// Proves the validity of a sequence of Schnorr signatures
    pub fn prove(&self) -> StarkProof {
        // generate the execution trace
        #[cfg(feature = "std")]
        debug!(
            "Generating proof for verifying {} Schnorr signatures\n\
            ---------------------",
            self.voting_keys.len(),
        );

        let prover = SchnorrProver::new(
            self.options.clone(),
            self.voting_keys.clone(),
            self.addresses.clone(),
            self.signatures.clone(),
        );

        // generate the execution trace
        #[cfg(feature = "std")]
        let now = Instant::now();
        let trace = prover.build_trace();
        #[cfg(feature = "std")]
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace.length()),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

    /// Verifies the validity of a proof of correct Schnorr signature verification
    pub fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            voting_keys: self.voting_keys.clone(),
            addresses: self.addresses.clone(),
            signatures: self.signatures.clone(),
        };
        winterfell::verify::<SchnorrAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_message(&self, proof: StarkProof) -> Result<(), VerifierError> {
        use rand_core::RngCore;

        let mut pub_inputs = PublicInputs {
            voting_keys: self.voting_keys.clone(),
            addresses: self.addresses.clone(),
            signatures: self.signatures.clone(),
        };
        let mut rng = OsRng;

        if rng.next_u32() % 2 == 0 {
            // Wrong voting key
            let fault_index = (rng.next_u32() as usize) % self.voting_keys.len();
            let fault_position = (rng.next_u32() as usize) % AFFINE_POINT_WIDTH;
            pub_inputs.voting_keys[fault_index][fault_position] += BaseElement::ONE;
        } else {
            // Wrong addresses
            let fault_index = (rng.next_u32() as usize) % self.addresses.len();
            let fault_position = (rng.next_u32() as usize) % Address::len_bytes();
            let mut wrong_address = *pub_inputs.addresses[fault_index].as_fixed_bytes();
            wrong_address[fault_position] ^= 1;
            pub_inputs.addresses[fault_index] = Address::from_slice(&wrong_address);
        }
        winterfell::verify::<SchnorrAir>(proof, pub_inputs)
    }

    #[cfg(test)]
    fn verify_with_wrong_signature(&self, proof: StarkProof) -> Result<(), VerifierError> {
        use rand_core::RngCore;

        let mut rng = OsRng;
        let fault_index = (rng.next_u32() as usize) % self.signatures.len();
        let fault_position = (rng.next_u32() as usize) % self.signatures[0].0.len();
        let mut wrong_signatures = self.signatures.clone();
        wrong_signatures[fault_index].0[fault_position] += BaseElement::ONE;
        let pub_inputs = PublicInputs {
            voting_keys: self.voting_keys.clone(),
            addresses: self.addresses.clone(),
            signatures: wrong_signatures,
        };
        winterfell::verify::<SchnorrAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes a Schnorr signature
pub(crate) fn sign_messages(
    voting_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    addresses: &Vec<Address>,
    secret_keys: &Vec<Scalar>,
) -> Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)> {
    let mut rng = OsRng;
    let mut signatures = Vec::with_capacity(voting_keys.len());

    for i in 0..voting_keys.len() {
        let r = Scalar::random(&mut rng);
        let r_point = AffinePoint::from(AffinePoint::generator() * r);
        let message = prepare_message(&voting_keys[i], addresses[i]);
        let h = hash_message(&r_point.get_x(), &message);
        let mut h_bytes = [0u8; 32];
        // take the first 4 elements of the hash
        for (i, h_word) in h.iter().enumerate().take(4) {
            h_bytes[8 * i..8 * i + 8].copy_from_slice(&h_word.to_bytes());
        }
        let h_bits = h_bytes.as_bits::<Lsb0>();

        // Reconstruct a scalar from the binary sequence of h
        let h_scalar = Scalar::from_bits(h_bits);

        let s = r - secret_keys[i] * h_scalar;
        signatures.push((r_point.get_x(), s))
    }

    signatures
}

/// Naively verify Schnorr signatures
pub fn naive_verify_signatures(
    voting_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    addresses: &Vec<Address>,
    signatures: &Vec<([BaseElement; POINT_COORDINATE_WIDTH], Scalar)>,
) -> bool {
    for i in 0..voting_keys.len() {
        if !verify_signature(voting_keys[i], addresses[i], signatures[i]) {
            return false;
        }
    }
    true
}

/// Verify a Schnorr signature
#[inline]
pub(crate) fn verify_signature(
    voting_key: [BaseElement; AFFINE_POINT_WIDTH],
    address: Address,
    signature: ([BaseElement; POINT_COORDINATE_WIDTH], Scalar),
) -> bool {
    let s_point = AffinePoint::generator() * signature.1;
    let message = prepare_message(&voting_key, address);
    let voting_key = AffinePoint::from_raw_coordinates(voting_key);
    assert!(voting_key.is_on_curve());
    let h = hash_message(&signature.0, &message);
    let mut h_bytes = [0u8; 32];
    for (i, h_word) in h.iter().enumerate().take(4) {
        h_bytes[8 * i..8 * i + 8].copy_from_slice(&h_word.to_bytes());
    }
    let h_bits = h_bytes.as_bits::<Lsb0>();
    // Reconstruct a scalar from the binary sequence of h
    let h_scalar = Scalar::from_bits(h_bits);
    let h_pubkey_point = voting_key * h_scalar;
    let r_point = AffinePoint::from(s_point + h_pubkey_point);
    r_point.get_x() == signature.0
}

pub(crate) fn random_key_pairs(
    num_pairs: usize,
) -> (Vec<Scalar>, Vec<[BaseElement; AFFINE_POINT_WIDTH]>) {
    let mut rng = OsRng;
    let secret_keys = (0..num_pairs)
        .map(|_| Scalar::random(&mut rng))
        .collect::<Vec<Scalar>>();
    let voting_keys = secret_keys
        .iter()
        .map(|&s| projective_to_elements(ProjectivePoint::generator() * s))
        .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();
    (secret_keys, voting_keys)
}

#[inline]
pub(crate) fn projective_to_elements(point: ProjectivePoint) -> [BaseElement; AFFINE_POINT_WIDTH] {
    let mut result = [BaseElement::ZERO; AFFINE_POINT_WIDTH];
    result[..POINT_COORDINATE_WIDTH].copy_from_slice(&AffinePoint::from(point).get_x());
    result[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH]
        .copy_from_slice(&AffinePoint::from(point).get_y());
    result
}

/// Prepare messages that voters need to sign based
/// on addresses and voting keys
#[inline]
pub(crate) fn prepare_messages(
    voting_keys: &Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    addresses: &Vec<Address>,
) -> Vec<[BaseElement; MSG_LENGTH]> {
    let mut messages = Vec::with_capacity(MSG_LENGTH);

    for i in 0..voting_keys.len() {
        messages.push(prepare_message(&voting_keys[i], addresses[i]));
    }

    messages
}

#[inline]
pub(crate) fn prepare_message(
    voting_key: &[BaseElement; AFFINE_POINT_WIDTH],
    address: Address,
) -> [BaseElement; MSG_LENGTH] {
    let mut message = [BaseElement::ZERO; MSG_LENGTH];
    // Voting key
    message[..AFFINE_POINT_WIDTH].copy_from_slice(voting_key);
    // Ethereum address
    let address_bytes = address.as_bytes();
    for i in (0..20).step_by(5) {
        message[AFFINE_POINT_WIDTH + (i / 5)] = BaseElement::from(u64::from_be_bytes([
            address_bytes[i],
            address_bytes[i + 1],
            address_bytes[i + 2],
            address_bytes[i + 3],
            address_bytes[i + 4],
            0,
            0,
            0,
        ]));
    }
    message
}

fn hash_message(
    input: &[BaseElement; POINT_COORDINATE_WIDTH],
    message: &[BaseElement; MSG_LENGTH],
) -> [BaseElement; HASH_RATE_WIDTH] {
    let mut h = Rescue63::digest(input);
    let mut message_chunk = rescue::Hash::new(
        message[0], message[1], message[2], message[3], message[4], message[5], message[6],
    );
    h = Rescue63::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(
        message[7],
        message[8],
        message[9],
        message[10],
        message[11],
        message[12],
        message[13],
    );
    h = Rescue63::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(
        message[14],
        message[15],
        message[16],
        message[17],
        message[18],
        message[19],
        message[20],
    );
    h = Rescue63::merge(&[h, message_chunk]);
    message_chunk = rescue::Hash::new(
        message[21],
        message[22],
        message[23],
        message[24],
        message[25],
        message[26],
        message[27],
    );
    h = Rescue63::merge(&[h, message_chunk]);

    h.to_elements()
}
