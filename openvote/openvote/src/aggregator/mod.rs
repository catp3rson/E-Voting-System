use self::{cast::VoteCollector, register::VoterRegistar, tally::VoteTallier};
use winterfell::{FieldExtension, HashFunction, ProofOptions};

/// Module for vote casting phase
pub mod cast;
pub(crate) mod constants;
/// Module for voter registration phase
pub mod register;
/// Module for vote tallying phase
pub mod tally;

#[cfg(test)]
mod tests;

/// Build options to generate all STARK proofs
pub fn build_options(extension: u8) -> ProofOptions {
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

/// Example for a complete set of aggrgator objects
#[derive(Debug)]
pub struct AggregatorExample {
    /// Collect and process registrations of voters
    pub voter_registar: VoterRegistar,
    /// Collect and process encrypted ballots
    pub vote_collector: VoteCollector,
    /// Tally encrypted votes
    pub vote_tallier: VoteTallier,
}

impl AggregatorExample {
    /// Create an instance of type AggregatorExample with random data
    pub fn new(num_voters: usize) -> Self {
        use self::constants::*;
        use crate::{
            cds::{concat_proof_points, encrypt_votes_and_compute_proofs, naive_verify_cds_proofs},
            merkle::build_merkle_tree_from,
            schnorr::{
                naive_verify_signatures, projective_to_elements, random_key_pairs, sign_messages,
            },
            tally::naive_verify_tally_result,
        };
        use rand_core::{OsRng, RngCore};
        use web3::types::Address;
        use winterfell::math::{
            curves::curve_f63::{AffinePoint, ProjectivePoint, Scalar},
            fields::f63::BaseElement,
        };

        assert!(num_voters > 1, "Number of voters must be greater than 1.");
        assert!(
            num_voters.is_power_of_two(),
            "Number of voters must be a power of two."
        );

        let (secret_keys, voting_keys) = random_key_pairs(num_voters);

        // generate Schnorr signatures and Merkle proofs
        let addresses = (0..num_voters)
            .map(|_| Address::random())
            .collect::<Vec<Address>>();
        let signatures = sign_messages(&voting_keys, &addresses, &secret_keys);
        assert!(naive_verify_signatures(
            &voting_keys,
            &addresses,
            &signatures
        ));
        let (elg_root, merkle_branches, hash_indices) = build_merkle_tree_from(&voting_keys);

        let projective_voting_keys = voting_keys
            .iter()
            .map(|&vk| ProjectivePoint::from(AffinePoint::from_raw_coordinates(vk)))
            .collect::<Vec<ProjectivePoint>>();

        // generate encrypted votes and CDS proofs
        // prepare blinding keys and random votes
        let mut blinding_key = ProjectivePoint::identity();
        for &voting_key in projective_voting_keys.iter().skip(1) {
            blinding_key -= voting_key;
        }
        let mut rng = OsRng;
        let mut blinding_keys = Vec::with_capacity(num_voters);
        let mut votes = Vec::with_capacity(num_voters);
        for i in 0..num_voters {
            blinding_keys.push(blinding_key);
            votes.push(rng.next_u32() % 2 == 1);
            if i + 1 < num_voters {
                blinding_key += projective_voting_keys[i];
                blinding_key += projective_voting_keys[i + 1];
            }
        }
        let (encrypted_votes, proof_scalars, proof_points) = encrypt_votes_and_compute_proofs(
            num_voters,
            &secret_keys,
            &projective_voting_keys,
            &blinding_keys,
            &votes,
        );
        assert!(naive_verify_cds_proofs(
            &projective_voting_keys,
            &encrypted_votes,
            &proof_scalars,
            &proof_points
        ));
        let encrypted_votes = encrypted_votes
            .into_iter()
            .map(|p| projective_to_elements(p))
            .collect::<Vec<[BaseElement; AFFINE_POINT_WIDTH]>>();

        let proof_points = proof_points
            .iter()
            .map(|ps| Some(concat_proof_points(ps)))
            .collect::<Vec<Option<[BaseElement; AFFINE_POINT_WIDTH * PROOF_NUM_POINTS]>>>();

        let proof_scalars = proof_scalars
            .iter()
            .map(|&ss| Some(ss))
            .collect::<Vec<Option<[Scalar; PROOF_NUM_SCALARS]>>>();

        // compute tally result
        let tally_result = votes.iter().fold(0u32, |acc, &e| acc + (e as u32));
        assert!(naive_verify_tally_result(&encrypted_votes, tally_result));

        let voter_registar = VoterRegistar {
            elg_root,
            num_elg_voters: num_voters,
            voting_keys: voting_keys.clone(),
            merkle_branches,
            hash_indices,
            signatures,
            addresses,
            dirty_flag: true,
            serialized_proof: vec![],
        };

        let wrapped_encrypted_votes = encrypted_votes
            .clone()
            .into_iter()
            .map(|p| Some(p))
            .collect::<Vec<Option<[BaseElement; AFFINE_POINT_WIDTH]>>>();

        let vote_collector = VoteCollector {
            voting_keys,
            blinding_keys,
            encrypted_votes: wrapped_encrypted_votes,
            proof_points,
            proof_scalars,
            num_valid_votes: num_voters,
            serialized_proof: vec![],
        };

        let vote_tallier = VoteTallier {
            tally_result: Some(tally_result),
            encrypted_votes,
        };

        AggregatorExample {
            voter_registar,
            vote_collector,
            vote_tallier,
        }
    }
}
