use crate::{
    aggregator::cast::VoteCollector,
    verifier::{verify_cast_proof, verify_register_proof, verify_tally_result},
};
use winterfell::{ByteWriter, Serializable};

use super::{register::*, tally::VoteTallier, AggregatorExample};

#[test]
fn register_test_all_valid() {
    let mut registar = VoterRegistar::get_example(2);
    let register_proof = registar.get_register_proof().unwrap();
    let mut elg_root_bytes = vec![];
    Serializable::write_batch_into(&registar.elg_root, &mut elg_root_bytes);
    let verified = verify_register_proof(&elg_root_bytes, &register_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(verified.unwrap(), "STARK proofs should be valid.")
}

#[test]
fn register_test_wrong_pub_inputs() {
    let mut registar = VoterRegistar::get_example(2);
    let register_proof = registar.get_register_proof_wrong_pub_inputs().unwrap();
    let mut elg_root_bytes = vec![];
    Serializable::write_batch_into(&registar.elg_root, &mut elg_root_bytes);
    let verified = verify_register_proof(&elg_root_bytes, &register_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(
        !verified.unwrap(),
        "One of the STARK proofs should be invalid."
    )
}

#[test]
fn register_test_wrong_stark_proof() {
    let mut registar = VoterRegistar::get_example(2);
    let register_proof = registar.get_register_proof_wrong_stark_proof().unwrap();
    let mut elg_root_bytes = vec![];
    Serializable::write_batch_into(&registar.elg_root, &mut elg_root_bytes);
    let verified = verify_register_proof(&elg_root_bytes, &register_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(
        !verified.unwrap(),
        "One of the STARK proofs should be invalid."
    )
}

#[test]
fn cast_test_all_valid() {
    let mut collector = VoteCollector::get_example(2);
    let cast_proof = collector.get_cast_proof().unwrap();
    let mut voting_keys = vec![];
    voting_keys.write_u8_slice(&(collector.voting_keys.len() as u32).to_be_bytes());
    for voting_key in collector.voting_keys.iter() {
        Serializable::write_batch_into(voting_key, &mut voting_keys);
    }
    let verified = verify_cast_proof(&voting_keys, &cast_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(verified.unwrap(), "STARK proof should be valid.")
}

#[test]
fn cast_test_wrong_pub_inputs() {
    let mut collector = VoteCollector::get_example(2);
    let cast_proof = collector.get_cast_proof_wrong_pub_inputs().unwrap();
    let mut voting_keys = vec![];
    voting_keys.write_u8_slice(&(collector.voting_keys.len() as u32).to_be_bytes());
    for voting_key in collector.voting_keys.iter() {
        Serializable::write_batch_into(voting_key, &mut voting_keys);
    }
    let verified = verify_cast_proof(&voting_keys, &cast_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(!verified.unwrap(), "STARK proof should be invalid.")
}

#[test]
fn cast_test_wrong_stark_proof() {
    let mut collector = VoteCollector::get_example(2);
    let cast_proof = collector.get_cast_proof_wrong_stark_proof().unwrap();
    let mut voting_keys = vec![];
    voting_keys.write_u8_slice(&(collector.voting_keys.len() as u32).to_be_bytes());
    for voting_key in collector.voting_keys.iter() {
        Serializable::write_batch_into(voting_key, &mut voting_keys);
    }
    let verified = verify_cast_proof(&voting_keys, &cast_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(!verified.unwrap(), "STARK proof should be invalid.")
}

#[test]
fn tally_test_all_valid() {
    let (mut tallier, expected_result) = VoteTallier::get_example(2);
    let tally_result = tallier.tally_votes().unwrap();
    let mut encrypted_votes = vec![];
    encrypted_votes.write_u32(tallier.encrypted_votes.len() as u32);
    for encrypted_vote in tallier.encrypted_votes.iter() {
        Serializable::write_batch_into(encrypted_vote, &mut encrypted_votes);
    }
    assert!(
        tally_result == expected_result,
        "Vote tallying result should be correct."
    );
    let verified = verify_tally_result(&encrypted_votes, tally_result);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(verified.unwrap(), "STARK proof should be valid.")
}

#[test]
fn tally_test_wrong_result() {
    let (mut tallier, expected_result) = VoteTallier::get_example(2);
    let tally_result = tallier.tally_votes_wrong_result().unwrap();
    let mut encrypted_votes = vec![];
    encrypted_votes.write_u32(tallier.encrypted_votes.len() as u32);
    for encrypted_vote in tallier.encrypted_votes.iter() {
        Serializable::write_batch_into(encrypted_vote, &mut encrypted_votes);
    }
    assert!(
        tally_result != expected_result,
        "Vote tallying result should be incorrect."
    );
    let verified = verify_tally_result(&encrypted_votes, tally_result);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(!verified.unwrap(), "STARK proof should be invalid.")
}

#[test]
fn aggregator_test_all_valid() {
    let mut aggregator = AggregatorExample::new(2);
    // Voter registration
    let register_proof = aggregator.voter_registar.get_register_proof().unwrap();
    let mut elg_root_bytes = vec![];
    Serializable::write_batch_into(&aggregator.voter_registar.elg_root, &mut elg_root_bytes);
    let verified = verify_register_proof(&elg_root_bytes, &register_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(verified.unwrap(), "Register proofs should be valid.");
    // Vote casting
    let cast_proof = aggregator.vote_collector.get_cast_proof().unwrap();
    let mut voting_keys = vec![];
    voting_keys.write_u8_slice(&(aggregator.vote_collector.voting_keys.len() as u32).to_be_bytes());
    for voting_key in aggregator.vote_collector.voting_keys.iter() {
        Serializable::write_batch_into(voting_key, &mut voting_keys);
    }
    let verified = verify_cast_proof(&voting_keys, &cast_proof);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(verified.unwrap(), "Cast proof should be valid.");
    // Vote tallying
    let tally_result = aggregator.vote_tallier.tally_votes().unwrap();
    let mut encrypted_votes = vec![];
    encrypted_votes.write_u32(aggregator.vote_tallier.encrypted_votes.len() as u32);
    for encrypted_vote in aggregator.vote_tallier.encrypted_votes.iter() {
        Serializable::write_batch_into(encrypted_vote, &mut encrypted_votes);
    }
    let verified = verify_tally_result(&encrypted_votes, tally_result);
    assert!(
        verified.is_ok(),
        "Serialized proof should be deserialized with no error."
    );
    assert!(verified.unwrap(), "Tally result should be valid.")
}
