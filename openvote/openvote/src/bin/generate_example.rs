use openvote::{
    aggregator::AggregatorExample,
    verifier::{verify_cast_proof, verify_register_proof, verify_tally_result, constants::GENERATOR},
};
use winterfell::{Serializable, ByteWriter};
use std::{
    fs::{File, create_dir},
    io::prelude::*,
    env,
};

fn main() {
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
    assert!(verified.unwrap(), "Tally result should be valid.");

    // create directory to write files
    let args: Vec<String> = env::args().collect();
    let dir_name = &args[1];
    println!("Writing example data to directory {}.", dir_name);
    create_dir(dir_name).expect("create failed");

    // write generator
    let mut generator_bytes = vec![];
    Serializable::write_batch_into(&GENERATOR, &mut generator_bytes);
    let mut file = File::create(format!("{}/generator.dat", dir_name)).expect("create failed");
    file.write_all(&generator_bytes).expect("write failed");

    // write Merkle root
    let mut file = File::create(format!("{}/elg_root.dat", dir_name)).expect("create failed");
    file.write_all(&elg_root_bytes).expect("write failed");

    // write truncated register proof to file
    let mut file = File::create(format!("{}/truncated_register_proof.dat", dir_name)).expect("create failed");
    file.write_all(&register_proof).expect("write failed");

    // write extended register proof to file (| selector | elg_root | register_proof |)
    let mut ext_register_proof = vec![];
    ext_register_proof.write_u8_slice(&[243, 90, 41, 19]);
    Serializable::write_batch_into(&aggregator.voter_registar.elg_root, &mut ext_register_proof);
    ext_register_proof.write_u8_slice(&register_proof);
    let mut file = File::create(format!("{}/register_proof.dat", dir_name)).expect("create failed");
    file.write_all(&ext_register_proof).expect("write failed");

    // write truncated cast proof to file
    let mut file = File::create(format!("{}/truncated_cast_proof.dat", dir_name)).expect("create failed");
    file.write_all(&cast_proof).expect("write failed");

    // write extended cast proof to file
    let mut ext_cast_proof = vec![];
    ext_cast_proof.write_u8_slice(&[199, 65, 76, 236]);
    ext_cast_proof.write_u8_slice(&(aggregator.vote_collector.num_valid_votes as u32).to_be_bytes());
    for voting_key in aggregator.vote_collector.voting_keys.iter() {
        Serializable::write_batch_into(voting_key, &mut ext_cast_proof);
    }
    ext_cast_proof.write_u8_slice(&cast_proof);
    let mut file = File::create(format!("{}/cast_proof.dat", dir_name)).expect("create failed");
    file.write_all(&ext_cast_proof).expect("write failed");

    // write tally result to file
    let tally_result_bytes = tally_result.to_be_bytes();
    let mut file = File::create(format!("{}/tally_result.dat", dir_name)).expect("create failed");
    file.write_all(&tally_result_bytes).expect("write failed");
}