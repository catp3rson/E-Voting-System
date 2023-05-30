use crate::{Error, Precompile, PrecompileAddress, PrecompileResult, StandardPrecompileFn};
use openvote::{
    verifier::{
        verify_register_proof, verify_cast_proof, verify_tally_result,
        constants::*,
    },
};
use winterfell::{math::fields::f63::BaseElement, Deserializable, SliceReader, ByteReader};

pub const CHECK_GENERATOR_SELECTOR: [u8; 4] = [248, 243, 181, 56];
pub const VERIFY_REGISTER_SELECTOR: [u8; 4] = [243, 90, 41, 19];
pub const VERIFY_CAST_SELECTOR: [u8; 4] = [199, 65, 76, 236];
pub const VERIFY_TALLY_SELECTOR: [u8; 4] = [151, 84, 187, 55];

pub const STARK_VERIFIER: PrecompileAddress = PrecompileAddress(
    [168, 178, 124, 96, 75, 85, 83, 81, 210, 209, 180, 146, 95, 104, 203, 67, 41, 196, 176, 242],
    Precompile::Standard(stark_verifier_run as StandardPrecompileFn),
);

fn stark_verifier_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&input[..4]);

    // map selector to corresponding method
    match selector {
        CHECK_GENERATOR_SELECTOR => { check_generator_run(&input[4..], gas_limit) },
        VERIFY_REGISTER_SELECTOR => { verify_register_proof_run(&input[4..], gas_limit) },
        VERIFY_CAST_SELECTOR => { verify_cast_proof_run(&input[4..], gas_limit) },
        VERIFY_TALLY_SELECTOR => { verify_tally_result_run(&input[4..], gas_limit) },
        _ => { Err(Error::InvalidMethod) }
    }
}

fn check_generator_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let cost = 0;
    if cost > gas_limit {
        Err(Error::OutOfGas)
    } else {
        let mut input = SliceReader::new(input);
        let generator = BaseElement::read_batch_from(&mut input, AFFINE_POINT_WIDTH);
        if input.has_more_bytes() {
            return Err(Error::UnconsumedBytes);
        }
        if generator.is_err() {
            return Err(Error::DeserializationError);
        }
        let generator = generator.unwrap();
        let mut output = vec![0u8; 32];
        output[31] = (generator == GENERATOR) as u8;
        Ok((cost, output))
    }
}

fn verify_register_proof_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let cost = 0;
    if cost > gas_limit {
        Err(Error::OutOfGas)
    } else {
        // separate inputs
        let elg_root_bytes = &input[..BYTES_PER_DIGEST];
        let register_proof = &input[BYTES_PER_DIGEST..];
        let verify_result = verify_register_proof(
            elg_root_bytes, register_proof
        );
        if verify_result.is_err() {
            return Err(Error::DeserializationError);
        }
        // get big-endian repr. of no. registrations
        let mut num_regs = [0u8; 4];
        num_regs.copy_from_slice(&register_proof[..4]);
        num_regs.reverse();
        let mut output = vec![0u8; 64];
        output[31] = verify_result.unwrap() as u8;
        output[60..64].copy_from_slice(&num_regs);

        Ok((cost, output))
    }
}


fn verify_cast_proof_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let cost = 0;
    if cost > gas_limit {
        Err(Error::OutOfGas)
    } else {
        // separate inputs
        let mut num_keys_bytes: [u8; 4] = [0u8; 4];
        num_keys_bytes.copy_from_slice(&input[..4]);
        let num_keys = u32::from_be_bytes(num_keys_bytes) as usize;
        let key_end = 4 + num_keys * BYTES_PER_AFFINE;
        let voting_keys = &input[..key_end];
        let cast_proof = &input[key_end..];
        let verify_result = verify_cast_proof(
            voting_keys, cast_proof
        );
        if verify_result.is_err() {
            return Err(Error::DeserializationError);
        }

        let output_length = 32 * 3 + num_keys + (32 - (num_keys % 32));
        let mut output = vec![0u8; output_length];
        output[31] = verify_result.unwrap() as u8;

        // ABI encode the dynamic array of outputs
        output[63] = 0x40;
        output[92..96].copy_from_slice(&num_keys_bytes);
        let cds_output_start = 4 + num_keys * BYTES_PER_AFFINE * (PROOF_NUM_POINTS + 1);
        
        for (i, j) in (cds_output_start..cds_output_start + num_keys * BYTES_PER_OUTPUT).step_by(BYTES_PER_OUTPUT).zip(96..num_keys + 96) {
            let cds_output = &cast_proof[i..i + BYTES_PER_OUTPUT];
            output[j] = cds_output.iter().all(|&b| b == 0) as u8;
        }

        Ok((cost, output))
    }
}

fn verify_tally_result_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let cost = 0;
    if cost > gas_limit {
        Err(Error::OutOfGas)
    } else {
        let mut output = vec![0u8; 32];
        
        // separate inputs
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&input[..4]);
        let tally_result = u32::from_be_bytes(tmp);
        tmp.copy_from_slice(&input[4..8]);
        let num_voters = u32::from_le_bytes(tmp);

        if tally_result > num_voters {
            output[31] = 0;
            return Ok((cost, output))
        }
        
        let verify_result = verify_tally_result(&input[4..], tally_result);

        if verify_result.is_err() {
            return Err(Error::DeserializationError);
        }

        output[31] = verify_result.unwrap() as u8;
        Ok((cost, output))
    }
}
