use super::calc_linear_cost_u32;
use crate::{Error, Precompile, PrecompileAddress, PrecompileResult, StandardPrecompileFn};
use openvote::verifier::{
    verify_register_proof, verify_cast_proof, verify_tally_result,
    constants::*,
};

// pub const SHA256: PrecompileAddress = PrecompileAddress(
//     crate::u64_to_b160(2),
//     Precompile::Standard(sha256_run as StandardPrecompileFn),
// );
// pub const RIPEMD160: PrecompileAddress = PrecompileAddress(
//     crate::u64_to_b160(3),
//     Precompile::Standard(ripemd160_run as StandardPrecompileFn),
// );

fn verify_register_proof_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
    // currently cost is set to 0
    let cost = 0;
    if cost > gas_limit {
        Err(Error::OutOfGas)
    } else {
        // parse input
        match verify_register_proof(&input[..BYTES_PER_DIGEST], &input[BYTES_PER_DIGEST..]) {
            Ok(valid) => {
                Ok((cost, vec![u8::from(valid); 1]))
            },
            Err(err) => { 
                Err(Error::DeserializationError)
            }
        }
    }
}
// /// See: https://ethereum.github.io/yellowpaper/paper.pdf
// /// See: https://docs.soliditylang.org/en/develop/units-and-global-variables.html#mathematical-and-cryptographic-functions
// /// See: https://etherscan.io/address/0000000000000000000000000000000000000002
// fn sha256_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
//     let cost = calc_linear_cost_u32(input.len(), 60, 12);
//     if cost > gas_limit {
//         Err(Error::OutOfGas)
//     } else {
//         let output = sha2::Sha256::digest(input).to_vec();
//         Ok((cost, output))
//     }
// }

// /// See: https://ethereum.github.io/yellowpaper/paper.pdf
// /// See: https://docs.soliditylang.org/en/develop/units-and-global-variables.html#mathematical-and-cryptographic-functions
// /// See: https://etherscan.io/address/0000000000000000000000000000000000000003
// fn ripemd160_run(input: &[u8], gas_limit: u64) -> PrecompileResult {
//     let gas_used = calc_linear_cost_u32(input.len(), 600, 120);
//     if gas_used > gas_limit {
//         Err(Error::OutOfGas)
//     } else {
//         let mut ret = [0u8; 32];
//         ret[12..32].copy_from_slice(&ripemd::Ripemd160::digest(input));
//         Ok((gas_used, ret.to_vec()))
//     }
// }
