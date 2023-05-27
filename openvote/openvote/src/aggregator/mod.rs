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

fn build_options(extension: u8) -> ProofOptions {
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
