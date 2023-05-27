use winterfell::{
    math::{
        curves::curve_f63::{AffinePoint, ProjectivePoint, Scalar},
        fields::f63::BaseElement,
        FieldElement,
    },
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};

use super::constants::*;

/// Errors raised by VoteTallier
#[derive(Debug, PartialEq)]
pub enum TallierError {
    /// Error occurs when the tally result cannot be found when
    /// looking through all possible solutions
    InvalidTallyResult,
}

/// Type that encapsulates all data and functionalities of
/// aggregator during vote tallying phase
#[derive(Debug, Clone)]
pub struct VoteTallier {
    /// Valid encrypted votes from vote casting phase
    pub encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>,
    /// Number of "yes" votes
    pub tally_result: Option<u32>,
}

impl VoteTallier {
    /// Create an object of type VoteTallier
    pub fn new(encrypted_votes: Vec<[BaseElement; AFFINE_POINT_WIDTH]>) -> Self {
        Self {
            encrypted_votes,
            tally_result: None,
        }
    }

    /// Reconstruct an object of type Self from a sequence of bytes
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        let mut source = SliceReader::new(source);
        Self::read_from(&mut source)
    }

    /// Dump self to an output stream
    pub fn dump_to<W: std::io::Write>(&self, target: &mut W) -> Result<usize, std::io::Error> {
        target.write(&self.to_bytes())
    }

    /// Calculate tally result
    pub fn tally_votes(&mut self) -> Result<u32, TallierError> {
        if self.tally_result.is_some() {
            return Ok(self.tally_result.unwrap());
        }

        let num_votes = self.encrypted_votes.len() as u32;
        let mut yes_sum = ProjectivePoint::generator() * Scalar::from(num_votes);
        for &encrypted_vote in self.encrypted_votes.iter() {
            yes_sum += AffinePoint::from_raw_coordinates(encrypted_vote);
        }
        yes_sum *= Scalar::from(2u32).invert();
        let mut tmp = ProjectivePoint::identity();
        let mut tally_result = 0u32;

        while tmp != yes_sum && tally_result <= num_votes {
            tmp += AffinePoint::generator();
            tally_result += 1;
        }

        if tally_result > num_votes {
            Err(TallierError::InvalidTallyResult)
        } else {
            self.tally_result = Some(tally_result);
            Ok(tally_result)
        }
    }

    #[cfg(test)]
    pub fn get_example(num_votes: usize) -> (Self, u32) {
        use crate::{aggregator::build_options, tally::TallyExample};

        let example = TallyExample::new(build_options(1), num_votes);
        (
            Self {
                encrypted_votes: example.encrypted_votes,
                tally_result: None,
            },
            example.tally_result,
        )
    }

    #[cfg(test)]
    pub fn tally_votes_wrong_result(&mut self) -> Result<u32, TallierError> {
        use rand_core::{OsRng, RngCore};

        let tally_result = self.tally_votes()?;
        let result_range = (self.encrypted_votes.len() + 1) as u32;
        let mut rng = OsRng;
        let mut wrong_tally_result = rng.next_u32() % result_range;

        while wrong_tally_result == tally_result {
            wrong_tally_result = rng.next_u32() % result_range;
        }

        Ok(wrong_tally_result)
    }
}

impl Serializable for VoteTallier {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.encrypted_votes.len() as u32);
        for encrypted_vote in self.encrypted_votes.iter() {
            Serializable::write_batch_into(encrypted_vote, target);
        }
    }
}

impl Deserializable for VoteTallier {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut encrypted_vote = [BaseElement::ZERO; AFFINE_POINT_WIDTH];

        let num_votes = source.read_u32()? as usize;
        let mut encrypted_votes = Vec::with_capacity(num_votes);

        for _ in 0..num_votes {
            encrypted_vote
                .copy_from_slice(&BaseElement::read_batch_from(source, AFFINE_POINT_WIDTH)?);
            encrypted_votes.push(encrypted_vote);
        }

        Ok(Self {
            encrypted_votes,
            tally_result: None,
        })
    }
}
