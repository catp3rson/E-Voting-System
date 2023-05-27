#[cfg(feature = "proof_size")]
mod tests {
    use crate::cds::CDSExample;
    use crate::merkle::MerkleExample;
    use crate::schnorr::SchnorrExample;
    use crate::tally::TallyExample;
    use winterfell::{FieldExtension, HashFunction, ProofOptions};

    pub const SIZES: [usize; 5] = [8, 16, 32, 64, 128];
    pub const SAMPLE_SIZE: usize = 50;

    #[test]
    fn merkle_proof_size() {
        for size in SIZES {
            let mut avg_size: usize = 0;
            for _ in 0..SAMPLE_SIZE {
                let merkle = MerkleExample::new(build_options(1), size);
                let proof = merkle.prove();
                let proof_size = proof.to_bytes().len();
                avg_size += proof_size;
            }
            println!(
                "Average proof size of merkle/{}: {}",
                size,
                avg_size / SAMPLE_SIZE
            );
        }
    }

    #[test]
    fn schnorr_proof_size() {
        for size in SIZES {
            let mut avg_size: usize = 0;
            for _ in 0..SAMPLE_SIZE {
                let schnorr = SchnorrExample::new(build_options(1), size);
                let proof = schnorr.prove();
                let proof_size = proof.to_bytes().len();
                avg_size += proof_size;
            }
            println!(
                "Average proof size of schnorr/{}: {}",
                size,
                avg_size / SAMPLE_SIZE
            );
        }
    }

    #[test]
    fn cds_proof_size() {
        for size in SIZES {
            let mut avg_size: usize = 0;
            for _ in 0..SAMPLE_SIZE {
                let (cds, _) = CDSExample::new(build_options(1), size);
                let (_, proof) = cds.prove();
                let proof_size = proof.to_bytes().len();
                avg_size += proof_size;
            }
            println!(
                "Average proof size of cds/{}: {}",
                size,
                avg_size / SAMPLE_SIZE
            );
        }
    }

    #[test]
    fn tally_proof_size() {
        for size in SIZES {
            let mut avg_size: usize = 0;
            for _ in 0..SAMPLE_SIZE {
                let tally = TallyExample::new(build_options(1), 8);
                let proof = tally.prove();
                let proof_size = proof.to_bytes().len();
                avg_size += proof_size;
            }
            println!(
                "Average proof size of tally/{}: {}",
                size,
                avg_size / SAMPLE_SIZE
            );
        }
    }

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
}
