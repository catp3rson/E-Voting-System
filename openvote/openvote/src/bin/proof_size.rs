use openvote::{
    cds::CDSExample,
    merkle::MerkleExample,
    schnorr::SchnorrExample,
    tally::TallyExample,
    aggregator::build_options,
};

pub const SIZES: [usize; 5] = [8, 16, 32, 64, 128];
pub const SAMPLE_SIZE: usize = 50;

fn main() {
    merkle_proof_size();
    schnorr_proof_size();
    cds_proof_size();
    tally_proof_size();
}

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

