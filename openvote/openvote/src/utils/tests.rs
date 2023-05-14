use rand_core::{OsRng, RngCore};
use winterfell::math::{fields::f63::BaseElement, FieldElement, curves::curve_f63::{Scalar, AffinePoint, ProjectivePoint}};


// #[test]
// fn test_mul_fp6() {
//     let x = &GENERATOR[..POINT_COORDINATE_WIDTH];
//     let y = &GENERATOR[POINT_COORDINATE_WIDTH..AFFINE_POINT_WIDTH];
//     let xy = mul_fp6(x, y);
//     println!("{:?}", xy);
// }

// #[test]
// fn test_zero_point() {
//     let mut x = [BaseElement::ZERO; PROJECTIVE_POINT_WIDTH + 1];
//     x[PROJECTIVE_POINT_WIDTH] = BaseElement::ONE;
//     x[AFFINE_POINT_WIDTH] = BaseElement::ONE;
//     x[..AFFINE_POINT_WIDTH].copy_from_slice(&GENERATOR);
//     let g_neg = compute_negation_affine(&GENERATOR);
//     ecc::apply_point_addition_mixed(
//         &mut x,
//         &g_neg
//     );
//     println!("{:?}", &x[..PROJECTIVE_POINT_WIDTH]);
// }

#[test]
fn test_mul_generator() {
    let mut x = ProjectivePoint::generator();
    let mut rng = OsRng;
    for _ in 0..255 {
            x = x.double();
            if rng.next_u32() % 2 == 1 {
                x += ProjectivePoint::generator();
            }
    }
    let x = AffinePoint::from(x);
    println!("{:?}", x.get_x());
    println!("{:?}", x.get_y());
}