// Copyright (c) Facebook, Inc. and its affiliates.
// Copyright (c) 2021-2022 Toposware, Inc.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::FieldElement;
use utils::collections::Vec;

// CONSTRAINT COMPOSITION COEFFICIENTS
// ================================================================================================
/// Coefficients used in construction of constraint composition polynomial.
///
/// These coefficients are created by the
/// [Air::get_constraint_composition_coefficients()](crate::Air::get_constraint_composition_coefficients)
/// function. In the interactive version of the protocol, the verifier draws these coefficients
/// uniformly at random from the extension field of the protocol.
///
/// There are two coefficients for each constraint so that we can compute a random linear
/// combination of constraints like so:
/// $$
/// \sum_{i = 0}^k{C_i(x) \cdot (\alpha_i + \beta_i \cdot x^{d_i})}
/// $$
/// where:
/// * $\alpha_i$ and $\beta_i$ are the coefficients for the $i$th constraint.
/// * $C_i(x)$ is an evaluation of the $i$th constraint at $x$.
/// * $d_i$ is the degree adjustment factor needed to normalize all constraints to the same degree.
///
/// The coefficients are separated into two lists: one for transition constraints and another one
/// for boundary constraints. This separation is done for convenience only.
#[derive(Debug, Clone)]
pub struct ConstraintCompositionCoefficients<E: FieldElement> {
    pub transition: Vec<(E, E)>,
    pub boundary: Vec<(E, E)>,
}

// DEEP COMPOSITION COEFFICIENTS
// ================================================================================================
/// Coefficients used in construction of DEEP composition polynomial.
///
/// These coefficients are created by the
/// [Air::get_deep_composition_coefficients()](crate::Air::get_deep_composition_coefficients)
/// function. In the interactive version of the protocol, the verifier draws these coefficients
/// uniformly at random from the extension field of the protocol.
///
/// The coefficients are used in computing the DEEP composition polynomial in two steps. First,
/// we compute a random linear combination of trace and constraint composition polynomials as:
/// $$
/// Y(x) = \sum_{i=0}^k{(
///     \alpha_i \cdot \frac{T_i(x) - T_i(z)}{x - z} +
///     \beta_i \cdot \frac{T_i(x) - T_i(z \cdot g)}{x - z \cdot g} +
///     \gamma_i \cdot \frac{T_i(x) - T_i(\overline{z})}{x - \overline{z}}
/// )} + \sum_{j=0}^m{\delta \cdot \frac{H_j(x) - H_j(z^m)}{x - z^m}}
/// $$
/// where:
/// * $z$ is an out-of-domain point drawn randomly from the entire field. In the interactive
///   version of the protocol, $z$ is provided by the verifier. $\overline{z}$ is the conjugate
///   of $z$.
/// * $g$ is the generator of the trace domain. This is the same as $n$th root of unity where
///   $n$ is the length of the execution trace.
/// * $T_i(x)$ is an evaluation of the $i$th trace polynomial at $x$, and $k$ is the total
///   number of trace polynomials (which is equal to the width of the execution trace).
/// * $H_i(x)$ is an evaluation of the $j$th constraint composition column polynomial at $x$,
///   and $m$ is the total number of column polynomials. The number of column polynomials is equal
///   to the highest constraint degree rounded to the next power of two. For example, if the
///   highest constraint degree is 6, $m$ will be equal to 8.
/// * $\alpha_i, \beta_i, \gamma_i$ are composition coefficients for the $i$th trace polynomial.
/// * $\delta_j$ is a composition coefficient for $j$th constraint column polynomial.
///
/// $T(x)$ and $H(x)$ are polynomials of degree $n - 1$, where $n$ is the length of the execution
/// trace. Thus, the degree of $Y(x)$ polynomial is $n - 2$. To bring the degree back up to
/// $n - 1$, we compute the DEEP composition polynomial as:
/// $$
/// C(x) = Y(x) \cdot (\lambda + \mu \cdot x)
/// $$
/// where $\lambda$ and $\mu$ are the composition coefficients for degree adjustment.
#[derive(Debug, Clone)]
pub struct DeepCompositionCoefficients<E: FieldElement> {
    /// Trace polynomial composition coefficients $\alpha_i$, $\beta_i$, and $\gamma_i$.
    pub trace: Vec<(E, E, E)>,
    /// Constraint column polynomial composition coefficients $\delta_j$.
    pub constraints: Vec<E>,
    /// Degree adjustment composition coefficients $\lambda$ and $\mu$.
    pub degree: (E, E),
}