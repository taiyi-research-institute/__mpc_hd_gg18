#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use std::convert::{TryFrom, TryInto};
use std::{fmt, ops};

use serde::{Deserialize, Serialize};

use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::elliptic::curves::{Curve, Point, Scalar};
use curv::ErrorSS::{self, VerifyShareError};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ShamirSecretSharing {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

/// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
/// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43
///
/// implementation details: The code is using FE and GE. Each party is given an index from 1,..,n and a secret share of type FE.
/// The index of the party is also the point on the polynomial where we treat this number as u32 but converting it to FE internally.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifiableSS<E: Curve> {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<Point<E>>, // modify: vec to map
}

/// Shared secret produced by [VerifiableSS::share]
///
/// After you shared your secret, you need to distribute `shares` among other parties, and erase
/// secret from your memory (SharedSecret zeroizes on drop).
///
/// You can retrieve a [polynomial](Self::polynomial) that was used to derive secret shares. It is
/// only needed to combine with other proofs (e.g. [low degree exponent interpolation]).
///
/// [low degree exponent interpolation]: crate::cryptographic_primitives::proofs::low_degree_exponent_interpolation
#[derive(Clone)]
pub struct SecretShares<E: Curve> {
    shares: Vec<Scalar<E>>, // modify: vec to map
    polynomial: Polynomial<E>,
}

impl<E: Curve> VerifiableSS<E> {
    pub fn reconstruct_limit(&self) -> u16 {
        self.parameters.threshold + 1
    }

    // generate VerifiableSS from a secret
    pub fn share(t: u16, n: u16, secret: &Scalar<E>) -> (VerifiableSS<E>, SecretShares<E>) {
        assert!(t < n);

        let polynomial = Polynomial::<E>::sample_exact_with_fixed_const_term(t, secret.clone());
        let shares = polynomial.evaluate_many_bigint(1..=n).collect();

        let g = Point::<E>::generator();
        let commitments = polynomial
            .coefficients()
            .iter()
            .map(|coef| g * coef)
            .collect::<Vec<_>>();
        let vss = VerifiableSS {
            parameters: ShamirSecretSharing {
                threshold: t,
                share_count: n,
            },
            commitments,
        };
        let shares = SecretShares { shares, polynomial };
        let ret = (vss, shares);

        ret
    }

    // takes given VSS and generates a new VSS for the same secret and a secret shares vector to match the new commitments
    pub fn reshare(&self) -> (VerifiableSS<E>, Vec<Scalar<E>>) {
        let t = self.parameters.threshold;
        let n = self.parameters.share_count;

        let one = Scalar::<E>::from(1);
        let poly = Polynomial::<E>::sample_exact_with_fixed_const_term(t, one.clone());
        let secret_shares_biased: Vec<_> = poly.evaluate_many_bigint(1..=n).collect();
        let secret_shares: Vec<_> = (0..secret_shares_biased.len())
            .map(|i| &secret_shares_biased[i] - &one)
            .collect();
        let g = Point::<E>::generator();
        let mut new_commitments = vec![self.commitments[0].clone()];
        for (poly, commitment) in poly.coefficients().iter().zip(&self.commitments).skip(1) {
            new_commitments.push((g * poly) + commitment)
        }
        (
            VerifiableSS {
                parameters: self.parameters.clone(),
                commitments: new_commitments,
            },
            secret_shares,
        )
    }

    // generate VerifiableSS from a secret and user defined x values (in case user wants to distribute point f(1), f(4), f(6) and not f(1),f(2),f(3))
    pub fn share_at_indices(
        t: u16,
        n: u16,
        secret: &Scalar<E>,
        index_vec: &[u16],
    ) -> (VerifiableSS<E>, SecretShares<E>) {
        assert_eq!(usize::from(n), index_vec.len());

        let polynomial = Polynomial::<E>::sample_exact_with_fixed_const_term(t, secret.clone());
        let shares = polynomial
            .evaluate_many_bigint(index_vec.iter().cloned())
            .collect();

        let g = Point::<E>::generator();
        let commitments = polynomial
            .coefficients()
            .iter()
            .map(|coef| g * coef)
            .collect::<Vec<Point<E>>>();
        (
            VerifiableSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
            },
            SecretShares { shares, polynomial },
        )
    }

    // returns vector of coefficients
    #[deprecated(since = "0.8.0", note = "please use Polynomial::sample instead")]
    pub fn sample_polynomial(t: usize, coef0: &Scalar<E>) -> Vec<Scalar<E>> {
        Polynomial::<E>::sample_exact_with_fixed_const_term(t.try_into().unwrap(), coef0.clone())
            .coefficients()
            .to_vec()
    }

    #[deprecated(
        since = "0.8.0",
        note = "please use Polynomial::evaluate_many_bigint instead"
    )]
    pub fn evaluate_polynomial(coefficients: &[Scalar<E>], index_vec: &[usize]) -> Vec<Scalar<E>> {
        Polynomial::<E>::from_coefficients(coefficients.to_vec())
            .evaluate_many_bigint(index_vec.iter().map(|&i| u64::try_from(i).unwrap()))
            .collect()
    }

    #[deprecated(since = "0.8.0", note = "please use Polynomial::evaluate instead")]
    pub fn mod_evaluate_polynomial(coefficients: &[Scalar<E>], point: Scalar<E>) -> Scalar<E> {
        Polynomial::<E>::from_coefficients(coefficients.to_vec()).evaluate(&point)
    }

    pub fn reconstruct(&self, indices: &[u16], shares: &[Scalar<E>]) -> Scalar<E> {
        assert_eq!(shares.len(), indices.len());
        assert!(shares.len() >= usize::from(self.reconstruct_limit()));
        // add one to indices to get points
        let points = indices
            .iter()
            .map(|i| Scalar::from(*i + 1))
            .collect::<Vec<_>>();
        VerifiableSS::<E>::lagrange_interpolation_at_zero(&points, shares)
    }

    // Performs a Lagrange interpolation in field Zp at the origin
    // for a polynomial defined by `points` and `values`.
    // `points` and `values` are expected to be two arrays of the same size, containing
    // respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).

    // The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.

    // This is obviously less general than `newton_interpolation_general` as we
    // only get a single value, but it is much faster.

    pub fn lagrange_interpolation_at_zero(points: &[Scalar<E>], values: &[Scalar<E>]) -> Scalar<E> {
        let vec_len = values.len();

        assert_eq!(points.len(), vec_len);
        // Lagrange interpolation for point 0
        // let mut acc = 0i64;
        let lag_coef =
            (0..vec_len)
                .map(|i| {
                    let xi = &points[i];
                    let yi = &values[i];
                    let num = Scalar::from(1);
                    let denum = Scalar::from(1);
                    let num = points.iter().zip(0..vec_len).fold(num, |acc, x| {
                        if i != x.1 {
                            acc * x.0
                        } else {
                            acc
                        }
                    });
                    let denum = points.iter().zip(0..vec_len).fold(denum, |acc, x| {
                        if i != x.1 {
                            let xj_sub_xi = x.0 - xi;
                            acc * xj_sub_xi
                        } else {
                            acc
                        }
                    });
                    let denum = denum.invert().unwrap();
                    num * denum * yi
                })
                .collect::<Vec<_>>();
        let mut lag_coef_iter = lag_coef.iter();
        let head = lag_coef_iter.next().unwrap();
        let tail = lag_coef_iter;
        tail.fold(head.clone(), |acc, x| acc + x)
    }

    // modify: index
    pub fn validate_share(&self, secret_share: &Scalar<E>, index: u16) -> Result<(), ErrorSS> {
        let g = Point::generator();
        let ss_point = g * secret_share;
        self.validate_share_public(&ss_point, index)
    }

    pub fn validate_share_public(&self, ss_point: &Point<E>, index: u16) -> Result<(), ErrorSS> {
        let comm_to_point = self.get_point_commitment(index);
        if *ss_point == comm_to_point {
            Ok(())
        } else {
            Err(VerifyShareError)
        }
    }

    pub fn get_point_commitment(&self, index: u16) -> Point<E> {
        let index_fe = Scalar::from(index);
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        tail.fold(head.clone(), |acc, x| x + acc * &index_fe)
    }

    //compute \lambda_{index,S}, a lagrangian coefficient that change the (t,n) scheme to (|S|,|S|)
    // used in http://stevengoldfeder.com/papers/GG18.pdf
    pub fn map_share_to_new_params(
        _params: &ShamirSecretSharing,
        index: u16,
        s: &[u16],
    ) -> Scalar<E> {
        let j = (0u16..)
            .zip(s)
            .find_map(|(j, s_j)| if *s_j == index { Some(j) } else { None })
            .expect("`s` doesn't include `index`");
        let xs = s.iter().map(|x| Scalar::from(*x + 1)).collect::<Vec<_>>();
        Polynomial::lagrange_basis(&Scalar::zero(), j, &xs)
    }
}

impl<E: Curve> SecretShares<E> {
    /// Polynomial that was used to derive secret shares
    pub fn polynomial(&self) -> &Polynomial<E> {
        &self.polynomial
    }
}

impl<E: Curve> fmt::Debug for SecretShares<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // blind sensitive data stored by the structure
        write!(f, "SecretShares{{ ... }}")
    }
}

impl<E: Curve> ops::Deref for SecretShares<E> {
    type Target = [Scalar<E>];
    fn deref(&self) -> &Self::Target {
        &self.shares
    }
}