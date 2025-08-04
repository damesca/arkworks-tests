use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
//use ark_ec::bls12::{G1Prepared, G2Prepared};
use ark_bls12_377::{ // NOTE: The crate ark_bls12_381 does not support feature "r1cs" and therefore cannot call GVars
    constraints::{G1Var, G2Var},
    G1Projective,
    G2Projective,
    Bls12_377,
    Fq,
};
use ark_std::{UniformRand}; // To call Fq::rand()
use ark_r1cs_std::{
    alloc::AllocVar, // Needed to call new_witness
    pairing::PairingVar, // To call prepare_g()
    eq::EqGadget, // To call enforce_equal()
    R1CSVar, // To call value()
};
use ark_ec::pairing::Pairing; // To call "native" pairing()

use crate::utils::print_cs_details;

pub fn test_pairing() -> Result<(), SynthesisError> {
    println!("\n### Running test_pairing()...");

    let cs = ConstraintSystem::<Fq>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let a_native = G1Projective::rand(&mut rng);
    let b_native = G2Projective::rand(&mut rng);

    let a = G1Var::new_witness(ark_relations::ns!(cs, "a"), || Ok(a_native))?;
    let b = G2Var::new_witness(ark_relations::ns!(cs, "b"), || Ok(b_native))?;

    let a_const = G1Var::new_constant(ark_relations::ns!(cs, "a_as_constant"), a_native)?;
    let b_const = G2Var::new_constant(ark_relations::ns!(cs, "b_as_constant"), b_native)?;

    let pairing_result_native = Bls12_377::pairing(a_native, b_native);

    //let a_prep = ark_bls12_377::constraints::PairingVar::prepare_g1(&a)?;
    let a_prep = ark_r1cs_std::pairing::bls12::PairingVar::<ark_bls12_377::Config>::prepare_g1(&a)?;
    let b_prep = ark_bls12_377::constraints::PairingVar::prepare_g2(&b)?;
    let pairing_result = ark_bls12_377::constraints::PairingVar::pairing(a_prep, b_prep)?;

    assert_eq!(pairing_result.value()?, pairing_result_native.0);

    let a_prep_const = ark_bls12_377::constraints::PairingVar::prepare_g1(&a_const)?;
    let b_prep_const = ark_bls12_377::constraints::PairingVar::prepare_g2(&b_const)?;
    let pairing_result_const = ark_bls12_377::constraints::PairingVar::pairing(a_prep_const, b_prep_const)?;

    pairing_result_const.enforce_equal(&pairing_result_const)?;
    assert!(cs.is_satisfied()?);

    cs.finalize();

    print_cs_details(cs);

    Ok(())
}