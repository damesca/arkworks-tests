use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
use ark_bls12_377::{
    G1Projective,
    Fq
};
use ark_bls12_377::constraints::G1Var;
use ark_r1cs_std::{
    groups::CurveVar,
    alloc::AllocVar,
    eq::EqGadget,
    R1CSVar,
};
use ark_std::{UniformRand};

use crate::utils::print_cs_details;

pub fn test_GVar() -> Result<(), SynthesisError> {
    println!("\n### Running test_GVar()...");

    let cs = ConstraintSystem::<Fq>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let a_native = G1Projective::rand(&mut rng);
    let b_native = G1Projective::rand(&mut rng);

    let a = G1Var::new_witness(ark_relations::ns!(cs, "a"), || Ok(a_native))?;
    let b = G1Var::new_witness(ark_relations::ns!(cs, "b"), || Ok(b_native))?;

    let a_const = G1Var::new_constant(ark_relations::ns!(cs, "a_as_constant"), a_native)?;
    let b_const = G1Var::new_constant(ark_relations::ns!(cs, "b_as_constant"), b_native)?;

    let zero = G1Var::zero();

    let two_a = &a + &a + &zero;
    two_a.enforce_equal(&a.double()?)?;

    assert!(cs.is_satisfied()?);

    assert_eq!((&a + &b).value()?, a_native + &b_native);

    (&a + &b).enforce_equal(&(&a_const + &b_const))?;
    assert!(cs.is_satisfied()?);

    cs.finalize();

    print_cs_details(cs);

    Ok(())
}