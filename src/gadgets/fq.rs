use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
use ark_bls12_377::{Fq};
use ark_r1cs_std::{
    alloc::AllocVar, // Needed to call new_witness
    eq::EqGadget, // To allow comparisons
    R1CSVar, // To extract the value
    fields::FieldVar, // To use one or zero vars inside the cs
};
use ark_std::{UniformRand}; // To call Fq::rand()
use ark_bls12_377::constraints::FqVar;

use crate::utils::print_cs_details;

pub fn test_fq_var() -> Result<(), SynthesisError> {
    println!("\n### Running test_fq_var()...");

    let cs: ConstraintSystemRef<Fq> = ConstraintSystem::<Fq>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let a_native: Fq = Fq::rand(&mut rng);
    let b_native: Fq = Fq::rand(&mut rng);

    let a: FqVar = FqVar::new_witness(ark_relations::ns!(cs.clone(), "generate_a"), || Ok(a_native))?;
    let b: FqVar = FqVar::new_witness(ark_relations::ns!(cs.clone(), "generate_b"), || Ok(b_native))?;

    let a_const: FqVar = FqVar::new_constant(ark_relations::ns!(cs.clone(), "a_as_constant"), a_native)?;
    let b_const: FqVar = FqVar::new_constant(ark_relations::ns!(cs.clone(), "b_as_constant"), b_native)?;

    // Must use ark_r1cs_std::fields::FieldVar to implement the methods one() and zero()
    let one = FqVar::one();
    let zero = FqVar::zero();

    let two = &one + &one + &zero;
    two.enforce_equal(&one.double()?)?;

    assert!(cs.is_satisfied()?);

    assert_eq!((&a + &b).value()?, a_native + &b_native);
    assert_eq!((&a * &b).value()?, a_native * &b_native);

    (&a + &b).enforce_equal(&(&a_const + &b_const))?;
    assert!(cs.is_satisfied()?);

    cs.finalize();

    print_cs_details(cs);

    Ok(())
}