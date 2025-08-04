use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal},
};
use ark_bls12_377::{Fr, Fq};
use ark_std::{UniformRand}; // To call Fq::rand()
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::nonnative::NonNativeFieldVar,
};

use crate::utils::print_cs_details;

pub fn test_add() -> Result<(), SynthesisError> {
    println!("\n### Running emulation::test_add()...");

    let cs = ConstraintSystem::<Fq>::new_ref();

    let mut rng = ark_std::test_rng();

    let a_value = Fr::rand(&mut rng);
    let b_value = Fr::rand(&mut rng);
    
    let a = NonNativeFieldVar::<Fr, Fq>::new_witness(ns!(cs, "a"), || Ok(a_value))?;
    let b = NonNativeFieldVar::<Fr, Fq>::new_witness(ns!(cs, "b"), || Ok(b_value))?;

    let a_plus_b = &a + &b;

    cs.finalize();

    print_cs_details(cs);

    Ok(())
}

pub fn test_mul() -> Result<(), SynthesisError> {
    println!("\n### Running emulation::test_mul()...");

    let cs = ConstraintSystem::<Fq>::new_ref();

    let mut rng = ark_std::test_rng();

    let a_value = Fr::rand(&mut rng);
    let b_value = Fr::rand(&mut rng);
    
    let a = NonNativeFieldVar::<Fr, Fq>::new_witness(ns!(cs, "a"), || Ok(a_value))?;
    let b = NonNativeFieldVar::<Fr, Fq>::new_witness(ns!(cs, "b"), || Ok(b_value))?;

    let a_times_b = &a * &b;

    cs.finalize();

    print_cs_details(cs);

    Ok(())
}

pub fn test_mul_without_reduce() -> Result<(), SynthesisError> {
    println!("\n### Running emulation::test_mul_without_reduce()...");

    let cs = ConstraintSystem::<Fq>::new_ref();

    let mut rng = ark_std::test_rng();

    let a_value = Fr::rand(&mut rng);
    let b_value = Fr::rand(&mut rng);
    
    let a = NonNativeFieldVar::<Fr, Fq>::new_witness(ns!(cs, "a"), || Ok(a_value))?;
    let b = NonNativeFieldVar::<Fr, Fq>::new_witness(ns!(cs, "b"), || Ok(b_value))?;

    let a_times_b = a.mul_without_reduce(&b)?;

    cs.finalize();

    print_cs_details(cs);

    Ok(())
}

/*
 * ¿Emulate pairings? --> Check https://eprint.iacr.org/2022/1162.pdf
 */