use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
use ark_bls12_377::{Fr};
use ark_r1cs_std::{
    uint8::UInt8,
    alloc::AllocVar, // Needed to call new_witness
    eq::EqGadget, // To allow comparisons
};

use crate::utils::print_cs_details;

/*
 *  Examples are from: 
 *  https://github.com/arkworks-rs/algebra/blob/a13c018816522de2411082db27e95c748c001642/curves/bls12_377/src/constraints/mod.rs
 */

pub fn test_uint8() -> Result<(), SynthesisError> {
    println!("\n### Running test_uint8()...");

    let cs: ConstraintSystemRef<Fr> = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);
    let two: UInt8<Fr> = UInt8::new_witness(cs.clone(), || Ok(2))?;
    let var: Vec<UInt8<Fr>> = vec![two.clone(); 32];

    let c: Vec<UInt8<Fr>> = UInt8::new_input_vec(cs.clone(), &[2; 32])?;
    var.enforce_equal(&c)?;
    assert!(cs.is_satisfied().unwrap());
    
    cs.finalize(); // This applies the optimization and inlines/outlines the constraints

    print_cs_details(cs);

    Ok(())
}