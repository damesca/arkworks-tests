use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
use ark_bls12_377::Fr;
use ark_crypto_primitives::{crh::CRHScheme, crh::sha256::constraints::Sha256Gadget, crh::sha256::Sha256};
use ark_r1cs_std::{
    ToBytesGadget,
    uint8::UInt8,
    eq::EqGadget,
};

use crate::utils::print_cs_details;

pub fn test_sha256_crh() -> Result<(), SynthesisError> {
    println!("\n### Running test_sha256_crh()...");

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let input = String::from("hello");

    let sha_params = <Sha256 as CRHScheme>::setup(&mut rng).unwrap();
    let sha_output = Sha256::evaluate(&sha_params, input.as_bytes()).unwrap();

    // Constraint System
    let input_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "input"), input.as_bytes())?;
    let output_var = UInt8::new_input_vec(ark_relations::ns!(cs, "output"), sha_output.as_slice())?;
    let mut sha_var = Sha256Gadget::<Fr>::default();
    sha_var.update(&input_var);
    let sha_var_output = sha_var.finalize().unwrap().to_bytes().unwrap();

    output_var.enforce_equal(sha_var_output.as_slice());

    assert!(cs.is_satisfied()?);

    cs.finalize();

    print_cs_details(cs);
    
    Ok(())
}