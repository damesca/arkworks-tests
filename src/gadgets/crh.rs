use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
use ark_bls12_377::{Fr, Fq, G1Projective, constraints::G1Var};
use ark_crypto_primitives::crh::{
    pedersen, sha256::{constraints::Sha256Gadget, Sha256}, CRHScheme, CRHSchemeGadget,
};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode}, eq::EqGadget, groups::CurveVar, uint8::UInt8, R1CSVar, ToBytesGadget
};
use ark_ed_on_bls12_377::{
    Fq as ConstraintF,
    EdwardsProjective as JubJub,
    constraints::EdwardsVar,
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

// HASH TO CURVE
// The crh works on twisted Edw with Fq = Bls12_Fr (for the constraint system)
pub fn test_pedersen_crh() -> Result<(), SynthesisError> {
    println!("\n### Running test_sha256_crh()...");

    let cs = ConstraintSystem::<ConstraintF>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let input = String::from("hello");

    #[derive(Clone)]
    pub struct PedersenWindow;
    impl pedersen::Window for PedersenWindow {
        const WINDOW_SIZE: usize = 128;
        const NUM_WINDOWS: usize = 4;
    }

    type PedersenCRH = pedersen::CRH<JubJub, PedersenWindow>;
    type PedersenCRHGadget = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, PedersenWindow>;

    let pedersen_params = PedersenCRH::setup(&mut rng).unwrap();
    let hash_output = PedersenCRH::evaluate(&pedersen_params, input.as_bytes()).unwrap();

    // Constraint System
    // Can call new_constant from CRHParametersVar because it implements AllocVar trait
    let parameters_var = pedersen::constraints::CRHParametersVar::<JubJub, EdwardsVar>::new_constant(
        ark_relations::ns!(cs, "CRH Parameters"),
        &pedersen_params,
    )
    .unwrap();
    let input_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "input"), input.as_bytes())?;
    let output_var = EdwardsVar::new_variable(
        ark_relations::ns!(cs, "output"),
        || Ok(hash_output),
        AllocationMode::Input,
    );
    let result_var = PedersenCRHGadget::evaluate(&parameters_var, &input_var).unwrap();
    
    result_var.enforce_equal(&output_var.unwrap());

    assert!(cs.is_satisfied()?);

    cs.finalize();

    print_cs_details(cs);
    
    Ok(())
}