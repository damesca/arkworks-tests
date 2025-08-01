//use core::slice::SlicePattern;
use std::{default, mem::zeroed, ops::Add};

use ark_ec::bls12::{G1Prepared, G2Prepared};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::{fp::{FpVar, AllocatedFp}, fp12::Fp12Var, FieldVar}, groups::{curves::short_weierstrass::ProjectiveVar, CurveVar}, pairing::PairingVar, uint8::UInt8, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal};
use ark_bls12_377::{constraints::{Fq2Var, FqVar, G1PreparedVar, G1Var, G2Var}, Bls12_377, Config, Fq, Fr, G1Projective, G2Projective};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{UniformRand, rand::SeedableRng, rand::RngCore};
//use ark_test_curves::{pairing::Pairing};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_ec::pairing::Pairing;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_crypto_primitives::crh::{sha256::{constraints::{Sha256Gadget, DigestVar}, Sha256}, CRHScheme, CRHSchemeGadget};

/*
 *  Examples are from: 
 *  https://github.com/arkworks-rs/algebra/blob/a13c018816522de2411082db27e95c748c001642/curves/bls12_377/src/constraints/mod.rs
 */

fn test_uint8() -> Result<(), SynthesisError> {
    println!("\n### Running test_uint8()...");

    let cs: ConstraintSystemRef<Fr> = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);
    let two: UInt8<Fr> = UInt8::new_witness(cs.clone(), || Ok(2))?;
    let var: Vec<UInt8<Fr>> = vec![two.clone(); 32];

    let c: Vec<UInt8<Fr>> = UInt8::new_input_vec(cs.clone(), &[2; 32])?;
    var.enforce_equal(&c);
    assert!(cs.is_satisfied().unwrap());
    
    cs.finalize(); // This applies the optimization and inlines/outlines the constraints

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());

    Ok(())
}

fn test_FqVar() -> Result<(), SynthesisError> {
    println!("\n### Running test_FqVar()...");

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

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());

    Ok(())
}

fn test_GVar() -> Result<(), SynthesisError> {
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

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());

    Ok(())
}

fn test_pairing() -> Result<(), SynthesisError> {
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

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());

    Ok(())
}

fn test_emulated_fr_fq() -> Result<(), SynthesisError> {
    println!("\n### Running test_emulated_fr_fq()...");

    let cs = ConstraintSystem::<Fq>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let a_value = Fr::rand(&mut rng);
    let b_value = Fr::rand(&mut rng);
    
    let c_value = a_value.add(b_value);

    let a = NonNativeFieldVar::<Fr, Fq>::new_witness(ark_relations::ns!(cs, "a"), || Ok(a_value))?;
    let b = NonNativeFieldVar::<Fr, Fq>::new_witness(ark_relations::ns!(cs, "b"), || Ok(b_value))?;

    let c = a.add(b);

    assert_eq!(c_value, c.value()?);

    cs.finalize();

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());

    Ok(())
}

fn test_emulated_fq_fr() -> Result<(), SynthesisError> {
    println!("\n### Running test_emulated_fq_fr()...");

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::None);

    let mut rng = ark_std::test_rng();

    let a_value = Fq::rand(&mut rng);
    let b_value = Fq::rand(&mut rng);
    
    let c_value = a_value.add(b_value);

    let a = NonNativeFieldVar::<Fq, Fr>::new_witness(ark_relations::ns!(cs, "a"), || Ok(a_value))?;
    let b = NonNativeFieldVar::<Fq, Fr>::new_witness(ark_relations::ns!(cs, "b"), || Ok(b_value))?;

    let c = a.add(b);

    assert_eq!(c_value, c.value()?);

    cs.finalize();

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());

    Ok(())
}

fn test_sha256_crh() -> Result<(), SynthesisError> {
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

    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());
    
    Ok(())
}

fn test_sha256_crh_with_proof() {
    println!("\n### Running test_sha256_crh_with_proof()...");

    use ark_groth16::Groth16;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64());

    #[derive(Clone)]
    struct Sha256Circuit {
        input: Option<Vec<u8>>,
        output: Option<Vec<u8>>,
    }
    
    impl Default for Sha256Circuit {
        fn default() -> Sha256Circuit {
            Sha256Circuit {
                // NOTE: The input length must be fixed: fix real input or apply padding
                input: Some(vec![0; 5]),
                output: Some(vec![0; 32]),
            }
        }
    }

    impl ConstraintSynthesizer<Fr> for Sha256Circuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
            let input_var = UInt8::new_witness_vec(
                ark_relations::ns!(cs, "input"), 
                self.input.ok_or(SynthesisError::AssignmentMissing).unwrap().as_slice(),
            )?;
            let output_var = UInt8::new_input_vec(
                ark_relations::ns!(cs, "output"),
                self.output.ok_or(SynthesisError::AssignmentMissing).unwrap().as_slice(),
            )?;
            let mut sha_var = Sha256Gadget::<Fr>::default();
            sha_var.update(&input_var)?;
            let sha_var_output = sha_var.finalize().unwrap().to_bytes().unwrap();

            output_var.enforce_equal(sha_var_output.as_slice())?;

            // cs.finalize() not needed here (specified inside prove() method)
            // same happens with OptimizationGoal

            Ok(())
        }
    }

    let circuit_default = Sha256Circuit::default();

    let (pk, vk) = Groth16::<Bls12_377>::setup(circuit_default, &mut rng).unwrap();

    let input = String::from("hello");
    let sha_params = <Sha256 as CRHScheme>::setup(&mut rng).unwrap();
    let output = Sha256::evaluate(&sha_params, input.as_bytes()).unwrap();
    
    let output_field = output.to_field_elements().unwrap();

    let input_vec = input.into_bytes();
    let circuit = Sha256Circuit {
        input: Some(input_vec),
        output: Some(output), 
    };

    let proof = Groth16::<Bls12_377>::prove(&pk, circuit, &mut rng).unwrap();
    // The public_input for verify() must be a &[F] element.
    // I think the circuit computation (from Vec<u8>) and the public_input are not being converted in the same way...
    assert!(Groth16::<Bls12_377>::verify(&vk, output_field.as_slice(), &proof).unwrap());

}

fn test_Fp_with_proof() {
    println!("\n### Running test_Fp_with_proof()...");

    use ark_groth16::Groth16;
    use ark_ff::Fp;

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64());

    #[derive(Clone, Debug)]
    struct FpCircuit<F: PrimeField>{
        a: F,
        b: F,
        c: F,
    }

    impl<F: PrimeField> Default for FpCircuit<F> {
        fn default() -> Self {
            FpCircuit {
                a: F::zero(),
                b: F::zero(),
                c: F::zero(),
            }
        }
    }

    impl ConstraintSynthesizer<Fr> for FpCircuit<Fr> {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> ark_relations::r1cs::Result<()> {
            let a_var = FpVar::new_witness(
                ark_relations::ns!(cs, "a"), 
                || { Ok(self.a) },
            )?;
            let b_var = FpVar::new_witness(
                ark_relations::ns!(cs, "b"), 
                || { Ok(self.b) },
            )?;
            let c_var = FpVar::new_input(
                ark_relations::ns!(cs, "c"),
                || { Ok(self.c) },
            )?;

            let result = a_var * b_var;

            c_var.enforce_equal(&result)?;

            Ok(())
        }
    }

    let default_circuit = FpCircuit::<Fr>::default();

    let (pk, vk) = Groth16::<Bls12_377>::setup(default_circuit, &mut rng).unwrap();

    let a_value = Fr::rand(&mut rng);
    let b_value = Fr::rand(&mut rng);

    let circuit = FpCircuit::<Fr> {
        a: a_value,
        b: b_value,
        c: a_value * b_value,
    };

    let proof = Groth16::<Bls12_377>::prove(&pk, circuit.clone(), &mut rng).unwrap();
    
    assert!(Groth16::<Bls12_377>::verify(&vk, &[circuit.c], &proof).unwrap());
    

}

fn main() {
    println!("Starting tests...");

    // *** ONLY GADGETS ***
    //let _ = test_uint8();
    //let _ = test_FqVar();
    //let _ = test_GVar();
    //let _ = test_pairing();
    //let _ = test_emulated_fr_fq();
    //let _ = test_emulated_fq_fr();
    //let _ = test_sha256_crh();

    // *** WITH PROOF ***
    let _ = test_sha256_crh_with_proof();
    //let _ = test_Fp_with_proof();
}
