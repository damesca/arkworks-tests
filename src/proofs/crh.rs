use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal, ConstraintSynthesizer};
use ark_bls12_377::{
    Fr,
    Bls12_377,
};
use ark_std::{
    rand::{SeedableRng, RngCore},
    UniformRand,
};
use ark_snark::{
    CircuitSpecificSetupSNARK,
    SNARK
};
use ark_r1cs_std::{
    uint8::UInt8,
    ToBytesGadget,
    eq::EqGadget,
};
use ark_crypto_primitives::crh::{
    sha256::{constraints::{Sha256Gadget, DigestVar}, Sha256}, 
    CRHScheme, 
    CRHSchemeGadget,
};
use ark_ff::ToConstraintField;

pub fn test_sha256_crh_with_proof() {
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