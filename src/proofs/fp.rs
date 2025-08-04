use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal, ConstraintSynthesizer};
use ark_ff::PrimeField;
use ark_bls12_377::{
    Fr,
    Bls12_377,
};
use ark_r1cs_std::{
    fields::fp::FpVar,
    alloc::AllocVar,
    eq::EqGadget,
};
use ark_std::{
    rand::{SeedableRng, RngCore},
    UniformRand,
};
use ark_snark::{
    CircuitSpecificSetupSNARK,
    SNARK
};

pub fn test_fp_with_proof() {
    println!("\n### Running test_fp_with_proof()...");

    use ark_groth16::Groth16;

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