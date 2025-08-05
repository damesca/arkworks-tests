use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError, OptimizationGoal, ConstraintSynthesizer};
use ark_bls12_377::{
    Fq as Fq_bls,
    //constraints::{G1Var, G2Var},
    G1Projective,
    G2Projective,
    G1Affine,
    G2Affine,
    Bls12_377,
    Config,
};
use ark_bw6_761::{
    Fr as Fr_bw,
    BW6_761,
};
use ark_std::{
    rand::{SeedableRng, RngCore},
    UniformRand,
};
use ark_r1cs_std::{
    alloc::{AllocVar}, 
    eq::EqGadget,
    ToBytesGadget,
    pairing::PairingVar, 
    R1CSVar
};
use ark_ec::pairing::{
    Pairing, // To call "native" pairing()
    PairingOutput,
};

use ark_ec::CurveGroup; // To use into_affine()
use ark_snark::{
    CircuitSpecificSetupSNARK,
    SNARK,
};

type Bls12G1 = <Bls12_377 as Pairing>::G1;
type Bls12G2 = <Bls12_377 as Pairing>::G2;
type Bls12Target = <Bls12_377 as Pairing>::TargetField;
type Bls12G1Var = ark_bls12_377::constraints::G1Var;
type Bls12G2Var = ark_bls12_377::constraints::G2Var;
type Bls12TargetVar = ark_bls12_377::constraints::Fq12Var;
type Bls12PairingVar = ark_bls12_377::constraints::PairingVar;

pub fn test_pairing_with_proof() {
    println!("\n### Running test_pairing_with_proof()...");

    use ark_groth16::Groth16;

    // Pairing with Fq over bls12_377
    // Groth16 proof with Fr over bw6_761

    //let mut rng = ark_std::test_rng();
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(ark_std::test_rng().next_u64());

    #[derive(Clone, Debug)]
    struct PairingCircuit {
        element_g1: Option<Bls12G1>,
        element_g2: Option<Bls12G2>,
        //element_gt: Bls12Target,
        element_gt: PairingOutput<Bls12_377>,
    }

    impl Default for PairingCircuit {
        fn default() -> PairingCircuit {
            let mut rng = ark_std::test_rng();
            let eg1 = Bls12G1::rand(&mut rng);
            let eg2 = Bls12G2::rand(&mut rng);
            let pc = PairingCircuit {
                // NOTE: The input length must be fixed: fix real input or apply padding
                element_g1: Some(eg1),
                element_g2: Some(eg2),
                element_gt: <Bls12_377 as Pairing>::pairing(eg1, eg2),
            };
            pc
        }
    }

    impl ConstraintSynthesizer<Fr_bw> for PairingCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr_bw>) -> ark_relations::r1cs::Result<()> {

            let a_var = Bls12G1Var::new_witness(
                ark_relations::ns!(cs, "a"), 
                || Ok(self.element_g1.unwrap().into_affine())
            )?;            
            let b_var = Bls12G2Var::new_witness(
                ark_relations::ns!(cs, "b"), 
                || Ok(self.element_g2.unwrap().into_affine())
            )?;
            // pub type Fp12Var<P> = QuadExtVar<Fp6Var<<P as Fp12Config>::Fp6Config>, Fp12ConfigWrapper<P>>;
            let pairing_native_var = Bls12TargetVar::new_input(
                ark_relations::ns!(cs, "c"),
                || Ok(self.element_gt.0)
            );

            let a_var_prep = Bls12PairingVar::prepare_g1(&a_var)?;
            let b_var_prep = Bls12PairingVar::prepare_g2(&b_var)?;
            let pairing_var = Bls12PairingVar::pairing(a_var_prep, b_var_prep)?;

            pairing_var.enforce_equal(&pairing_native_var.unwrap());

            Ok(())
        }
    }

    let circuit_default = PairingCircuit::default();

    let (pk, vk) = Groth16::<BW6_761>::setup(circuit_default, &mut rng).unwrap();

    let circuit = PairingCircuit::default();

    let proof = Groth16::<BW6_761>::prove(&pk, circuit.clone(), &mut rng).unwrap();

    let public_input: Vec<_> = circuit.element_gt.0.to_base_prime_field_elements().map(|x| x).collect();

    assert!(Groth16::<BW6_761>::verify(&vk, public_input.as_slice(), &proof).unwrap());


}