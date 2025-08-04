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
};
use ark_std::{UniformRand};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode}, eq::EqGadget, groups::bls12::{
        G1Var,
        G2Var,
        G1PreparedVar,
        G2PreparedVar,
    }, pairing::PairingVar, R1CSVar
};
use ark_ec::pairing::{
    Pairing, // To call "native" pairing()
    PairingOutput,
};
use ark_ec::bls12::G1Prepared;
use ark_ec::bls12::G2Prepared;
use ark_ec::bls12::Bls12Config;

pub fn test_pairing_with_proof() {

    // Pairing with Fq over bls12_377
    // Groth16 proof with Fr over bw6_761

    let mut rng = ark_std::test_rng();

    #[derive(Clone, Debug)]
    struct PairingCircuit {
        element_g1: Option<G1Projective>,
        element_g2: Option<G2Projective>,
        //element_gt: PairingOutput<>,
    }

    impl Default for PairingCircuit {
        fn default() -> PairingCircuit {
            let mut rng = ark_std::test_rng();
            PairingCircuit {
                // NOTE: The input length must be fixed: fix real input or apply padding
                element_g1: Some(G1Projective::rand(&mut rng)),
                element_g2: Some(G2Projective::rand(&mut rng)),
            }
        }
    }

    impl ConstraintSynthesizer<Fr_bw> for PairingCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr_bw>) -> ark_relations::r1cs::Result<()> {

            //let a = G1Var::new_witness(ark_relations::ns!(cs, "a"), || Ok(self.element_g1))?;            
            //let b = G2Var::new_witness(ark_relations::ns!(cs, "b"), || Ok(self.element_g2))?;

            Ok(())
        }
    }

    let circuit_default = PairingCircuit::default();


}