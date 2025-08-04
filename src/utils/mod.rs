use ark_relations::r1cs::{ConstraintSystemRef};
use ark_ff::Field;

type CS<F> = ConstraintSystemRef<F>;

pub fn print_cs_details<F: Field>(cs: CS<F>) {
    println!("Num constraints: {:#?}", cs.num_constraints());
    println!("Num instance variables: {:#?}", cs.num_instance_variables());
    println!("Num witness variables: {:#?}", cs.num_witness_variables());
    println!("Optimization goal: {:#?}", cs.optimization_goal());
    println!("Constraint names: {:#?}", cs.constraint_names());
}