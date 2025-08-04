mod utils;
mod gadgets;
mod proofs;

fn main() {
    println!("Starting tests...");

    // *** ONLY GADGETS ***
    let _ = gadgets::test_uint8();
    //let _ = gadgets::test_fq_var();
    //let _ = gadgets::test_GVar();
    //let _ = gadgets::test_pairing();
    //let _ = gadgets::test_sha256_crh();
    //let _ = gadgets::test_add();
    //let _ = gadgets::test_mul();
    //let _ = gadgets::test_mul_without_reduce();

    // *** WITH PROOF ***
    //let _ = proofs::test_sha256_crh_with_proof();
    //let _ = proofs::test_fp_with_proof();
    
    //TODO: let _  = proofs::test_pairing_with_proof();
}
