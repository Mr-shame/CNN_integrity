#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>

using namespace libsnark;
using namespace std;

int main () {
    typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;

    // Initialize the curve parameters
    default_r1cs_gg_ppzksnark_pp::init_public_params();
  
    // Create protoboard
    protoboard<FieldT> pb;

    // Define variables
    pb_variable<FieldT> w1;
    pb_variable<FieldT> w2;
    pb_variable<FieldT> w3;
    pb_variable<FieldT> w4;
    pb_variable<FieldT> w5;
    pb_variable<FieldT> w6;
    pb_variable<FieldT> w7;
    pb_variable<FieldT> w8;
    pb_variable<FieldT> w9;
    pb_variable<FieldT> w10;
    pb_variable<FieldT> w11; 
    pb_variable<FieldT> w12; 
    pb_variable<FieldT> w13;
    pb_variable<FieldT> x1;
    pb_variable<FieldT> x2;
    pb_variable<FieldT> x3;
    pb_variable<FieldT> x4;
    pb_variable<FieldT> x5;
    pb_variable<FieldT> x6;
    pb_variable<FieldT> x7;
    pb_variable<FieldT> x8;
    pb_variable<FieldT> x9;
    pb_variable<FieldT> x10;
    pb_variable<FieldT> x11; 
    pb_variable<FieldT> x12; 
    pb_variable<FieldT> x13;
    pb_variable<FieldT> sym_1;
    pb_variable<FieldT> sym_2;
    pb_variable<FieldT> sym_3;
    pb_variable<FieldT> sym_4;
    pb_variable<FieldT> sym_5;
    pb_variable<FieldT> sym_6;
    pb_variable<FieldT> sym_7;
    pb_variable<FieldT> sym_8;
    pb_variable<FieldT> sym_9;
    pb_variable<FieldT> sym_10;
    pb_variable<FieldT> sym_11; 
    pb_variable<FieldT> sym_12; 
    pb_variable<FieldT> sym_13;
    pb_variable<FieldT> b;
    pb_variable<FieldT> out;

    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes    
    out.allocate(pb, "out");
    x1.allocate(pb, "x1");
    x2.allocate(pb, "x2");
    x3.allocate(pb, "x3");
    x4.allocate(pb, "x4");
    x5.allocate(pb, "x5");
    x6.allocate(pb, "x6");
    x7.allocate(pb, "x7");
    x8.allocate(pb, "x8");
    x9.allocate(pb, "x9");
    x10.allocate(pb, "x10");
    x11.allocate(pb, "x11");
    x12.allocate(pb, "x12");
    x13.allocate(pb, "x13");
    w1.allocate(pb, "w1");
    w2.allocate(pb, "w2");
    w3.allocate(pb, "w3");
    w4.allocate(pb, "w4");
    w5.allocate(pb, "w5");
    w6.allocate(pb, "w6");
    w7.allocate(pb, "w7");
    w8.allocate(pb, "w8");
    w9.allocate(pb, "w9");
    w10.allocate(pb, "w10");
    w11.allocate(pb, "w11");
    w12.allocate(pb, "w12");
    w13.allocate(pb, "w13");
    sym_1.allocate(pb, "sym_1");
    sym_2.allocate(pb, "sym_2");
    sym_3.allocate(pb, "sym_3");
    sym_4.allocate(pb, "sym_4");
    sym_5.allocate(pb, "sym_5");
    sym_6.allocate(pb, "sym_6");
    sym_7.allocate(pb, "sym_7");
    sym_8.allocate(pb, "sym_8");
    sym_9.allocate(pb, "sym_9");
    sym_10.allocate(pb, "sym_10");
    sym_11.allocate(pb, "sym_11");
    sym_12.allocate(pb, "sym_12");
    sym_13.allocate(pb, "sym_13");
    b.allocate(pb, "b");
    

    // This sets up the protoboard variables
    // so that the first one (out) represents the public
    // input and the rest is private input
    pb.set_input_sizes(14);

    // Add R1CS constraints to protoboard

    // x1*w1 = sym_1
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x1, w1, sym_1));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x2, w2, sym_2));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x3, w3, sym_3));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x4, w4, sym_4));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x5, w5, sym_5));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x6, w6, sym_6));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x7, w7, sym_7));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x8, w8, sym_8));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x9, w9, sym_9));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x10, w10, sym_10));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x11, w11, sym_11));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x12, w12, sym_12));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x13, w13, sym_13));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1 + sym_2 + sym_3 + sym_4 + sym_5 + sym_6 + sym_7 + sym_8 + sym_9 + sym_10 + sym_11 + sym_12 + sym_13 + b, 1, out));
    
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    // generate keypair
    const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);

    // Add public input and witness values
    pb.val(out) = 38530;

    pb.val(x1) = 1;
    pb.val(x2) = 0;
    pb.val(x3) = 0;
    pb.val(x4) = 1;
    pb.val(x5) = 0;
    pb.val(x6) = 0;
    pb.val(x7) = 1;
    pb.val(x8) = 1;
    pb.val(x9) = 0;
    pb.val(x10) = 1;
    pb.val(x11) = 0;
    pb.val(x12) = 1;
    pb.val(x13) = 0;
    
    pb.val(w1) = -126;
    pb.val(w2) = 49;
    pb.val(w3) = -48;
    pb.val(w4) = 3450;
    pb.val(w5) = -16039;
    pb.val(w6) = 3680;
    pb.val(w7) = -9;
    pb.val(w8) = -1506;
    pb.val(w9) = 312;
    pb.val(w10) = -11;
    pb.val(w11) = -930;
    pb.val(w12) = 10;
    pb.val(w13) = -489;
    
    pb.val(sym_1) = -126;
    pb.val(sym_2) = 0;
    pb.val(sym_3) = 0;
    pb.val(sym_4) = 3450;
    pb.val(sym_5) = 0;
    pb.val(sym_6) = 0;
    pb.val(sym_7) = -9;
    pb.val(sym_8) = -1506;
    pb.val(sym_9) = 0;
    pb.val(sym_10) = -11;
    pb.val(sym_11) = 0;
    pb.val(sym_12) = 10;
    pb.val(sym_13) = 0;
    
    pb.val(b) = 36722;
    

    // generate proof
    const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // verify
    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;

    return 0;
}
