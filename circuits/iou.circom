pragma circom 2.1.5;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/comparators.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./ecdsa/ecdsa.circom";



template Array2Registers(){
   signal input in[256];
   signal output out[4];
   var temp[64];
   signal register[4][64];
   for(var i = 1; i < 5; i++){
      for(var j = 0; j + ((i - 1) * 64) < 64 * i; j++){
         temp[j] = in[j];
      }
      register[i - 1] <== temp;
   }

   var bits2numr0 = Bits2Num(64)(register[0]);
   var bits2numr1 = Bits2Num(64)(register[1]);
   var bits2numr2 = Bits2Num(64)(register[2]);
   var bits2numr3 = Bits2Num(64)(register[3]);

   out <== [bits2numr0, bits2numr1, bits2numr2, bits2numr3];
}

template iou(){
   signal input step_in[3];
   signal output step_out[3];

   signal note_id <== step_in[0];
   signal index <== step_in[1];
   signal state_in <== step_in[2];
   signal input prevBlinder;
   signal input inBlinder;
   signal input changeBlinder;
   signal input transferBlinder;
   signal input inputVal;
   signal input outputVal;
   signal input input_index;
   signal input signature[2];
   signal input nullifierKey;
   signal input pubkey[2];
   signal input receiver;

   // recover sender
   var identityCommitment = Poseidon(2)([nullifierKey, pubkey[0]]);
   // TODO n_in_pre
   // recover input note
   var input_note = Poseidon(5)([note_id, index,inputVal,identityCommitment,input_index]);
   // recover blinded input note
   var blinded_input_node = Poseidon(2)([input_note, inBlinder]);
   // TODO add dir
   var state_in_recovery = Poseidon(2)([blinded_input_node, prevBlinder]);
   component IsEqual = IsEqual();
   IsEqual.in <== [state_in, state_in_recovery];
   // recover nullifier
   var rec_nullifier = Poseidon(2)([identityCommitment, blinded_input_node]);
   // recover change
   var note_change = Poseidon(6)([note_id, index + 1, input_note, inputVal - outputVal, identityCommitment, 0]);
   // blind transfer
   var blinded_change = Poseidon(2)([note_change, changeBlinder]);
   // recover transfer
   var note_transfer = Poseidon(6)([note_id, index + 1, input_note, outputVal, receiver, 1]);
   // blind transfer
   var blinded_transfer = Poseidon(2)([note_transfer, transferBlinder]);
   // recover transition
   var recover_trans = Poseidon(3)([state_in, blinded_change, blinded_transfer]);
   // Check zero sum
   // TODO check 251 bits 
   component GreaterEqThan = GreaterEqThan(251);
   GreaterEqThan.in <== [inputVal, outputVal];
   GreaterEqThan.out === 1;
   // TODO Check signature
   var message = Poseidon(2)([state_in, recover_trans]);
   component message2bits = Num2Bits(256);
   message2bits.in <== message;
   //var message_bits = num2bits.out;
   component message2registers = Array2Registers();
   message2registers.in <== message2bits.out;

   component signature_r2bits = Num2Bits(256);
   signature_r2bits.in <== signature[0];
   component signature_r2registers = Array2Registers();
   signature_r2registers.in <== signature_r2bits.out;

   component signature_s2bits = Num2Bits(256);
   signature_s2bits.in <== signature[1];
   component signature_s2registers = Array2Registers();
   signature_s2registers.in <== signature_s2bits.out;

   component pubkeyx2bits = Num2Bits(256);
   pubkeyx2bits.in <== pubkey[0];
   component pubkeyx2registers = Array2Registers();
   pubkeyx2registers.in <== pubkeyx2bits.out;

   component pubkeyy2bits = Num2Bits(256);
   pubkeyy2bits.in <== pubkey[1];
   component pubkeyy2registers = Array2Registers();
   pubkeyy2registers.in <== pubkeyy2bits.out;

   var pubkey_ecdsa[2][4] = [pubkeyx2registers.out, pubkeyy2registers.out];
   // signature, message, pubkey
   component sign = ECDSAVerifyNoPubkeyCheck(64, 4);
   sign.r <== signature_r2registers.out;
   sign.s <== signature_s2registers.out;
   sign.msghash <== message2registers.out;
   sign.pubkey <== pubkey_ecdsa;


}

component main { public [step_in] } = iou();