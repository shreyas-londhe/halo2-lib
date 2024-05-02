use super::{
    constants::{get_dst_prime, get_lib_str, get_z_pad},
    util::{bits_le_to_bytes_assigned, bytes_to_bits_le_assigned, fe_to_bytes_le},
};
use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    poseidon::hasher::PoseidonHasher,
    utils::BigPrimeField,
    AssignedValue, Context,
};

fn calc_msg_prime_output_length(msg_length: usize) -> usize {
    msg_length + 64 + 2 + 50 + 1 // msg + z_pad + lib_str + dst_prime + 0
}

fn msg_prime<F: BigPrimeField>(
    ctx: &mut Context<F>,
    msg_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let zero = ctx.load_zero();

    let z_pad = get_z_pad(ctx);
    let lib_str = get_lib_str(ctx);
    let dst_prime = get_dst_prime(ctx);

    let msg_prime_len = calc_msg_prime_output_length(msg_bytes.len());
    let mut msg_prime = Vec::<AssignedValue<F>>::with_capacity(msg_prime_len);

    // msg_prme = z_pad ...
    msg_prime.extend(z_pad);

    // msg_prme = z_pad || msg ...
    msg_prime.extend(msg_bytes);

    // msg_prme = z_pad || msg || lib_str ...
    msg_prime.extend(lib_str);

    // msg_prme = z_pad || msg || lib_str || 0 ...
    msg_prime.push(zero);

    // msg_prme = z_pad || msg || lib_str || 0 || dst_prime
    msg_prime.extend(dst_prime);

    assert_eq!(msg_prime.len(), msg_prime_len);
    msg_prime
}

fn hash_msg_prime_to_b0<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    poseidon_hasher: &PoseidonHasher<F, 3, 2>,
    msg_prime_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let len = ctx.load_witness(F::from(msg_prime_bytes.len() as u64));
    let hash = poseidon_hasher.hash_var_len_array(ctx, range, msg_prime_bytes, len);
    let mut hash_bytes = fe_to_bytes_le(ctx, range, hash);
    hash_bytes.reverse();

    hash_bytes
}

fn hash_bi<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    poseidon_hasher: &PoseidonHasher<F, 3, 2>,
    b_idx_byte: &AssignedValue<F>,
    b0_bytes: &[AssignedValue<F>],
    bi_minus_one_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    assert_eq!(b0_bytes.len(), 32);
    assert_eq!(b0_bytes.len(), bi_minus_one_bytes.len());

    let b0_bits = bytes_to_bits_le_assigned(ctx, range, b0_bytes);
    let bi_minus_one_bits = bytes_to_bits_le_assigned(ctx, range, bi_minus_one_bytes);

    let xor_bits = str_xor(ctx, range, &b0_bits, &bi_minus_one_bits);
    let xor_bytes = bits_le_to_bytes_assigned(ctx, range, &xor_bits);

    let bi_bytes = hash_b(ctx, range, poseidon_hasher, b_idx_byte, &xor_bytes);

    bi_bytes
}

fn hash_b<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    poseidon_hasher: &PoseidonHasher<F, 3, 2>,
    b_idx_byte: &AssignedValue<F>,
    b_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    assert_eq!(b_bytes.len(), 32);
    assert!(b_idx_byte.value() < &F::from(8u64));

    let dst_prime = get_dst_prime(ctx);

    let mut preimage = Vec::<AssignedValue<F>>::new();
    preimage.extend(b_bytes);
    preimage.push(*b_idx_byte);
    preimage.extend(dst_prime);

    let len = ctx.load_witness(F::from(preimage.len() as u64));
    let hash = poseidon_hasher.hash_var_len_array(ctx, range, &preimage, len);
    let mut hash_bytes = fe_to_bytes_le(ctx, range, hash);
    hash_bytes.reverse();

    hash_bytes
}

fn str_xor<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    a_bits: &[AssignedValue<F>],
    b_bits: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    assert_eq!(a_bits.len(), b_bits.len());

    let gate = range.gate();

    let mut xor = Vec::<AssignedValue<F>>::new();
    for (a_bit, b_bit) in a_bits.iter().zip(b_bits.iter()) {
        let res = gate.xor(ctx, *a_bit, *b_bit);
        xor.push(res);
    }

    xor
}

pub(crate) fn expand_message_xmd<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    poseidon_hasher: &PoseidonHasher<F, 3, 2>,
    msg_bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    let one = ctx.load_constant(F::from(1));
    let two = ctx.load_constant(F::from(2));
    let three = ctx.load_constant(F::from(3));

    let msg_prime_bytes = msg_prime(ctx, msg_bytes);
    let b0 = hash_msg_prime_to_b0(ctx, range, poseidon_hasher, &msg_prime_bytes);
    let b1 = hash_b(ctx, range, poseidon_hasher, &one, &b0);
    let b2 = hash_bi(ctx, range, poseidon_hasher, &two, &b0, &b1);
    let b3 = hash_bi(ctx, range, poseidon_hasher, &three, &b0, &b2);

    let mut expanded_msg = [b1, b2, b3].concat();
    expanded_msg.reverse();

    expanded_msg
}
