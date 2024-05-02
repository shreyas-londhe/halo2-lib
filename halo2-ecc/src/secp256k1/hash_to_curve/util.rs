use halo2_base::{
    gates::{GateInstructions, RangeChip, RangeInstructions},
    utils::{fe_to_biguint, BigPrimeField},
    AssignedValue, Context, QuantumCell,
};
use itertools::Itertools;
use num_bigint::{BigUint, ToBigInt};

use crate::{
    bigint::{CRTInteger, OverflowInteger, ProperCrtUint},
    fields::FieldChip,
    secp256k1::FpChip,
};

pub(crate) fn byte_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    byte: &AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    range.range_check(ctx, *byte, 8);
    range.gate().num_to_bits(ctx, *byte, 8)
}

pub(crate) fn bytes_to_bits_le_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bytes.iter().flat_map(|byte| byte_to_bits_le_assigned(ctx, range, byte)).collect_vec()
}

pub(crate) fn bits_le_to_byte_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> AssignedValue<F> {
    assert_eq!(bits.len(), 8);
    let _ = bits.iter().map(|bit| range.gate().assert_bit(ctx, *bit));
    range.gate().bits_to_num(ctx, bits)
}

pub(crate) fn bits_le_to_bytes_assigned<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bits: &[AssignedValue<F>],
) -> Vec<AssignedValue<F>> {
    bits.chunks(8).map(|chunk| bits_le_to_byte_assigned(ctx, range, chunk)).collect_vec()
}

pub(crate) fn bytes_le_to_fe<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    bytes: &[AssignedValue<F>],
) -> AssignedValue<F> {
    let bytes_base = (0..bytes.len())
        .map(|i| QuantumCell::Constant(range.gate().pow_of_two()[i * 8]))
        .collect_vec();
    let _ = bytes.iter().map(|byte| range.range_check(ctx, *byte, 8));
    range.gate().inner_product(ctx, bytes.to_vec(), bytes_base)
}

pub fn fe_to_bytes_le<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    fe: AssignedValue<F>,
) -> Vec<AssignedValue<F>> {
    let bytes = fe.value().to_bytes_le();
    let bytes_assigned = bytes
        .iter()
        .map(|byte| {
            let assigned = ctx.load_witness(F::from(*byte as u64));
            range.range_check(ctx, assigned, 8);
            assigned
        })
        .collect_vec();
    let _fe = bytes_le_to_fe(ctx, range, &bytes_assigned);
    assert_eq!(fe.value(), _fe.value());
    ctx.constrain_equal(&fe, &_fe);

    bytes_assigned
}

pub(crate) fn limbs_le_to_bn<F: BigPrimeField>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<'_, F>,
    limbs: &[AssignedValue<F>],
    max_limb_bits: usize,
) -> ProperCrtUint<F> {
    let mut value = BigUint::from(0u64);
    for i in 0..limbs.len() {
        value += (BigUint::from(1u64) << (max_limb_bits * i)) * fe_to_biguint(limbs[i].value());
    }

    let assigned_uint = OverflowInteger::new(limbs.to_vec(), max_limb_bits);
    let assigned_native = OverflowInteger::evaluate_native(
        ctx,
        fp_chip.range().gate(),
        limbs.to_vec(),
        &fp_chip.limb_bases,
    );
    let assigned_uint = CRTInteger::new(assigned_uint, assigned_native, value.to_bigint().unwrap());

    fp_chip.carry_mod(ctx, assigned_uint)
}
