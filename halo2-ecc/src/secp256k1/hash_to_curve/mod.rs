use self::{hash_to_field::hash_to_field, map_to_curve::map_to_curve};
use super::Secp256k1Chip;
use crate::{bigint::ProperCrtUint, ecc::EcPoint};
use halo2_base::{poseidon::hasher::PoseidonHasher, utils::BigPrimeField, AssignedValue, Context};

pub mod constants;
pub mod expand_message_xmd;
pub mod hash_to_field;
pub mod iso_map;
pub mod map_to_curve;
pub mod util;

pub fn hash_to_curve<F: BigPrimeField>(
    ctx: &mut Context<F>,
    secp256k1_chip: &Secp256k1Chip<'_, F>,
    poseidon_hasher: &PoseidonHasher<F, 3, 2>,
    msg_bytes: &[AssignedValue<F>],
) -> EcPoint<F, ProperCrtUint<F>> {
    let fp_chip = secp256k1_chip.field_chip();

    // Step 1: u = hash_to_field(msg)
    let (u0, u1) = hash_to_field(ctx, fp_chip, poseidon_hasher, msg_bytes);

    // Step 2: Q0 = map_to_curve(u[0])
    let (q0_x, q0_y) = map_to_curve(ctx, fp_chip, &u0);

    // Step 3: Q1 = map_to_curve(u[1])
    let (q1_x, q1_y) = map_to_curve(ctx, fp_chip, &u1);

    // Step 4: return A + B
    let q0 = EcPoint::<F, ProperCrtUint<F>>::new(q0_x, q0_y);
    let q1 = EcPoint::<F, ProperCrtUint<F>>::new(q1_x, q1_y);

    let point_add = secp256k1_chip.add_unequal(ctx, q0, q1, false);

    point_add
}

#[cfg(test)]
mod test {
    use halo2_base::{
        gates::RangeInstructions,
        halo2_proofs::halo2curves::bn256::Fr,
        poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
        utils::testing::base_test,
    };

    use crate::{ecc::EccChip, secp256k1::FpChip};

    use super::hash_to_curve;

    #[derive(Default, Clone)]
    struct TestData {
        message: [u8; 4],
    }

    #[test]
    fn test_hash_to_curve() {
        base_test().k(15).lookup_bits(14).expect_satisfied(true).bench_builder(
            TestData::default(),
            TestData { message: [0x01, 0x02, 0x03, 0x04] },
            |pool, range, data: TestData| {
                let ctx = pool.main();

                let fp_chip = FpChip::<Fr>::new(range, 88, 3);
                let ecc_chip = EccChip::<Fr, FpChip<Fr>>::new(&fp_chip);

                let mut poseidon_hasher =
                    PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<8, 57, 0>());
                poseidon_hasher.initialize_consts(ctx, range.gate());

                let msg_bytes = data
                    .message
                    .iter()
                    .map(|&x| ctx.load_witness(Fr::from(x as u64)))
                    .collect::<Vec<_>>();

                let point = hash_to_curve(ctx, &ecc_chip, &poseidon_hasher, msg_bytes.as_slice());
            },
        );
    }
}
