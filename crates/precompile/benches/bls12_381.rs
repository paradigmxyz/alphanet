use alphanet_precompile::bls12_381;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use revm_primitives::{hex::FromHex, Bytes};

pub fn criterion_benchmark(c: &mut Criterion) {
    let sample_input = Bytes::from_hex("00000000000000000000000000000000150b75e9e9c03ada40b607f3d648bd6c40269aba3a1a992986dc005c9fde80bb1605266add0819641a0ca702d67bceed00000000000000000000000000000000083b43df032654f2dce90c8049ae4872a39f9cd860f08512930f43898e0f1e5625a5620818788797f3ca68134bc27d220000000000000000000000000000000012dae9aee13ed6ad52fe664bf7d2d0a1f134f0951d0d7ce5184e223bde164f6860967f9aaaa44fa6654d77d026c52d2a000000000000000000000000000000000f71889d64ec2f7da7319994883eb8bd1c753e6cdd3495036b630c35f07118a1bc10568c411ecbdf468a9cdaa9b4811b").unwrap();
    let gas_limit = 100_000;

    c.bench_function("g1_add", |b| {
        b.iter(|| bls12_381::g1_add(black_box(&sample_input), black_box(gas_limit)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
