use aptos_crypto::HashValue;
use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::hash::{EllipticCurveMultisetHash as SuiIncrHash, MultisetHash};
use rust_incrhash::ristretto::RistBlakeIncHash as AlinIncrHash;

fn sui_incr_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("sui_incr_hash");

    const SET_SIZE: usize = 10000;

    let mut incr_hash = SuiIncrHash::default();
    let mut updates = Vec::new();

    for _ in 0..SET_SIZE {
        let old = HashValue::random();
        let new = HashValue::random();
        incr_hash.insert(old.as_slice());
        updates.push((old, new));
    }

    group.throughput(criterion::Throughput::Elements(SET_SIZE as u64));

    group.bench_function("sui_incr_hash", |b| {
        b.iter(|| {
            for (old, new) in &updates {
                incr_hash.remove(old.as_slice());
                incr_hash.insert(new.as_slice());
            }
        })
    });
}

fn alin_incr_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("alin_incr_hash");

    const SET_SIZE: usize = 1;

    println!("a");

    let mut incr_hash = AlinIncrHash::default();
    let mut updates = Vec::new();

    println!("b");

    for _ in 0..SET_SIZE {
        let old = HashValue::random();
        let new = HashValue::random();
        println!("b1");
        let h = AlinIncrHash::from(old.as_slice());
        println!("b1.5");
        incr_hash +=  h;
        println!("b2");
        updates.push((old, new));
    }

    println!("c");

    group.throughput(criterion::Throughput::Elements(SET_SIZE as u64));

    println!("d");

    group.bench_function("alin_incr_hash", |b| {
        b.iter(|| {
            for (old, new) in &updates {
                incr_hash -= AlinIncrHash::from(old.as_slice());
                incr_hash += AlinIncrHash::from(new.as_slice());
            }
        })
    });
}

fn complete_merkle_tree_sim(
    group: &mut BenchmarkGroup<WallTime>,
    batch_size: usize,
    set_size: usize,
    arity: usize,
) {
    let total_levels = (set_size as f64).log(arity as f64).ceil() as usize + 1;
    let overlapping_top_levels = (batch_size as f64).log(arity as f64).floor() as usize + 1;
    let sparse_levels = total_levels - overlapping_top_levels;
    let total_hashing = batch_size * sparse_levels + 2usize.pow(overlapping_top_levels as u32) - 1;
    let mut hashings = Vec::new();
    for _ in 0..total_hashing {
        let mut siblings = Vec::new();
        for _ in 0..arity {
            siblings.push(HashValue::random());
        }
        hashings.push(siblings);
    }

    let name = format!("arity_{}_leaves_{}_batch_{}", arity, set_size, batch_size);
    println!("total_levels: {total_levels}");
    println!("overlapping_top_levels: {overlapping_top_levels}");
    println!("sparse_levels: {sparse_levels}");
    println!("total_hashing: {total_hashing}");

    group.throughput(criterion::Throughput::Elements(batch_size as u64));
    group.bench_function(&name, |b| {
        b.iter(|| {
            for siblings in &hashings {
                let mut hasher = aptos_crypto::hash::DefaultHasher::new(name.as_bytes());
                for hash in siblings {
                    hasher.update(hash.as_ref());
                }
                hasher.finish();
            }
        })
    });
}

fn complete_merkle_tree_sims(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("complete_merkle_tree_sims"));

    for set_size in [
        16_000_000,
        64_000_000,
        128_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
    ] {
        for batch_size in [1_000, 10_000, 100_000] {
            for arity in [2, 4, 8, 16, 64, 256] {
                complete_merkle_tree_sim(&mut group, batch_size, set_size, arity);
            }
        }
    }
    complete_merkle_tree_sim(&mut group, 10_000, 32_000_000, 2);
}

criterion_group!(
    name = hashing;
    config = Criterion::default();
    targets = sui_incr_hash, alin_incr_hash, complete_merkle_tree_sims,
);

criterion_main!(hashing);