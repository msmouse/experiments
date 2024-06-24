use aptos_crypto::HashValue;
use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::hash::{EllipticCurveMultisetHash, MultisetHash};
use rayon::prelude::*;

fn inc_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("inc_hashing");

    const SET_SIZE: usize = 10000;

    let mut inc_hash = EllipticCurveMultisetHash::default();
    let mut updates = Vec::new();

    for _ in 0..SET_SIZE {
        let old = HashValue::random();
        let new = HashValue::random();
        inc_hash.insert(old.as_slice());
        updates.push((old, new));
    }

    group.throughput(criterion::Throughput::Elements(SET_SIZE as u64));

    group.bench_function("single_thread", |b| {
        b.iter(|| {
            for (old, new) in &updates {
                inc_hash.remove(old.as_slice());
                inc_hash.insert(new.as_slice());
            }
        })
    });
}

fn inc_hash_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("inc_hashing_parallel");

    const SET_SIZE: usize = 10000;

    // Fix Rayon threadpool size to 8, which is realistic as in the current production setting
    // and benchmarking result will be more stable across different machines.
    rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .thread_name(|index| format!("rayon-global-{}", index))
        .build_global()
        .expect("Failed to build rayon global thread pool.");

    let updates: Vec<_> = (0..SET_SIZE)
        .into_par_iter()
        .with_min_len(100)
        .map(|_| (HashValue::random(), HashValue::random()))
        .collect();

    let mut inc_hash = updates
        .par_iter()
        .fold(
            || EllipticCurveMultisetHash::default(),
            |mut inc_hash, (old, _new)| {
                inc_hash.insert(old.as_slice());
                inc_hash
            },
        )
        .reduce(
            || EllipticCurveMultisetHash::default(),
            |mut inc_hash, other_inc_hash| {
                inc_hash.union(&other_inc_hash);
                inc_hash
            },
        );

    group.throughput(criterion::Throughput::Elements(SET_SIZE as u64));

    group.bench_function("multi_thread", |b| {
        b.iter(|| {
            let diff = updates
                .par_iter()
                .fold(
                    || EllipticCurveMultisetHash::default(),
                    |mut inc_hash, (old, new)| {
                        inc_hash.remove(old.as_slice());
                        inc_hash.insert(new.as_slice());
                        inc_hash
                    },
                )
                .reduce(
                    || EllipticCurveMultisetHash::default(),
                    |mut inc_hash, other_inc_hash| {
                        inc_hash.union(&other_inc_hash);
                        inc_hash
                    },
                );
            inc_hash.union(&diff)
        })
    });
}

fn num_full_tree_nodes(arity: usize, levels: usize) -> usize {
    (arity.pow(levels as u32) - 1) / (arity - 1)
}

fn complete_merkle_tree_sim(
    group: &mut BenchmarkGroup<WallTime>,
    batch_size_k: usize,
    set_size_m: usize,
    arity: usize,
) {
    let name = format!("arity_{}_leaves_{}m_batch_{}k", arity, set_size_m, batch_size_k);
    println!("-- {name}: calculating parameters");

    let total_levels = ((set_size_m * 1024 * 1024) as f64).log(arity as f64).ceil() as usize;
    let total_nodes = num_full_tree_nodes(arity, total_levels);
    let total_memory_m = total_nodes * 32 / 1024 / 1024;

    let overlapping_top_levels = ((batch_size_k * 1024) as f64).log(arity as f64).floor() as usize + 1;
    let sparse_levels = total_levels - overlapping_top_levels;
    let total_hashing =
        batch_size_k * 1024 * sparse_levels + num_full_tree_nodes(arity, overlapping_top_levels);
    let disk_bytes_per_update = total_hashing * 32 / batch_size_k / 1024;

    println!("(not counting leaves):");
    print!("{{name: '{name}', ");
    print!(" set_size_m: {set_size_m}, ");
    print!(" batch_size_k: {batch_size_k}, ");
    print!(" arity: {arity}, ");
    print!(" total_levels: {total_levels}, ");
    print!(" total_memory_m: {total_memory_m}, ");
    print!("  overlapping_top_levels: {overlapping_top_levels}, ");
    print!("  sparse_levels: {sparse_levels}, ");
    print!("  total_hashing: {total_hashing}, ");
    print!("  disk_bytes_per_update: {disk_bytes_per_update}");
    print!("}}\n\n\n");

    let mut hashings = Vec::new();
    for _ in 0..total_hashing {
        let mut siblings = Vec::new();
        for _ in 0..arity {
            siblings.push(HashValue::random());
        }
        hashings.push(siblings);
    }

    group.throughput(criterion::Throughput::Elements(batch_size_k as u64 * 1024));
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

    for set_size_m in [16, 64, 128, 1_000, 10_000, 100_000] {
        for batch_size_k in [1, 10, 100] {
            for arity in [2, 4, 8, 16, 32, 64, 256] {
                complete_merkle_tree_sim(&mut group, batch_size_k, set_size_m, arity);
            }
        }
    }
}

criterion_group!(
    name = hashing;
    config = Criterion::default();
    targets = inc_hash, inc_hash_parallel, complete_merkle_tree_sims,
);

criterion_main!(hashing);
