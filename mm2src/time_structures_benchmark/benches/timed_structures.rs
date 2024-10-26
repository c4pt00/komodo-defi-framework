use common::time_cache::TimeCache;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use timed_map::{MapKind, StdClock, TimedMap};

fn benchmark_timed_structures(c: &mut Criterion) {
    let mut group = c.benchmark_group("Timed Data Structures");

    let sizes = vec![100, 1_000, 10_000];
    let expire_duration = Duration::from_secs(60);

    // Benchmark insertion
    for size in &sizes {
        group.bench_with_input(BenchmarkId::new("TimedMap_FxHash/insert", size), size, |b, size| {
            b.iter(|| {
                let mut map: TimedMap<StdClock, _, _> =
                    TimedMap::new_with_map_kind(MapKind::FxHashMap).expiration_tick_cap(500);
                for i in 0..*size {
                    map.insert_expirable(i, i, expire_duration);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("TimeCache/insert", size), size, |b, size| {
            b.iter(|| {
                let mut cache = TimeCache::new(expire_duration);
                for i in 0..*size {
                    cache.insert(i, i);
                }
            });
        });
    }

    // Benchmark retrieval
    for size in &sizes {
        group.bench_with_input(BenchmarkId::new("TimedMap_FxHash/get", size), size, |b, size| {
            let mut map: TimedMap<StdClock, _, _> =
                TimedMap::new_with_map_kind(MapKind::FxHashMap).expiration_tick_cap(500);
            for i in 0..*size {
                map.insert_expirable(i, i, expire_duration);
            }

            b.iter(|| {
                for i in 0..*size {
                    black_box(map.get_unchecked(&i));
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("TimeCache/get", size), size, |b, size| {
            let mut cache = TimeCache::new(expire_duration);
            for i in 0..*size {
                cache.insert(i, i);
            }

            b.iter(|| {
                for i in 0..*size {
                    black_box(cache.get(&i));
                }
            });
        });
    }

    // Benchmark removal
    for size in &sizes {
        group.bench_with_input(BenchmarkId::new("TimedMap_FxHash/remove", size), size, |b, size| {
            b.iter_batched(
                || {
                    let mut map: TimedMap<StdClock, _, _> =
                        TimedMap::new_with_map_kind(MapKind::FxHashMap).expiration_tick_cap(500);
                    for i in 0..*size {
                        map.insert_expirable(i, i, expire_duration);
                    }
                    map
                },
                |mut map| {
                    for i in 0..*size {
                        black_box(map.remove_unchecked(&i));
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("TimeCache/remove", size), size, |b, size| {
            b.iter_batched(
                || {
                    let mut cache = TimeCache::new(expire_duration);
                    for i in 0..*size {
                        cache.insert(i, i);
                    }
                    cache
                },
                |mut cache| {
                    for i in 0..*size {
                        black_box(cache.remove(i));
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // Mixed operations benchmark
    for size in &sizes {
        group.bench_with_input(BenchmarkId::new("TimedMap_FxHash/mixed_ops", size), size, |b, size| {
            b.iter(|| {
                let mut map: TimedMap<StdClock, _, _> =
                    TimedMap::new_with_map_kind(MapKind::FxHashMap).expiration_tick_cap(500);
                for i in 0..*size {
                    map.insert_expirable(i, i, expire_duration);
                }
                for i in 0..*size {
                    black_box(map.get_unchecked(&i));
                }
                for i in 0..(*size / 2) {
                    black_box(map.remove_unchecked(&i));
                }
                for i in 0..(*size / 2) {
                    map.insert_expirable(i, i * 2, expire_duration);
                }
            });
        });

        group.bench_with_input(BenchmarkId::new("TimeCache/mixed_ops", size), size, |b, size| {
            b.iter(|| {
                let mut cache = TimeCache::new(expire_duration);
                for i in 0..*size {
                    cache.insert(i, i);
                }
                for i in 0..*size {
                    black_box(cache.get(&i));
                }
                for i in 0..(*size / 2) {
                    black_box(cache.remove(i));
                }
                for i in 0..(*size / 2) {
                    cache.insert(i, i * 2);
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_timed_structures);
criterion_main!(benches);
