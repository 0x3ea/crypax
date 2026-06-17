use crypax::chunks::split::{
    MAX_DATA_SHARDS, join_data_shards, plan_chunks, split_into_data_shards,
};

#[test]
fn split_and_join_roundtrip_small_input() {
    let data = b"hello world";
    let plan = plan_chunks(data.len() as u64);
    let shards = split_into_data_shards(data, &plan);
    let restored = join_data_shards(&shards, plan.total_len).expect("join");

    assert_eq!(restored, data);
}

#[test]
fn split_and_join_roundtrip_exact_multiple() {
    let data = vec![42u8; 100];
    let plan = plan_chunks(data.len() as u64);
    let shards = split_into_data_shards(&data, &plan);
    let restored = join_data_shards(&shards, plan.total_len).expect("join");

    assert_eq!(restored, data);
}

#[test]
fn split_and_join_roundtrip_large_input() {
    let data = vec![7u8; 1_000_000];
    let plan = plan_chunks(data.len() as u64);
    let shards = split_into_data_shards(&data, &plan);
    let restored = join_data_shards(&shards, plan.total_len).expect("join");

    assert_eq!(restored, data);
}

#[test]
fn data_shards_never_exceed_max() {
    for size in [1, 100, 10_000, 1_000_000, 50_000_000] {
        let plan = plan_chunks(size);
        assert!(
            plan.data_shards <= MAX_DATA_SHARDS,
            "data_shards {} exceeds max for size {}",
            plan.data_shards,
            size
        );
        assert!(plan.data_shards >= 1);
    }
}

#[test]
fn empty_input_produces_one_shard() {
    let plan = plan_chunks(0);

    assert_eq!(plan.data_shards, 1);
    assert_eq!(plan.shard_size, 0);

    let shards = split_into_data_shards(b"", &plan);
    assert_eq!(shards.len(), 1);
    assert_eq!(shards[0].data.len(), 0);

    let restored = join_data_shards(&shards, 0).expect("join empty");
    assert!(restored.is_empty());
}

#[test]
fn all_shards_have_equal_length() {
    let data = vec![1u8; 999];
    let plan = plan_chunks(data.len() as u64);
    let shards = split_into_data_shards(&data, &plan);

    for shard in &shards {
        assert_eq!(shard.data.len(), plan.shard_size);
    }
}

#[test]
fn join_rejects_non_consecutive_shards() {
    let data = vec![0u8; 100];
    let plan = plan_chunks(data.len() as u64);
    let mut shards = split_into_data_shards(&data, &plan);

    shards.remove(0);

    let result = join_data_shards(&shards, plan.total_len);
    assert!(result.is_err());
}

#[test]
fn join_works_with_shuffled_shards() {
    let data = vec![3u8; 5000];
    let plan = plan_chunks(data.len() as u64);
    let mut shards = split_into_data_shards(&data, &plan);

    shards.reverse();

    let restored = join_data_shards(&shards, plan.total_len).expect("join shuffled");
    assert_eq!(restored, data);
}

#[test]
fn single_byte_input() {
    let data = b"x";
    let plan = plan_chunks(1);
    let shards = split_into_data_shards(data, &plan);

    assert_eq!(shards.len(), 1);
    assert_eq!(shards[0].data, b"x");

    let restored = join_data_shards(&shards, 1).expect("join single byte");
    assert_eq!(restored, data);
}
