use crypax::chunks::erasure::{encode_recovery_shards, plan_erasure, reconstruct_missing_shards};
use crypax::chunks::split::{plan_chunks, split_into_data_shards};

#[test]
fn plan_erasure_12_percent_at_least_one_parity() {
    for k in 1..=20 {
        let plan = plan_erasure(k, 12);
        assert!(
            plan.parity_shards >= 1,
            "k={} should have at least 1 parity shard",
            k
        );
    }
}

#[test]
fn plan_erasure_zero_percent_means_no_parity() {
    let plan = plan_erasure(10, 0);
    assert_eq!(plan.parity_shards, 0);
}

#[test]
fn plan_erasure_known_values() {
    // k=20, 12% → ceil(20*12/100) = ceil(2.4) = 3
    let plan = plan_erasure(20, 12);
    assert_eq!(plan.parity_shards, 3);

    // k=5, 12% → ceil(0.6) = 1
    let plan = plan_erasure(5, 12);
    assert_eq!(plan.parity_shards, 1);

    // k=10, 50% → ceil(5.0) = 5
    let plan = plan_erasure(10, 50);
    assert_eq!(plan.parity_shards, 5);
}

#[test]
fn encode_and_reconstruct_roundtrip() {
    let data = vec![99u8; 5000];
    let chunk_plan = plan_chunks(data.len() as u64);
    let data_shards = split_into_data_shards(&data, &chunk_plan);

    let erasure_plan = plan_erasure(chunk_plan.data_shards, 12);
    let recovery = encode_recovery_shards(&data_shards, &erasure_plan).expect("encode");

    assert_eq!(recovery.len(), erasure_plan.parity_shards);

    // Simulate losing one data shard
    let mut all_shards: Vec<Option<Vec<u8>>> = Vec::new();
    for d in &data_shards {
        all_shards.push(Some(d.data.clone()));
    }
    for r in &recovery {
        all_shards.push(Some(r.data.clone()));
    }

    // Remove first data shard
    all_shards[0] = None;

    reconstruct_missing_shards(&mut all_shards, &erasure_plan).expect("reconstruct");

    // Verify reconstruction matches original
    assert_eq!(all_shards[0].as_ref().unwrap(), &data_shards[0].data);
}

#[test]
fn reconstruct_fails_when_too_many_missing() {
    let data = vec![42u8; 1000];
    let chunk_plan = plan_chunks(data.len() as u64);
    let data_shards = split_into_data_shards(&data, &chunk_plan);

    let erasure_plan = plan_erasure(chunk_plan.data_shards, 12);
    let recovery = encode_recovery_shards(&data_shards, &erasure_plan).expect("encode");

    let mut all_shards: Vec<Option<Vec<u8>>> = Vec::new();
    for d in &data_shards {
        all_shards.push(Some(d.data.clone()));
    }
    for r in &recovery {
        all_shards.push(Some(r.data.clone()));
    }

    // Remove more than m shards
    let to_remove = erasure_plan.parity_shards + 1;
    for shard in all_shards.iter_mut().take(to_remove) {
        *shard = None;
    }

    let result = reconstruct_missing_shards(&mut all_shards, &erasure_plan);
    assert!(result.is_err());
}

#[test]
fn reconstruct_with_max_allowed_missing() {
    let data = vec![7u8; 10_000];
    let chunk_plan = plan_chunks(data.len() as u64);
    let data_shards = split_into_data_shards(&data, &chunk_plan);

    let erasure_plan = plan_erasure(chunk_plan.data_shards, 12);
    let recovery = encode_recovery_shards(&data_shards, &erasure_plan).expect("encode");

    let mut all_shards: Vec<Option<Vec<u8>>> = Vec::new();
    for d in &data_shards {
        all_shards.push(Some(d.data.clone()));
    }
    for r in &recovery {
        all_shards.push(Some(r.data.clone()));
    }

    // Remove exactly m shards (maximum recoverable)
    for shard in all_shards.iter_mut().take(erasure_plan.parity_shards) {
        *shard = None;
    }

    reconstruct_missing_shards(&mut all_shards, &erasure_plan).expect("reconstruct max missing");

    // Verify all data shards restored
    for (i, d) in data_shards.iter().enumerate() {
        assert_eq!(all_shards[i].as_ref().unwrap(), &d.data);
    }
}

#[test]
fn recovery_shards_have_same_length_as_data_shards() {
    let data = vec![1u8; 3333];
    let chunk_plan = plan_chunks(data.len() as u64);
    let data_shards = split_into_data_shards(&data, &chunk_plan);

    let erasure_plan = plan_erasure(chunk_plan.data_shards, 12);
    let recovery = encode_recovery_shards(&data_shards, &erasure_plan).expect("encode");

    let expected_len = data_shards[0].data.len();
    for r in &recovery {
        assert_eq!(r.data.len(), expected_len);
    }
}
