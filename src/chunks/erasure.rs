use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::{
    chunks::split::DataShard,
    error::{Result, corrupt_archive, invalid_input},
};

pub struct ErasurePlan {
    pub data_shards: usize,
    pub parity_shards: usize,
}

pub struct RecoveryShard {
    pub index: usize,
    pub data: Vec<u8>,
}

pub fn plan_erasure(data_shards: usize, redundancy_percent: u8) -> ErasurePlan {
    let mut parity_shards = (data_shards * redundancy_percent as usize).div_ceil(100);

    if redundancy_percent > 0 && parity_shards == 0 {
        parity_shards = 1;
    }
    ErasurePlan {
        data_shards,
        parity_shards,
    }
}

pub fn encode_recovery_shards(
    data: &[DataShard],
    plan: &ErasurePlan,
) -> Result<Vec<RecoveryShard>> {
    let rs = ReedSolomon::new(plan.data_shards, plan.parity_shards)
        .map_err(|e| invalid_input(format!("reed-solomon init: {e}")))?;

    let shard_size = data[0].data.len();

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(plan.data_shards + plan.parity_shards);

    for d in data {
        shards.push(d.data.clone());
    }

    for _ in 0..plan.parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    rs.encode(&mut shards)
        .map_err(|e| invalid_input(format!("reed-solomon encode: {e}")))?;

    let recovery = shards
        .drain(plan.data_shards..)
        .enumerate()
        .map(|(i, data)| RecoveryShard { index: i, data })
        .collect();

    Ok(recovery)
}

pub fn reconstruct_missing_shards(
    shards: &mut [Option<Vec<u8>>],
    plan: &ErasurePlan,
) -> Result<()> {
    let rs = ReedSolomon::new(plan.data_shards, plan.parity_shards)
        .map_err(|e| invalid_input(format!("reed-solomon init: {e}")))?;

    rs.reconstruct(shards)
        .map_err(|e| corrupt_archive(format!("reconstruction failed: {e}")))?;

    Ok(())
}
