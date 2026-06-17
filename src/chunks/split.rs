use crate::error::{Result, invalid_input};
use std::cmp::min;
pub const MAX_DATA_SHARDS: usize = 20;

pub struct ChunkPlan {
    pub data_shards: usize,
    pub shard_size: usize,
    pub total_len: u64,
}

pub struct DataShard {
    pub index: usize,
    pub data: Vec<u8>,
}

pub fn plan_chunks(total_len: u64) -> ChunkPlan {
    if total_len == 0 {
        return ChunkPlan {
            data_shards: 1,
            shard_size: 0,
            total_len,
        };
    }

    let shard_size = (total_len as usize).div_ceil(MAX_DATA_SHARDS);
    let data_shards = (total_len as usize).div_ceil(shard_size);

    ChunkPlan {
        data_shards,
        shard_size,
        total_len,
    }
}

pub fn split_into_data_shards(bytes: &[u8], plan: &ChunkPlan) -> Vec<DataShard> {
    let mut result = Vec::new();

    for i in 0..plan.data_shards {
        let start = i * plan.shard_size;
        let end = min(start + plan.shard_size, bytes.len());
        let mut shard_data = bytes[start..end].to_vec();
        if shard_data.len() < plan.shard_size {
            shard_data.resize(plan.shard_size, 0);
        }
        result.push(DataShard {
            index: i,
            data: shard_data,
        });
    }
    result
}

pub fn join_data_shards(shards: &[DataShard], original_len: u64) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut sorted: Vec<&DataShard> = shards.iter().collect();
    sorted.sort_by_key(|e| e.index);

    for (i, shard) in sorted.iter().enumerate() {
        if shard.index != i {
            return Err(invalid_input("shards"));
        }
    }

    for shard in &sorted {
        result.extend_from_slice(&shard.data);
    }
    result.truncate(original_len as usize);
    Ok(result)
}
