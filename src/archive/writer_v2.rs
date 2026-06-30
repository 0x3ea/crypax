use std::{
    cmp::min,
    io::{Read, Seek, SeekFrom, Write},
};

use crate::{
    archive::format_v2::{
        ArchiveHeaderV2, BLAKE3_PREFIX_LEN, EOF_MARKER_SIZE, HEADER_SIZE, SEGMENT_ENTRY_SIZE,
        SegmentEntry, write_eof_marker, write_header_v2, write_segment_table,
    },
    chunks::{
        erasure::{ErasurePlan, encode_recovery_shards},
        split::DataShard,
    },
    crypto::{aead::encrypt_segment, keys::ArchiveKey},
    error::{Result, invalid_input},
};

pub struct ArchiveWriterV2<W: Read + Write + Seek> {
    writer: W,
    entries: Vec<SegmentEntry>,
    current_offset: u64,
    key: ArchiveKey,
    header: ArchiveHeaderV2,
}

impl<W: Read + Write + Seek> ArchiveWriterV2<W> {
    pub fn new(mut writer: W, salt: [u8; 16], key: [u8; 32]) -> Result<Self> {
        // Step 1: reserve 512B header (zeroed; real header written back at finalize).
        let buf = vec![0u8; HEADER_SIZE];
        writer.write_all(&buf)?;
        let mut header = ArchiveHeaderV2::default();
        rand::fill(&mut header.archive_uuid);
        header.salt = salt;
        Ok(Self {
            writer,
            entries: Vec::new(),
            current_offset: HEADER_SIZE as u64,
            key: ArchiveKey::from_bytes(key),
            header,
        })
    }

    pub fn write_segment(&mut self, plaintext: &[u8]) -> Result<()> {
        // Step 2: AEAD-encrypt one segment and append it to the data region.
        let segment_index = self.header.total_segments as u64;
        self.header.total_segments += 1;
        self.header.total_plaintext_size += plaintext.len() as u64;
        let segment = encrypt_segment(
            &self.key,
            plaintext,
            segment_index,
            &self.header.archive_uuid,
            self.header.version as u16,
        )?;

        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| invalid_input("segment exceeds 4 GiB limit"))?;
        let ciphertext_len = u32::try_from(segment.ciphertext.len() + segment.nonce.len())
            .map_err(|_| invalid_input("segment ciphertext exceeds 4 GiB limit"))?;

        let entry = SegmentEntry {
            offset: self.current_offset,
            ciphertext_len,
            plaintext_len,
            blake3_prefix: blake3::hash(plaintext).as_bytes()[..BLAKE3_PREFIX_LEN]
                .try_into()
                .unwrap(),
            reserved: [0u8; 8],
        };
        self.entries.push(entry);

        self.current_offset += ciphertext_len as u64;
        self.writer.write_all(&segment.ciphertext)?;
        self.writer.write_all(&segment.nonce)?;

        Ok(())
    }

    pub fn finalize(mut self) -> Result<()> {
        // Step 3: append segment table.
        self.header.segment_table_offset = self.current_offset;
        write_segment_table(&self.entries, &mut self.writer)?;
        self.current_offset += (self.entries.len() * SEGMENT_ENTRY_SIZE) as u64;

        // Step 5: append RS parity region (re-reads the data region).
        self.header.rs_parity_region_offset = self.current_offset;
        self.write_rs_parity()?;

        // Step 6: append footer copy + EOF marker.
        self.write_footer()?;

        // Step 7: seek to 0 and write the real 512B header.
        self.writer.seek(SeekFrom::Start(0))?;
        write_header_v2(&self.header, &mut self.writer)?;
        Ok(())
    }

    fn write_rs_parity(&mut self) -> Result<()> {
        let (stripe_cell_count, cell_size) = (
            self.header.rs_data_cells_per_stripe as usize,
            self.header.cell_size as usize,
        );

        let erasure_plan = ErasurePlan {
            data_shards: stripe_cell_count,
            parity_shards: self.header.rs_parity_cells_per_stripe as usize,
        };

        let read_end = self.current_offset;
        let mut write_end = self.current_offset;

        let mut byte_start = HEADER_SIZE as u64;
        let mut stripe_buf = vec![0u8; stripe_cell_count * cell_size];
        let mut cells: Vec<DataShard> = Vec::with_capacity(stripe_cell_count);

        self.writer.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        while byte_start < read_end {
            let to_read = min(stripe_buf.len(), (read_end - byte_start) as usize);
            self.writer.read_exact(&mut stripe_buf[..to_read])?;
            byte_start += to_read as u64;

            for i in (0..to_read).step_by(cell_size) {
                let mut cell = stripe_buf[i..min(i + cell_size, to_read)].to_vec();
                cell.resize(cell_size, 0);
                cells.push(DataShard {
                    index: i / cell_size,
                    data: cell,
                });
            }
            while cells.len() < stripe_cell_count {
                cells.push(DataShard {
                    index: cells.len(),
                    data: vec![0u8; cell_size],
                });
            }

            let rs_paritys = encode_recovery_shards(&cells, &erasure_plan)?;
            cells.clear();
            self.writer.seek(SeekFrom::Start(write_end))?;
            write_end += (rs_paritys.len() * cell_size) as u64;
            for rs_parity in rs_paritys {
                self.writer.write_all(&rs_parity.data)?;
            }

            self.writer.seek(SeekFrom::Start(byte_start))?;
        }
        self.writer.seek(SeekFrom::Start(write_end))?;
        self.current_offset = write_end;
        Ok(())
    }

    fn write_footer(&mut self) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        let mut footer_body = Vec::new();
        self.header.footer_offset = self.current_offset;
        write_header_v2(&self.header, &mut footer_body)?;
        write_segment_table(&self.entries, &mut footer_body)?;
        hasher.update(&footer_body);
        let footer_blake3_prefix: [u8; BLAKE3_PREFIX_LEN] =
            hasher.finalize().as_bytes()[..BLAKE3_PREFIX_LEN].try_into()?;
        let footer_offset = self.current_offset;

        self.writer.write_all(&footer_body)?;
        write_eof_marker(&mut self.writer, footer_offset, footer_blake3_prefix)?;

        self.current_offset += footer_body.len() as u64 + EOF_MARKER_SIZE as u64;
        Ok(())
    }
}
