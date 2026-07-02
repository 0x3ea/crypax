use std::io::{Read, Seek, SeekFrom};

use crate::{
    archive::format_v2::{ArchiveHeaderV2, SegmentEntry, read_header_v2, read_segment_table},
    crypto::{
        aead::{EncryptedBlob, NONCE_LEN, decrypt_segment},
        keys::ArchiveKey,
    },
    error::Result,
};

pub struct ArchiveReaderV2<R: Read + Seek> {
    reader: R,
    header: ArchiveHeaderV2,
    entries: Vec<SegmentEntry>,
    next_segment: usize,
}

impl<R: Read + Seek> ArchiveReaderV2<R> {
    pub fn open(mut reader: R) -> Result<Self> {
        let header = read_header_v2(&mut reader)?;

        reader.seek(SeekFrom::Start(header.segment_table_offset))?;
        let entries = read_segment_table(&mut reader, header.total_segments as usize)?;

        Ok(Self {
            reader,
            header,
            entries,
            next_segment: 0,
        })
    }

    pub fn salt(&self) -> [u8; 16] {
        self.header.salt
    }

    pub fn header(&self) -> &ArchiveHeaderV2 {
        &self.header
    }

    pub fn next_segment(&mut self, key: &ArchiveKey) -> Result<Option<Vec<u8>>> {
        if self.next_segment == self.entries.len() {
            return Ok(None);
        }

        let entry = &self.entries[self.next_segment];
        let ciphertext_len = entry.stored_len as usize - NONCE_LEN;
        let mut nonce_buf = [0u8; NONCE_LEN];
        self.reader.seek(SeekFrom::Start(entry.offset))?;
        self.reader.read_exact(&mut nonce_buf)?;
        let mut ciphertext_buf = vec![0u8; ciphertext_len];
        self.reader.read_exact(&mut ciphertext_buf)?;

        let blob = EncryptedBlob {
            nonce: nonce_buf,
            ciphertext: ciphertext_buf,
        };
        let raw = decrypt_segment(
            key,
            &blob,
            self.next_segment as u64,
            &self.header.archive_uuid,
            self.header.version as u16,
        )?;
        self.next_segment += 1;

        Ok(Some(raw))
    }
}
