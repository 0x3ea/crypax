use std::{
    fs::File,
    io::{Cursor, Read},
};

use crate::{
    error::{Result, invalid_input},
    fs::{
        pack::{PACK_FORMAT_VERSION, PACK_MAGIC, serialize_entry_framing},
        scan::{EntryKind, SourceTree},
    },
};

pub struct PackStream<'a> {
    tree: &'a SourceTree,
    index: usize,
    entry_framing: Option<Cursor<Vec<u8>>>,
    file: Option<(File, u64)>,
    buf: Vec<u8>,
    segment_size: usize,
    filled: usize,
}

impl<'a> PackStream<'a> {
    pub fn new(tree: &'a SourceTree, segment_size: usize) -> Result<Self> {
        if segment_size == 0 || segment_size > u32::MAX as usize {
            return Err(invalid_input("invalid segment size"));
        }

        let mut preamble = Vec::new();
        preamble.extend_from_slice(PACK_MAGIC);
        preamble.extend_from_slice(&PACK_FORMAT_VERSION.to_le_bytes());
        preamble.extend_from_slice(&(tree.entries.len() as u32).to_le_bytes());

        Ok(Self {
            tree,
            index: 0,
            entry_framing: Some(Cursor::new(preamble)),
            file: None,
            buf: vec![0u8; segment_size],
            segment_size,
            filled: 0,
        })
    }

    pub fn next_segment(&mut self) -> Result<Option<&[u8]>> {
        self.filled = 0;
        while self.filled < self.segment_size {
            let space = self.segment_size - self.filled;
            if let Some(cursor) = &mut self.entry_framing {
                let remaining = cursor.get_ref().len() - cursor.position() as usize;
                let take = remaining.min(space);
                cursor.read_exact(&mut self.buf[self.filled..self.filled + take])?;
                self.filled += take;

                if cursor.position() as usize == cursor.get_ref().len() {
                    self.entry_framing = None;
                }
            } else if let Some((mut file, mut remaining)) = self.file.take() {
                let take = space.min(remaining as usize);
                file.read_exact(&mut self.buf[self.filled..self.filled + take])?;
                self.filled += take;
                remaining -= take as u64;

                if remaining > 0 {
                    self.file = Some((file, remaining));
                }
            } else if self.index < self.tree.entries.len() {
                let entry = &self.tree.entries[self.index];
                self.index += 1;
                self.entry_framing = Some(Cursor::new(serialize_entry_framing(entry)?));
                if entry.kind == EntryKind::File {
                    let path = self.tree.base_dir.join(&entry.relative_path);
                    self.file = Some((File::open(path)?, entry.size));
                }
            } else {
                break;
            }
        }

        if self.filled == 0 {
            Ok(None)
        } else {
            Ok(Some(&self.buf[..self.filled]))
        }
    }
}
