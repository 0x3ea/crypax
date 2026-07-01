use std::{
    fs::{self, File},
    io::Write,
    path::{self, PathBuf},
};

use crate::{
    error::{Result, invalid_input},
    fs::pack::{PACK_FORMAT_VERSION, PACK_MAGIC},
};

#[derive(Clone, Copy)]
enum State {
    Preamble,                //26B
    Kind,                    //1B
    Permissions,             //1B
    PathLen,                 //8B
    Path { path_len: u64 },  //PathLen
    Size,                    //8B
    DataLen,                 //8B
    Data { remaining: u64 }, //DataLen
    Done,
}
pub struct RestoreStream {
    out_dir: PathBuf,
    pending: Vec<u8>,
    state: State,
    entry_count: u32,
    entry_handled: u32,

    cur_kind: u8,
    cur_permissions: u8,
    cur_path: PathBuf,
    cur_size: u64,
    cur_data_len: u64,
    writer: Option<File>,
}

const MAX_PATH_LEN: u64 = 4096;
impl RestoreStream {
    pub fn new(out_dir: PathBuf, entry_count: u32) -> Self {
        Self {
            out_dir,
            pending: Vec::new(),
            state: State::Preamble,
            entry_count,
            entry_handled: 0,

            cur_kind: 0,
            cur_permissions: 0,
            cur_path: PathBuf::new(),
            cur_size: 0,
            cur_data_len: 0,
            writer: None,
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<()> {
        let mut i = 0;
        loop {
            match self.state {
                State::Preamble => {
                    if !self.fill_fixed(26, chunk, &mut i) {
                        return Ok(());
                    }
                    self.validate_preamble()?;
                    self.pending.clear();
                    self.state = State::Kind;
                }
                State::Kind => {
                    let Some(b) = self.take_byte(chunk, &mut i) else {
                        return Ok(());
                    };

                    if b != 1 && b != 2 {
                        return Err(invalid_input("invalid kind"));
                    }
                    self.cur_kind = b;
                    self.state = State::Permissions;
                }
                State::Permissions => {
                    let Some(b) = self.take_byte(chunk, &mut i) else {
                        return Ok(());
                    };
                    self.cur_permissions = b;
                    self.state = State::PathLen;
                }
                State::PathLen => {
                    if !self.fill_fixed(8, chunk, &mut i) {
                        return Ok(());
                    }
                    let path_len = self.read_unsafe_path()?;
                    self.pending.clear();
                    self.state = State::Path { path_len };
                }
                State::Path { path_len } => {
                    if !self.fill_fixed(path_len as usize, chunk, &mut i) {
                        return Ok(());
                    }

                    let bytes = std::mem::take(&mut self.pending);
                    self.cur_path = PathBuf::from(String::from_utf8(bytes)?);
                    if self.cur_path.components().any(|c| {
                        !matches!(c, path::Component::Normal(_)) || self.cur_path.is_absolute()
                    }) {
                        return Err(invalid_input("unsafe path in archive"));
                    }
                    self.state = State::Size;
                }
                State::Size => {
                    if !self.fill_fixed(8, chunk, &mut i) {
                        return Ok(());
                    }
                    self.cur_size = u64::from_le_bytes(self.pending[..8].try_into().unwrap());
                    self.pending.clear();
                    self.state = State::DataLen;
                }
                State::DataLen => {
                    if !self.fill_fixed(8, chunk, &mut i) {
                        return Ok(());
                    }
                    self.cur_data_len = u64::from_le_bytes(self.pending[..8].try_into().unwrap());
                    self.pending.clear();

                    self.open_target()?;
                }
                State::Data { mut remaining } => {
                    let take = (remaining as usize).min(chunk.len() - i);
                    if take > 0 {
                        if let Some(w) = self.writer.as_mut() {
                            w.write_all(&chunk[i..i + take])?;
                        }
                        i += take;
                        remaining -= take as u64;
                    }
                    if remaining == 0 {
                        self.writer = None;
                        self.entry_handled += 1;
                        self.state = self.next_entry_state();
                    } else {
                        self.state = State::Data { remaining };
                        return Ok(());
                    }
                }
                State::Done => {
                    break;
                }
            };
        }
        Ok(())
    }

    fn open_target(&mut self) -> Result<()> {
        let target = self.out_dir.join(&self.cur_path);
        match self.cur_kind {
            1 => {
                self.writer = Some(File::create(target)?);
                if self.cur_data_len == 0 {
                    self.writer = None;
                    self.entry_handled += 1;
                    self.state = self.next_entry_state();
                } else {
                    self.state = State::Data {
                        remaining: self.cur_data_len,
                    }
                }
            }
            2 => {
                if self.cur_data_len != 0 {
                    return Err(invalid_input("directory entry has data"));
                }
                fs::create_dir_all(&target)?;
                self.entry_handled += 1;
                self.state = self.next_entry_state();
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn next_entry_state(&self) -> State {
        if self.entry_handled < self.entry_count {
            State::Kind
        } else {
            State::Done
        }
    }

    fn fill_fixed(&mut self, n: usize, chunk: &[u8], i: &mut usize) -> bool {
        let take = n.saturating_sub(self.pending.len()).min(chunk.len() - *i);
        self.pending.extend_from_slice(&chunk[*i..*i + take]);
        *i += take;
        self.pending.len() == n
    }

    fn take_byte(&self, chunk: &[u8], i: &mut usize) -> Option<u8> {
        let b = chunk.get(*i)?;
        *i += 1;
        Some(*b)
    }

    fn validate_preamble(&self) -> Result<()> {
        let magic = &self.pending[..11];
        if magic != PACK_MAGIC {
            return Err(invalid_input("invalid magic"));
        }

        let version = u16::from_le_bytes(self.pending[11..13].try_into().unwrap());
        if version != PACK_FORMAT_VERSION {
            return Err(invalid_input("invalid version"));
        }
        Ok(())
    }

    fn read_unsafe_path(&self) -> Result<u64> {
        let path_len = u64::from_le_bytes(self.pending[..8].try_into().unwrap());
        if path_len > MAX_PATH_LEN {
            return Err(invalid_input("path too long"));
        }
        Ok(path_len)
    }
}
