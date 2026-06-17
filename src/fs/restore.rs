use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use crate::error::{Result, invalid_input};

pub fn restore_packed_source(bytes: &[u8], output_dir: &Path) -> Result<()> {
    if !output_dir.exists() {
        return Err(invalid_input("output path not exist"));
    }

    let (_, count, mut pos) = parse_header(bytes)?;

    for _ in 0..count {
        let type_tag = read_u8(bytes, &mut pos)?;
        let relative_path = read_string(bytes, &mut pos)?;
        let _size = read_u64_le(bytes, &mut pos)?;
        let content = read_bytes(bytes, &mut pos)?;

        let target = validate_restore_path(output_dir, &relative_path)?;

        match type_tag {
            1 => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&target, &content)?;
            }
            2 => {
                fs::create_dir_all(&target)?;
            }
            _ => return Err(invalid_input("unknown entry type in packed data")),
        }
    }
    Ok(())
}

fn parse_header(bytes: &[u8]) -> Result<(u16, u32, usize)> {
    let mut pos = 0;

    let magic = b"CRYPAXPACK\0";
    if bytes.len() < magic.len() || &bytes[..magic.len()] != magic {
        return Err(invalid_input("not a valid packed source"));
    }
    pos += magic.len();

    let version = read_u16_le(bytes, &mut pos)?;
    if version != 1 {
        return Err(invalid_input("unsupported pack version"));
    }

    let count = read_u32_le(bytes, &mut pos)?;

    Ok((version, count, pos))
}

fn validate_restore_path(output_dir: &Path, relative_str: &str) -> Result<PathBuf> {
    let relative = Path::new(relative_str);

    if relative.is_absolute() {
        return Err(invalid_input("path traversal: absolute path"));
    }

    for component in relative.components() {
        match component {
            Component::Normal(_) => {}
            _ => return Err(invalid_input("path traversal: illegal component")),
        }
    }

    Ok(output_dir.join(relative))
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8> {
    if *pos >= bytes.len() {
        return Err(invalid_input("unexpected end of packed data"));
    }
    let value = bytes[*pos];
    *pos += 1;
    Ok(value)
}

fn read_u16_le(bytes: &[u8], pos: &mut usize) -> Result<u16> {
    let end = *pos + 2;
    if end > bytes.len() {
        return Err(invalid_input("unexpected end of packed data"));
    }
    let value = u16::from_le_bytes(bytes[*pos..end].try_into().unwrap());

    *pos = end;

    Ok(value)
}

fn read_u32_le(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    let end = *pos + 4;
    if end > bytes.len() {
        return Err(invalid_input("unexpected end of packed data"));
    }
    let value = u32::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(value)
}

fn read_u64_le(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let end = *pos + 8;
    if end > bytes.len() {
        return Err(invalid_input("unexpected end of packed data"));
    }
    let value = u64::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(value)
}

fn read_bytes(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let len = read_u64_le(bytes, pos)? as usize;
    let end = *pos + len;
    if end > bytes.len() {
        return Err(invalid_input("unexpected end of packed data"));
    }
    let value = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(value)
}

fn read_string(bytes: &[u8], pos: &mut usize) -> Result<String> {
    let raw = read_bytes(bytes, pos)?;
    String::from_utf8(raw).map_err(|_| invalid_input("relative path is not valid UTF-8"))
}
