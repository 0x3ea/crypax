use crate::error::Result;
use std::io::{Read, Seek, SeekFrom, Write};

pub const ARCHIVE_MAGIC: &[u8] = b"CRYPAX\x02";
pub const EOF_MAGIC: &[u8] = b"CXEOF\x02\x00\x00";
pub const ARCHIVE_FORMAT_VERSION: u8 = 2;

pub struct ArchiveHeaderV2 {
    pub magic: [u8; 7],
    pub version: u8,
    pub archive_uuid: [u8; 16],
    pub salt: [u8; 16],
    pub segment_plaintext_size: u32,
    pub total_segments: u32,
    pub total_plaintext_size: u64,
    pub rs_data_cells_per_stripe: u16,
    pub rs_parity_cells_per_segment: u16,
    pub cell_size: u32,
    pub segment_table_offset: u64,
    pub rs_parity_region_offset: u64,
    pub footer_offset: u64,
    pub encrypted_manifest_size: u32,
    pub reserved: [u8; 420],
}

pub struct SegmentEntry {
    pub offset: u64,
    pub ciphertext_len: u32,
    pub plaintext_len: u32,
    pub blake3_prefix: [u8; 8],
    pub reserved: [u8; 8],
}

pub fn write_header_v2(header: &ArchiveHeaderV2, writer: &mut impl Write) -> Result<()> {
    let mut buf = [0u8; 512];
    buf[0..7].copy_from_slice(&header.magic);
    buf[7] = header.version;
    buf[8..24].copy_from_slice(&header.archive_uuid);
    buf[24..40].copy_from_slice(&header.salt);
    buf[40..44].copy_from_slice(&header.segment_plaintext_size.to_le_bytes());
    buf[44..48].copy_from_slice(&header.total_segments.to_le_bytes());
    buf[48..56].copy_from_slice(&header.total_plaintext_size.to_le_bytes());
    buf[56..58].copy_from_slice(&header.rs_data_cells_per_stripe.to_le_bytes());
    buf[58..60].copy_from_slice(&header.rs_parity_cells_per_segment.to_le_bytes());
    buf[60..64].copy_from_slice(&header.cell_size.to_le_bytes());
    buf[64..72].copy_from_slice(&header.segment_table_offset.to_le_bytes());
    buf[72..80].copy_from_slice(&header.rs_parity_region_offset.to_le_bytes());
    buf[80..88].copy_from_slice(&header.footer_offset.to_le_bytes());
    buf[88..92].copy_from_slice(&header.encrypted_manifest_size.to_le_bytes());
    buf[92..].copy_from_slice(&header.reserved);

    writer.write_all(&buf)?;
    Ok(())
}

pub fn read_header_v2(reader: &mut impl Read) -> Result<ArchiveHeaderV2> {
    let mut buf = [0u8; 512];
    reader.read_exact(&mut buf)?;

    parse_header_from_buf(&buf)
}

pub fn read_header_from_footer(file: &mut (impl Read + Seek)) -> Result<ArchiveHeaderV2> {
    let (footer_offset, footer_blake) = read_eof_marker(file)?;
    let mut buf = [0u8; 512];
    file.seek(SeekFrom::Start(footer_offset))?;
    file.read_exact(&mut buf)?;

    let header = parse_header_from_buf(&buf)?;

    let remaining_size: usize =
        (header.total_segments * 32 + header.encrypted_manifest_size) as usize;
    let mut rest = vec![0u8; remaining_size];
    file.read_exact(&mut rest)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf);
    hasher.update(&rest);
    let hash = hasher.finalize();
    if hash.as_bytes()[..8] != footer_blake {
        return Err(anyhow::anyhow!("Footer hash mismatch"));
    }

    Ok(header)
}

pub fn write_segment_table(entries: &[SegmentEntry], writer: &mut impl Write) -> Result<()> {
    for entry in entries {
        let mut buf = [0u8; 32];
        buf[..8].copy_from_slice(&entry.offset.to_le_bytes());
        buf[8..12].copy_from_slice(&entry.ciphertext_len.to_le_bytes());
        buf[12..16].copy_from_slice(&entry.plaintext_len.to_le_bytes());
        buf[16..24].copy_from_slice(&entry.blake3_prefix);
        buf[24..32].copy_from_slice(&entry.reserved);
        writer.write_all(&buf)?;
    }
    Ok(())
}

pub fn read_segment_table(reader: &mut impl Read, count: usize) -> Result<Vec<SegmentEntry>> {
    let mut buf = [0u8; 32];
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        reader.read_exact(&mut buf)?;
        let entry = SegmentEntry {
            offset: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            ciphertext_len: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            plaintext_len: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            blake3_prefix: buf[16..24].try_into().unwrap(),
            reserved: buf[24..32].try_into().unwrap(),
        };
        entries.push(entry);
    }
    Ok(entries)
}

pub fn write_eof_marker(
    writer: &mut impl Write,
    footer_offset: u64,
    footer_blake3_prefix: [u8; 8],
) -> Result<()> {
    writer.write_all(&EOF_MAGIC)?;
    writer.write_all(&footer_offset.to_le_bytes())?;
    writer.write_all(&footer_blake3_prefix)?;
    Ok(())
}

pub fn read_eof_marker(reader: &mut (impl Read + Seek)) -> Result<(u64, [u8; 8])> {
    let file_size = reader.seek(SeekFrom::End(0))?;

    if file_size < 24 {
        return Err(anyhow::anyhow!("Invalid archive size"));
    }

    reader.seek(SeekFrom::Start(file_size - 24))?;

    let mut buf = [0u8; 24];
    reader.read_exact(&mut buf)?;

    if buf[0..8] != *EOF_MAGIC {
        return Err(anyhow::anyhow!("Invalid archive magic"));
    }

    let footer_offset = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let footer_blake: [u8; 8] = buf[16..24].try_into().unwrap();
    Ok((footer_offset, footer_blake))
}

fn parse_header_from_buf(buf: &[u8; 512]) -> Result<ArchiveHeaderV2> {
    let header = ArchiveHeaderV2 {
        magic: buf[0..7].try_into().unwrap(),
        version: buf[7],
        archive_uuid: buf[8..24].try_into().unwrap(),
        salt: buf[24..40].try_into().unwrap(),
        segment_plaintext_size: u32::from_le_bytes(buf[40..44].try_into().unwrap()),
        total_segments: u32::from_le_bytes(buf[44..48].try_into().unwrap()),
        total_plaintext_size: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
        rs_data_cells_per_stripe: u16::from_le_bytes(buf[56..58].try_into().unwrap()),
        rs_parity_cells_per_segment: u16::from_le_bytes(buf[58..60].try_into().unwrap()),
        cell_size: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
        segment_table_offset: u64::from_le_bytes(buf[64..72].try_into().unwrap()),
        rs_parity_region_offset: u64::from_le_bytes(buf[72..80].try_into().unwrap()),
        footer_offset: u64::from_le_bytes(buf[80..88].try_into().unwrap()),
        encrypted_manifest_size: u32::from_le_bytes(buf[88..92].try_into().unwrap()),
        reserved: buf[92..512].try_into().unwrap(),
    };

    if header.magic != *ARCHIVE_MAGIC {
        return Err(anyhow::anyhow!("Invalid archive magic"));
    }

    if header.version != ARCHIVE_FORMAT_VERSION {
        return Err(anyhow::anyhow!("Unsupported archive version"));
    }

    Ok(header)
}
