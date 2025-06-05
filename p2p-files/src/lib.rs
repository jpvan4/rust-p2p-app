use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use p2p_core::{FileInfo, FileChunk, TransferId, P2PResult, P2PError};
use sha2::{Sha256, Digest};

/// File manager to read files in chunks
pub struct FileManager {
    base_dir: PathBuf,
}

impl FileManager {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Compute FileInfo for a path
    pub fn file_info(&self, path: &Path) -> P2PResult<FileInfo> {
        let full = self.base_dir.join(path);
        let metadata = std::fs::metadata(&full)?;
        let mut file = File::open(&full)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        Ok(FileInfo {
            name: path.to_string_lossy().into_owned(),
            size: metadata.len(),
            hash: hasher.finalize().to_vec(),
            mime_type: None,
            created: metadata.created().ok(),
            modified: metadata.modified().ok(),
        })
    }

    /// Read chunks from a file
    pub fn read_chunks(&self, path: &Path, chunk_size: u32) -> P2PResult<Vec<FileChunk>> {
        let info = self.file_info(path)?;
        let total_chunks = (info.size + chunk_size as u64 - 1) / chunk_size as u64;
        let mut file = File::open(self.base_dir.join(path))?;
        let mut chunks = Vec::new();
        for index in 0..total_chunks {
            let mut data = vec![0u8; chunk_size as usize];
            let read = file.read(&mut data)?;
            data.truncate(read);
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let checksum = hasher.finalize().to_vec();
            chunks.push(FileChunk {
                transfer_id: TransferId::new(),
                chunk_index: index as u32,
                data,
                checksum,
            });
        }
        Ok(chunks)
    }
}

