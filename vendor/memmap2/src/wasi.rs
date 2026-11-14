// opentide's addition to memmap2 0.9.12 (vendor/README.md): WASI preview 1
// has no mmap, so a "map" there is the file's bytes read into the heap.
//
// Read-only and private (copy-on-write) maps are exact: the bytes are the
// file's when the map is made, and private writes never reach the file, as
// with MAP_PRIVATE. An anonymous map is zeroed heap. A shared writable map
// (`map_mut`, `map_raw`) and an executable one are refused (Unsupported):
// their writes would never reach the file, which is the one thing they
// promise. Unlike a real map, the bytes are a snapshot: a later write to the
// file does not show in the map.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

pub struct MmapInner {
    data: Vec<u8>,
}

impl MmapInner {
    /// `len` bytes of `file` from `offset`, read into the heap.
    fn read(len: usize, file: &File, offset: u64) -> io::Result<MmapInner> {
        let mut file = file;
        let position = file.stream_position()?;
        file.seek(SeekFrom::Start(offset))?;
        let mut data = vec![0_u8; len];
        let read = file.read_exact(&mut data);
        // Leave the file's position where it was, as mapping it would.
        file.seek(SeekFrom::Start(position))?;
        read?;
        Ok(MmapInner { data })
    }

    fn unsupported() -> io::Result<MmapInner> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn map(len: usize, file: &File, offset: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        MmapInner::read(len, file, offset)
    }

    pub fn map_exec(_: usize, _: &File, _: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        MmapInner::unsupported()
    }

    pub fn map_mut(_: usize, _: &File, _: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        MmapInner::unsupported()
    }

    pub fn map_copy(len: usize, file: &File, offset: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        MmapInner::read(len, file, offset)
    }

    pub fn map_copy_read_only(
        len: usize,
        file: &File,
        offset: u64,
        _: bool,
        _: bool,
        _: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::read(len, file, offset)
    }

    pub fn map_anon(len: usize, _: bool, _: bool, _: Option<u8>, _: bool) -> io::Result<MmapInner> {
        Ok(MmapInner { data: vec![0_u8; len] })
    }

    /// Nothing reaches the file from a read-only, private or anonymous map.
    pub fn flush(&self, _: usize, _: usize) -> io::Result<()> {
        Ok(())
    }

    pub fn flush_async(&self, _: usize, _: usize) -> io::Result<()> {
        Ok(())
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        Ok(())
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn check_safe_to_map(
        _file: &File,
        _offset: u64,
        _len: usize,
    ) -> Result<(), crate::MapIfSafeError> {
        Err(crate::MapIfSafeError::new_not_supported())
    }
}

pub fn file_len(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.len())
}
