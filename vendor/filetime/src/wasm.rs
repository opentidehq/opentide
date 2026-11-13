use crate::FileTime;
use std::fs;
use std::io;
use std::path::Path;

pub fn set_symlink_file_times(_p: &Path, _atime: FileTime, _mtime: FileTime) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Other, "Wasm not implemented"))
}

// opentide's change (vendor/README.md): WASI's metadata has the times, which
// std reads (`Metadata::modified`, `accessed`, `created`), so on
// `target_os = "wasi"` they come from there instead of panicking. Other wasm
// targets keep upstream's `unimplemented!()`.
#[cfg(target_os = "wasi")]
fn from_std(time: io::Result<std::time::SystemTime>) -> Option<FileTime> {
    time.ok().map(FileTime::from_system_time)
}

#[cfg(target_os = "wasi")]
pub fn from_last_modification_time(meta: &fs::Metadata) -> FileTime {
    from_std(meta.modified()).unwrap_or_else(FileTime::zero)
}

#[cfg(target_os = "wasi")]
pub fn from_last_access_time(meta: &fs::Metadata) -> FileTime {
    from_std(meta.accessed()).unwrap_or_else(FileTime::zero)
}

#[cfg(target_os = "wasi")]
pub fn from_creation_time(meta: &fs::Metadata) -> Option<FileTime> {
    from_std(meta.created())
}

#[cfg(not(target_os = "wasi"))]
pub fn from_last_modification_time(_meta: &fs::Metadata) -> FileTime {
    unimplemented!()
}

#[cfg(not(target_os = "wasi"))]
pub fn from_last_access_time(_meta: &fs::Metadata) -> FileTime {
    unimplemented!()
}

#[cfg(not(target_os = "wasi"))]
pub fn from_creation_time(_meta: &fs::Metadata) -> Option<FileTime> {
    unimplemented!()
}

pub fn open(path: &Path) -> io::Result<fs::File> {
    fs::File::open(path)
}
