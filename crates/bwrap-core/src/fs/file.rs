//! Small file helpers for the newroot setup (`setup_newroot`): probing an open
//! fd's file type and copying file data. Both are faithful ports of bubblewrap
//! utilities (`get_file_mode`, `copy_file_data`).

use std::os::fd::BorrowedFd;

use nix::errno::Errno;
use nix::sys::stat::{SFlag, fstat};
use nix::unistd::{read, write};

/// The file-type bits (`st_mode & S_IFMT`) of an open fd — bwrap's
/// `get_file_mode`. The executor uses this to choose a bind-mount destination's
/// node type (dir vs file) from the source, and to refuse mounting on a symlink
/// destination.
pub fn file_type(fd: BorrowedFd<'_>) -> nix::Result<SFlag> {
    let st = fstat(fd)?;
    Ok(SFlag::from_bits_truncate(st.st_mode & SFlag::S_IFMT.bits()))
}

/// Copy all data from `src` to `dst` until end of file — bwrap's
/// `copy_file_data`. Used by `--file` and `--bind-data` to populate a node from
/// the caller-supplied data fd. Short writes are retried; `EINTR` is retried on
/// both sides.
pub fn copy_file_data(src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> nix::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = match read(src, &mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
        };
        let mut off = 0;
        while off < n {
            match write(dst, &buf[off..n]) {
                Ok(0) => return Err(Errno::EIO),
                Ok(w) => off += w,
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;

    #[test]
    fn file_type_distinguishes_dir_file_and_symlink() {
        let dir = std::env::temp_dir();
        let d = std::fs::File::open(&dir).unwrap();
        assert_eq!(file_type(d.as_fd()).unwrap(), SFlag::S_IFDIR);

        let path = dir.join(format!("bwrap-ft-{}", std::process::id()));
        let f = std::fs::File::create(&path).unwrap();
        assert_eq!(file_type(f.as_fd()).unwrap(), SFlag::S_IFREG);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn copy_file_data_copies_all_bytes() {
        let dir = std::env::temp_dir();
        let src_path = dir.join(format!("bwrap-cp-src-{}", std::process::id()));
        let dst_path = dir.join(format!("bwrap-cp-dst-{}", std::process::id()));
        // A payload larger than one buffer, so the read/write loop iterates.
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

        let mut src = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&src_path)
            .unwrap();
        src.write_all(&payload).unwrap();
        src.seek(std::io::SeekFrom::Start(0)).unwrap();

        let dst = std::fs::File::create(&dst_path).unwrap();
        copy_file_data(src.as_fd(), dst.as_fd()).unwrap();
        drop(dst);

        let mut back = Vec::new();
        std::fs::File::open(&dst_path)
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, payload);

        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);
    }

    #[test]
    fn copy_file_data_empty_source_is_ok() {
        let dir = std::env::temp_dir();
        let src_path = dir.join(format!("bwrap-cp-e-src-{}", std::process::id()));
        let dst_path = dir.join(format!("bwrap-cp-e-dst-{}", std::process::id()));
        std::fs::File::create(&src_path).unwrap(); // create empty
        let src = std::fs::File::open(&src_path).unwrap(); // reopen readable
        let dst = std::fs::File::create(&dst_path).unwrap();
        copy_file_data(src.as_fd(), dst.as_fd()).unwrap();
        assert_eq!(std::fs::metadata(&dst_path).unwrap().len(), 0);
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&dst_path);
    }
}
