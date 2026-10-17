//! Linux executable trailer: [32 raw key bytes][fixed 32-byte random magic].
//!
//! Read the running inode, not argv[0]. Updates use a private temporary file
//! and atomic rename: Linux forbids writing to an executing inode (ETXTBSY).

use crate::crypto::SharedSecret;

pub(crate) fn load() -> Result<SharedSecret, String> {
    #[cfg(target_os = "linux")]
    {
        linux::load()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("embedded executable keys currently require Linux".into())
    }
}

/// Reuse the running executable's key, or persist a fresh one. `regenerate`
/// always replaces the key on disk; running peers retain their old key.
pub(crate) fn server(regenerate: bool) -> Result<(SharedSecret, bool), String> {
    #[cfg(target_os = "linux")]
    {
        linux::server(regenerate).map_err(|e| format!("cannot initialize embedded key: {e}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = regenerate;
        Err("embedded executable keys currently require Linux".into())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    const KEY_LEN: usize = 32;
    // Generated once; fixed across builds and shared by all keyed executables.
    const MAGIC: &[u8] = b"\x29\xd9\x31\xf3\x21\xc2\xdf\xe2\xd1\x45\x98\x63\xbc\x8f\xd3\x5b\xd0\x92\x63\x86\xc0\x7d\x02\xa8\x55\x98\xb5\x0a\xba\xb0\x58\xd8";
    const TRAILER_LEN: u64 = (KEY_LEN + MAGIC.len()) as u64;

    fn trailer(file: &mut File) -> io::Result<Option<SharedSecret>> {
        let len = file.metadata()?.len();
        if len < MAGIC.len() as u64 {
            return Ok(None);
        }
        file.seek(SeekFrom::End(-(MAGIC.len() as i64)))?;
        let mut magic = vec![0; MAGIC.len()];
        file.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Ok(None);
        }
        if len < TRAILER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated embedded key trailer",
            ));
        }
        file.seek(SeekFrom::End(-(TRAILER_LEN as i64)))?;
        let mut key = vec![0; KEY_LEN];
        file.read_exact(&mut key)?;
        Ok(Some(SharedSecret::new(key).expect("32-byte key")))
    }

    pub(super) fn load() -> Result<SharedSecret, String> {
        let mut file = File::open("/proc/self/exe")
            .map_err(|e| format!("cannot read running executable: {e}"))?;
        trailer(&mut file)
            .map_err(|e| format!("cannot read embedded key: {e}"))?
            .ok_or_else(|| "no embedded key; securely copy the keyed executable from the server (initialize it with server --genkey)".into())
    }

    pub(super) fn server(regenerate: bool) -> io::Result<(SharedSecret, bool)> {
        let mut source = File::open("/proc/self/exe")?;
        let existing = trailer(&mut source)?;
        if !regenerate && let Some(key) = &existing {
            return Ok((key.clone(), false));
        }
        let path = std::env::current_exe()?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("executable has no parent directory"))?;
        // A directory lock survives replacement of the executable inode. Never
        // overwrite a different executable installed while this one was running.
        let directory = File::open(parent)?;
        directory.lock()?;
        let running = source.metadata()?;
        let on_disk = std::fs::metadata(&path)?;
        if (running.dev(), running.ino()) != (on_disk.dev(), on_disk.ino()) {
            return Err(io::Error::other(
                "executable was replaced while running; restart and try again",
            ));
        }
        let base_len = running.len() - if existing.is_some() { TRAILER_LEN } else { 0 };
        let key = replace(&mut source, &path, base_len)?;
        directory.sync_all()?;
        Ok((key, true))
    }

    struct Temporary(PathBuf);

    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn replace(source: &mut File, path: &Path, base_len: u64) -> io::Result<SharedSecret> {
        let mut key = vec![0; KEY_LEN];
        getrandom::fill(&mut key).map_err(io::Error::other)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let nonce = u128::from_ne_bytes(nonce);
        let temp_path = path.with_file_name(format!(".cloudyday-{nonce:032x}.tmp"));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&temp_path)?;
        let temp = Temporary(temp_path);
        source.rewind()?;
        if io::copy(&mut source.take(base_len), &mut output)? != base_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "executable was truncated",
            ));
        }
        output.write_all(&key)?;
        output.write_all(MAGIC)?;
        // Do not preserve setuid/setgid, capabilities, or public readability.
        output.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        output.sync_all()?;
        std::fs::rename(&temp.0, path)?;
        Ok(SharedSecret::new(key).expect("32-byte key"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn create_reuse_and_rotate_trailer() {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "cloudyday-trailer-{:032x}",
                u128::from_ne_bytes(nonce)
            ));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join("program");
            let base = b"fake executable bytes";
            std::fs::write(&path, base).unwrap();
            let mut source = File::open(&path).unwrap();
            assert!(trailer(&mut source).unwrap().is_none());
            replace(&mut source, &path, base.len() as u64).unwrap();
            let first = std::fs::read(&path).unwrap();
            assert_eq!(first.len(), base.len() + TRAILER_LEN as usize);
            assert_eq!(&first[..base.len()], base);
            assert_eq!(&first[first.len() - MAGIC.len()..], MAGIC);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            let mut source = File::open(&path).unwrap();
            assert!(trailer(&mut source).unwrap().is_some());
            assert_eq!(std::fs::read(&path).unwrap(), first);
            replace(&mut source, &path, base.len() as u64).unwrap();
            let second = std::fs::read(&path).unwrap();
            assert_eq!(
                first.len(),
                second.len(),
                "rotation must replace, not append"
            );
            assert_eq!(&second[..base.len()], base);
            assert_ne!(
                &first[base.len()..base.len() + KEY_LEN],
                &second[base.len()..base.len() + KEY_LEN]
            );
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
            std::fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn reject_truncated_trailer() {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "cloudyday-truncated-{:032x}",
                u128::from_ne_bytes(nonce)
            ));
            std::fs::write(&path, MAGIC).unwrap();
            assert_eq!(
                trailer(&mut File::open(&path).unwrap()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            std::fs::remove_file(path).unwrap();
        }
    }
}
