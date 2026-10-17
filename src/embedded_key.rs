//! Linux executable trailer: [32 raw key bytes][fixed 32-byte random magic].

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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::File;
    use std::io::{self, Read, Seek, SeekFrom};

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
            .ok_or_else(|| "no embedded key; add a key with rekey.py".into())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;

        fn temp_path(label: &str) -> std::path::PathBuf {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            std::env::temp_dir().join(format!(
                "cloudyday-{label}-{:032x}",
                u128::from_ne_bytes(nonce)
            ))
        }

        #[test]
        fn reads_trailer() {
            let path = temp_path("trailer");
            let key = [42; KEY_LEN];
            let mut file = File::create(&path).unwrap();
            file.write_all(b"fake executable bytes").unwrap();
            file.write_all(&key).unwrap();
            file.write_all(MAGIC).unwrap();
            drop(file);

            assert!(trailer(&mut File::open(&path).unwrap()).unwrap().is_some());
            std::fs::remove_file(path).unwrap();
        }

        #[test]
        fn reject_truncated_trailer() {
            let path = temp_path("truncated");
            std::fs::write(&path, MAGIC).unwrap();
            assert_eq!(
                trailer(&mut File::open(&path).unwrap()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            std::fs::remove_file(path).unwrap();
        }
    }
}
