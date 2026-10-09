//! Hash protected file bytes as they already pass through the transformation.
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Fingerprint {
    pub len: u64,
    pub digest: [u8; 32],
}

#[derive(Default)]
pub struct ReadHash {
    hash: Sha256,
    len: u64,
}

impl ReadHash {
    #[cfg(any(windows, test))]
    pub fn fingerprint(&self, size: u64) -> Option<Fingerprint> {
        (self.len == size).then(|| Fingerprint {
            len: self.len,
            digest: self.hash.clone().finalize().into(),
        })
    }
}

pub struct HashingReader<R> {
    inner: R,
    position: u64,
    hash: Option<Arc<Mutex<ReadHash>>>,
}

impl<R: Read + Seek> HashingReader<R> {
    pub fn new(mut inner: R, hash: Option<Arc<Mutex<ReadHash>>>) -> io::Result<Self> {
        inner.rewind()?;
        Ok(Self {
            inner,
            position: 0,
            hash,
        })
    }

    #[cfg(any(windows, test))]
    pub fn finish(
        &mut self,
        size: u64,
        callback: Option<&crate::crypto::ProgressCallback<'_>>,
    ) -> io::Result<()> {
        if let Some(hash) = &self.hash {
            let covered = crate::commands::lock(hash).len;
            self.position = self.inner.seek(SeekFrom::Start(covered))?;
            let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
            while self.position < size {
                if let Some(callback) = callback {
                    callback(0)?;
                }
                let count = buffer
                    .len()
                    .min((size - self.position).min(usize::MAX as u64) as usize);
                if self.read(&mut buffer[..count])? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "source truncated during receipt capture",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(bytes)?;
        if let Some(hash) = &self.hash {
            let mut hash = crate::commands::lock(hash);
            if self.position > hash.len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-contiguous source hash",
                ));
            }
            // Buffered seeks may reread an already hashed prefix. Hash only the
            // new suffix, from this same immutable, protected source handle.
            let skip = (hash.len - self.position).min(n as u64) as usize;
            hash.hash.update(&bytes[skip..n]);
            hash.len += (n - skip) as u64;
        }
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for HashingReader<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = self.inner.seek(position)?;
        if let Some(hash) = &self.hash {
            let covered = crate::commands::lock(hash).len;
            if target > covered {
                self.position = self.inner.seek(SeekFrom::Start(covered))?;
                let mut buffer =
                    Zeroizing::new(vec![0u8; (target - covered).min(64 * 1024) as usize]);
                while self.position < target {
                    let count = buffer
                        .len()
                        .min((target - self.position).min(usize::MAX as u64) as usize);
                    if self.read(&mut buffer[..count])? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "source truncated between ZIP entries",
                        ));
                    }
                }
            }
        }
        self.position = self.inner.seek(SeekFrom::Start(target))?;
        Ok(self.position)
    }
}

pub struct HashingWriter<W> {
    inner: W,
    hash: Option<Sha256>,
    len: u64,
}

impl<W> HashingWriter<W> {
    pub fn new(inner: W, enabled: bool) -> Self {
        Self {
            inner,
            hash: enabled.then(Sha256::new),
            len: 0,
        }
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.hash.as_ref().map(|hash| Fingerprint {
            len: self.len,
            digest: hash.clone().finalize().into(),
        })
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        if let Some(hash) = &mut self.hash {
            hash.update(&bytes[..n]);
        }
        self.len += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Counted {
        bytes: Cursor<Vec<u8>>,
        read_bytes: usize,
    }
    impl Read for Counted {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.bytes.read(out)?;
            self.read_bytes += n;
            Ok(n)
        }
    }
    impl Seek for Counted {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(position)
        }
    }

    #[test]
    fn zip_gaps_and_footer_are_hashed_once_without_rereading_bodies() {
        let bytes: Vec<_> = (0..1000).map(|n| (n % 251) as u8).collect();
        let hash = Arc::new(Mutex::new(ReadHash::default()));
        let mut reader = HashingReader::new(
            Counted {
                bytes: Cursor::new(bytes.clone()),
                read_bytes: 0,
            },
            Some(hash.clone()),
        )
        .unwrap();
        reader.seek(SeekFrom::Start(20)).unwrap();
        reader.read_exact(&mut [0u8; 400]).unwrap();
        reader.seek(SeekFrom::Start(450)).unwrap();
        reader.read_exact(&mut [0u8; 500]).unwrap();
        assert!(crate::commands::lock(&hash).fingerprint(1000).is_none());
        reader.finish(1000, None).unwrap();
        let actual = crate::commands::lock(&hash).fingerprint(1000).unwrap();
        assert_eq!(actual.digest, <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(reader.inner.read_bytes, 1000);
        reader.finish(1000, None).unwrap();
        assert_eq!(reader.inner.read_bytes, 1000);
        // Buffered readers can seek back across prefetched bytes without hashing twice.
        reader.seek(SeekFrom::Start(10)).unwrap();
        reader.read_exact(&mut [0u8; 30]).unwrap();
        assert_eq!(
            crate::commands::lock(&hash)
                .fingerprint(1000)
                .unwrap()
                .digest,
            actual.digest
        );
    }

    #[test]
    fn receipt_tail_reads_remain_cancellable() {
        let hash = Arc::new(Mutex::new(ReadHash::default()));
        let mut reader = HashingReader::new(Cursor::new(vec![0; 100]), Some(hash)).unwrap();
        let cancel = |_| Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        assert_eq!(
            reader.finish(100, Some(&cancel)).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn output_hash_tracks_only_successfully_written_bytes() {
        struct Partial(Vec<u8>);
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let n = bytes.len().min(2);
                self.0.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = HashingWriter::new(Partial(Vec::new()), true);
        writer.write_all(b"partial writes").unwrap();
        let actual = writer.fingerprint().unwrap();
        assert_eq!(actual.len, 14);
        assert_eq!(
            actual.digest,
            <[u8; 32]>::from(Sha256::digest(b"partial writes"))
        );
        assert_eq!(writer.inner.0, b"partial writes");
    }
}
