//! Disposable directories for filesystem regression tests.
use std::{fs, path::PathBuf};

pub struct TestDir(pub PathBuf);
impl TestDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fe-test-{}",
            crate::crypto::opaque_file_name().to_string_lossy()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(windows)]
pub fn add_stream(path: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let mut stream = path.as_os_str().to_os_string();
    stream.push(":");
    stream.push(name);
    let stream = PathBuf::from(stream);
    fs::write(&stream, bytes).unwrap();
    stream
}

#[cfg(windows)]
pub fn retained_removal(dir: &TestDir) -> crate::deletion::Removal {
    use std::os::windows::fs::OpenOptionsExt;
    let source = dir.0.join("locked.txt");
    fs::write(&source, b"bytes").unwrap();
    let reader = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&source)
        .unwrap();
    let options = crate::crypto::JobOptions {
        overwrite: false,
        remove_original: true,
        key_file: None,
        output_dir: None,
    };
    let result =
        crate::crypto::encrypt_file_with_progress(&[8; 32], &source, &options, &|_| Ok(()))
            .unwrap();
    drop(reader);
    assert!(result.removal.retry.is_some());
    result.removal
}
