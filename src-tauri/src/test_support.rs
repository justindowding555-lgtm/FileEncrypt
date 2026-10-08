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
