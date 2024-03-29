use procfs::process::MMapPath;
use std::path::PathBuf;

pub trait MMapPathExt {
    fn unwrap(&self) -> &PathBuf;
    fn path(&self) -> Option<&PathBuf>;
}

impl MMapPathExt for MMapPath {
    fn unwrap(&self) -> &PathBuf {
        self.path().unwrap()
    }

    fn path(&self) -> Option<&PathBuf> {
        if let MMapPath::Path(p) = self {
            Some(p)
        } else {
            None
        }
    }
}
