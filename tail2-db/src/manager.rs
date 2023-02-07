//! DB Manager
//! A database manager that can be used to create and manage multiple tail2 databases.
//! Each tail2 database file(duckdb file) is accompanied with a metadata file that contains tags.

use std::{path::{PathBuf, Path}, fs, sync::Arc};
use anyhow::{Result, Context};

use fnv::FnvHashMap;
use tokio::sync::Mutex;
use tracing::error;

use crate::{db::Tail2DB, metadata::Metadata};

/// A database manager that can be used to create and manage multiple tail2 databases.
pub struct Manager {
    folder: PathBuf,
    dbs: FnvHashMap<String, Arc<Mutex<Db>>>,
}

/// A database instance consisting of a db file and a metadata file.
pub struct Db {
    metadata: Metadata,
    /// The Tail2DB t2db file
    pub tail2_db: Tail2DB,
}

impl Db {
    /// Open a database from a tail2 db path
    pub fn open(path_to_t2db: &PathBuf) -> Result<Self> {
        if path_to_t2db.extension().context("no ext")? == "t2db" {
            let tail2_db = Tail2DB::open(path_to_t2db);
            let metadata = tail2_db.metadata().context("missing metadata")?;
            Ok(Self {
                metadata,
                tail2_db,
            })
        } else {
            Err(anyhow::anyhow!("invalid database file"))
        }
    }

    /// Create a new database given a path to t2db
    pub fn create(path_to_t2db: &PathBuf, metadata: Metadata) -> Result<Self> {
        let tail2_db = Tail2DB::open(path_to_t2db);
        metadata.save(path_to_t2db.parent().context("no parent")?)?;
        Ok(Self {
            metadata,
            tail2_db,
        })
    }
}

impl Manager {
    /// Create a new database manager given a path to a folder
    pub fn new<P: AsRef<Path>>(folder: P) -> Self {
        let folder = PathBuf::from(&folder.as_ref());
        // populate dbs
        let mut dbs = FnvHashMap::default();
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            match Db::open(&path) {
                Ok(db) => {
                    dbs.insert(db.metadata.name.clone(), Arc::new(Mutex::new(db)));
                }
                Err(e) => {
                    error!("error opening db: {:?}", e);
                }
            }
        }

        Self {
            folder,
            dbs,
        }
    }

    /// Create a new database given metadata
    pub fn create_db(&mut self, metadata: Metadata) -> Result<Arc<Mutex<Db>>> {
        metadata.save(&self.folder)?;
        let db_path = self.folder.join(&metadata.name).with_extension("t2db");
        let db = Db::create(&db_path, metadata)?;
        let name = db.metadata.name.clone();
        let ret = Arc::new(Mutex::new(db));
        self.dbs.insert(name, Arc::clone(&ret));
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use fnv::FnvHashMap;

    use super::*;

    #[test]
    fn test_manager() {
        let tempdir = tempfile::tempdir().unwrap();
        let folder = tempdir.path().to_path_buf();
        // let folder = PathBuf::from("/home/g/tail2/test");
        let mut manager = Manager::new(&folder);
        assert_eq!(manager.dbs.len(), 0);
        
        let metadata = Metadata {
            name: "test".to_string(),
            tags: FnvHashMap::new(),
        };
        manager.create_db(metadata).unwrap();
        assert_eq!(manager.dbs.len(), 1);
        drop(manager);

        // check how many files are in the temp dir
        let files = fs::read_dir(&folder)
            .unwrap()
            .map(|f| f.unwrap().path())
            .collect::<Vec<_>>();

        dbg!(&files);
        assert_eq!(files.len(), 2);
        assert!(files.contains(&folder.join("test.t2db")));
        assert!(files.contains(&folder.join("test.toml")));
    }
}