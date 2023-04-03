//! DB Manager
//! A database manager that can be used to create and manage multiple tail2 databases.
//! Each tail2 database file(duckdb file) is accompanied with a metadata file that contains tags.

use std::{path::{PathBuf, Path}, fs, sync::Arc};
use anyhow::{Result, Context};

use fnv::FnvHashMap;
use serde::Serialize;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info};

use crate::{db::Tail2DB, metadata::Metadata};

/// A database manager that can be used to create and manage multiple tail2 databases.
pub struct Manager {
    folder: PathBuf,
    pub dbs: FnvHashMap<String, Db>,
}

/// A database instance consisting of a db file and a metadata file.
#[derive(Clone, Serialize)]
pub struct Db {
    metadata: Metadata,

    #[serde(skip)]
    pub notify: Arc<Notify>,

    /// The Tail2DB t2db file
    #[serde(skip)]
    pub tail2_db: Arc<Mutex<Tail2DB>>,
}

impl Db {
    /// Open a database from a tail2 db path
    pub fn open(path_to_t2db: &PathBuf) -> Result<Self> {
        info!("opening {:?}", path_to_t2db);
        if path_to_t2db.extension().context("no ext")? == "t2db" {
            let tail2_db = Tail2DB::open(path_to_t2db)?;
            let metadata = tail2_db.metadata().context("missing metadata")?;
            Ok(Self {
                metadata,
                notify: Arc::new(Notify::new()),
                tail2_db: Arc::new(Mutex::new(tail2_db)),
            })
        } else {
            Err(anyhow::anyhow!("invalid database file"))
        }
    }

    /// Create a new database given a path to t2db
    pub fn create(path_to_t2db: &PathBuf, metadata: &Metadata) -> Result<Self> {
        let tail2_db = Tail2DB::open(path_to_t2db)?;
        metadata.save(path_to_t2db.parent().context("no parent")?)?;
        Ok(Self {
            metadata: metadata.clone(),
            tail2_db: Arc::new(Mutex::new(tail2_db)),
            notify: Arc::new(Notify::new()),
        })
    }
}

impl Manager {
    /// Create a new database manager given a path to a folder
    pub fn new<P: AsRef<Path>>(folder: P) -> Self {
        let folder = PathBuf::from(&folder.as_ref());
        // recursively make dir so folder exists
        fs::create_dir_all(&folder).unwrap();

        // populate dbs
        let mut dbs = FnvHashMap::default();
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            match Db::open(&path) {
                Ok(db) => {
                    dbs.insert(db.metadata.name.clone(), db);
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
    pub fn create_db(&mut self, metadata: &Metadata) -> Result<Db> {
        metadata.save(&self.folder)?;
        let db_path = self.folder.join(&metadata.name).with_extension("t2db");
        let db = Db::create(&db_path, metadata)?;
        let name = db.metadata.name.clone();
        self.dbs.insert(name, db.clone());
        Ok(db)
    }

    /// Clear dbs in manager
    pub fn clear(&mut self) {
        self.dbs.clear();
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
            tags: FnvHashMap::default(),
        };
        manager.create_db(&metadata).unwrap();
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