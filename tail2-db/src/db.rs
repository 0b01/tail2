#![warn(missing_docs)]
use std::sync::Arc;
use std::time::Duration;

use duckdb::params;
use duckdb::Config;
use duckdb::Connection;
use duckdb::OptionalExt;
use anyhow::Result;
use fnv::FnvHashMap;
use tail2::calltree::UnsymbolizedCallTree;
use tail2::Mergeable;
use tail2::dto::ModuleMapping;
use tail2::symbolication::module::Module;
use std::path::PathBuf;
use tokio::sync::Mutex;

use crate::metadata::Metadata;
use crate::tile;
use crate::tile::Tile;

use self::module_table::DbBackedModuleMap;


/// A row in the database
pub struct DbRow {
    /// timestamp
    pub ts_ms: i64,
    /// call tree
    pub ct: UnsymbolizedCallTree,
    /// count
    pub n: i32,
}

impl Eq for DbRow {}

impl PartialEq for DbRow {
    fn eq(&self, other: &Self) -> bool {
        self.ts_ms == other.ts_ms
    }
}

impl Ord for DbRow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialOrd for DbRow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.ts_ms.partial_cmp(&other.ts_ms)
    }
}

/// response from db
#[derive(Default)]
pub struct DbResponse {
    /// start
    pub t0: i64,
    /// end
    pub t1: i64,
    /// call tree
    pub calltree: UnsymbolizedCallTree,
    /// count
    pub n: i32,
}

impl std::fmt::Debug for DbResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbResponse")
            .field("t0", &self.t0)
            .field("t1", &self.t1)
            .field("n", &self.n)
            .finish()
    }
}

impl tail2::Mergeable for DbResponse {
    /// Merge two db response
    fn merge(&mut self, other: &Self) -> &Self {
        self.t0 = self.t0.min(other.t0);
        self.t1 = self.t1.max(other.t1);
        self.calltree.merge(&other.calltree);
        self.n += other.n;
        self
    }
}

pub(crate) mod module_table {
    use super::*;

    pub(crate) struct ModuleCache {
        modules: Vec<Option<Arc<Module>>>,
        debug_ids: FnvHashMap<String, i32>,
    }

    impl ModuleCache {
        fn new() -> Self {
            Self { modules: vec![], debug_ids: FnvHashMap::default() }
        }

        fn get_idx_by_debug_id(&self, debug_id: &str) -> Option<i32> {
            self.debug_ids.get(debug_id).copied()
        }

        fn get(&self, idx: usize) -> Option<Arc<Module>> {
            self.modules.get(idx).and_then(|x| x.clone())
        }

        fn insert(&mut self, idx: usize, module: Arc<Module>) {
            if self.modules.len() <= idx {
                self.modules.resize(idx + 1, None);
            }
            self.debug_ids.insert(module.debug_id.clone(), idx as i32);
            self.modules[idx] = Some(module);
        }
    }

    /// Module map backed
    pub struct DbBackedModuleMap {
        /// db connection
        conn: Connection,
        cache: ModuleCache,
    }

    impl DbBackedModuleMap {
        pub(crate) fn new(conn: Connection) -> Self {
            Self {
                conn,
                cache: ModuleCache::new(),
            }
        }
    }

    impl ModuleMapping for DbBackedModuleMap {
        fn get_index_or_insert(&mut self, module: Arc<Module>) -> Option<i32> {
            if let Some(idx) = self.cache.get_idx_by_debug_id(&module.debug_id) {
                return Some(idx);
            }

            if let Ok(ret) = self.conn.query_row("SELECT id FROM modules WHERE debug_id = '?'",
                params![module.debug_id],
                |row| row.get(0))
            {
                return ret;
            }

            let module_ref = module.as_ref();
            self.conn.execute("INSERT INTO modules (id, debug_id, module) VALUES (nextval('seq_module_id'), ?, ?)",
                params![module.debug_id, serde_json::to_string(module_ref).unwrap()]).unwrap();
            let idx = self.conn.query_row("SELECT id FROM modules WHERE debug_id = ?",
                params![module.debug_id],
                |row| row.get(0)).ok();
            if let Some(idx) = idx {
                self.cache.insert(idx as usize, module);
            }

            idx
        }

        fn get(&mut self, idx: usize) -> Arc<Module> {
            // check if the value is cached
            if let Some(m) = self.cache.get(idx) {
                return m;
            }

            let ret: Arc<Module> = Arc::new(self.conn.query_row("SELECT module FROM modules WHERE id = ?", params![idx], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(serde_json::from_slice::<Module>(&bytes).unwrap())
            }).unwrap());

            // update cache
            self.cache.insert(idx, ret.clone());
            ret
        }
    }

}

/// Tail2 database file
pub struct Tail2DB {
    /// path to the db file
    pub path: PathBuf,
    /// db connection
    pub conn: Connection,
    /// last timestamp refreshed, may not be the latest ts in the table
    last_refresh_ts: i64,
    /// latest timestamp
    latest_ts: i64,
    /// order of magnitude augmented tree node for fast call tree merge
    scales: Vec<i64>,
    /// base scale is smallest augmentation scale
    min_tile: i64,
    /// modules table
    modules: Arc<Mutex<DbBackedModuleMap>>,
}

impl Drop for Tail2DB {
    fn drop(&mut self) {
        self.conn.execute("CHECKPOINT;", params![]).unwrap();
    }
}

impl Tail2DB {
    /// Create a file based new database with name
    pub fn open(path: &PathBuf) -> Self {
        let is_existing_db = path.exists();

        let config = Config::default()
            .access_mode(duckdb::AccessMode::ReadWrite)
            .unwrap();
        let conn = Connection::open_with_flags(&path, config).unwrap();

        // 10^3 millis to 10^10
        let scales: Vec<_> = (3..10).rev().map(|i| 10_i64.pow(i)).collect();
        let min_tile = *scales.last().unwrap();

        // modules table
        let modules = Arc::new(Mutex::new(DbBackedModuleMap::new(conn.try_clone().unwrap())));

        // create tables
        if !is_existing_db {
            conn
                .execute_batch(&format!(include_str!("./sql/create_table.sql"), 1))
                .unwrap();

            for i in &scales {
                conn
                    .execute_batch(&format!(include_str!("./sql/create_table.sql"), i))
                    .unwrap();
            }
        }

        // update latest timestamp
        let latest_ts: i64 = conn
            .query_row(
                "SELECT ts FROM samples_1 ORDER BY ts DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .map(|i: i64| i / 1000).unwrap_or_default();

        Self {
            path: path.clone(),
            conn,
            latest_ts,
            last_refresh_ts: 0,
            scales,
            min_tile,
            modules,
        }
    }

    /// Get the modules table
    pub fn modules(&self) -> Arc<Mutex<DbBackedModuleMap>> {
        self.modules.clone()
    }

    /// Insert rows into samples_1. Data must be sorted by timestamp.
    pub fn insert(&mut self, mut data: Vec<DbRow>) -> Result<()> {
        data.sort_unstable();

        let mut stmt = self
            .conn
            .prepare(&format!("INSERT INTO samples_1 VALUES (?, ?, ?)"))?;

        for row in data {
            let ct_bytes = bincode::serialize(&row.ct).unwrap();
            stmt.execute(params![
                Duration::from_millis(row.ts_ms as u64),
                ct_bytes,
                row.n
            ])?;

            // update latest_ts
            self.latest_ts = self.latest_ts.max(row.ts_ms);
        }

        Ok(())
    }

    /// Refresh samples_* augmentation tables
    pub fn refresh_cache(&mut self) -> Result<()> {
        let interval = (self.last_refresh_ts, self.latest_ts);

        let tiles = tile::tile(interval, self.scales.as_slice());
        for Tile{scale, start} in tiles {
            self.get_tile_rec(scale, start)?;
        }

        self.last_refresh_ts = self.latest_ts;

        Ok(())
    }

    // TODO: batch tiles into multiple rows per timescale
    /// Get the [`DbResponse`] object associated with the given range
    pub fn range_query(&self, range @ (t0, t1): (i64, i64)) -> Result<DbResponse> {
        let tiles = tile::tile(range, self.scales.as_slice());
        // dbg!(&tiles);

        let mut trees = vec![];

        if tiles.is_empty() {
            trees.extend(self.query_1(t0, t1)?);
        } else {
            for Tile{scale, start} in tiles {
                trees.push(self.get_tile_rec(scale, start)?);
            }
        }

        // dbg!(&trees);

        let merged = trees.into_iter().reduce(|mut a, b| {
            a.merge(&b);
            a
        }).unwrap_or_default();

        Ok(merged)
    }

    /// query samples_1 the most granular table
    fn query_1(&self, t0: i64, t1: i64) -> Result<Vec<DbResponse>> {
        assert!(t1 - t0 < self.scales[0]);
        let mut ret = vec![];
        let mut stmt = self
            .conn
            .prepare("SELECT ts, ct, n FROM samples_1 WHERE ts >= (?) AND ts < (?)")?;
        let rows = stmt.query_map(
            [
                Duration::from_millis(t0 as u64),
                Duration::from_millis(t1 as u64),
            ],
            |row| {
                Ok(DbRow {
                    ts_ms: row.get::<_, i64>(0)? / 1000,
                    ct: bincode::deserialize(&row.get::<_, Vec<_>>(1)?).unwrap(),
                    n: row.get(2)?,
                })
            },
        )?;
        for row in rows {
            let row = row?;
            ret.push(DbResponse {
                t0,
                t1,
                calltree: row.ct,
                n: row.n,
            });
        }

        Ok(ret)
    }

    /// Get a single tile from the table of that scale
    /// This is the main recursive algorithm that populates the tables as needed by the tiling algorithm.
    fn get_tile_rec(&self, scale: i64, start: i64) -> Result<DbResponse> {
        // dbg!((scale, start));

        // First, try to find a sample that matches our tile
        let ret: Option<(Vec<u8>, i32)> = self
            .conn
            .query_row(
                &format!("SELECT ct, n FROM samples_{scale} WHERE ts = epoch_ms((?))"),
                [start],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        // If we found a matching sample, return it
        if let Some((ct_bytes, n)) = ret {
            let ct = bincode::deserialize(&ct_bytes).unwrap();
            return Ok(DbResponse {
                t0: start,
                t1: start + scale,
                calltree: ct,
                n,
            });
        }

        let mut next_results = vec![];

        // If we didn't find our result, let's build the cache for the tiling algorithm
        // base case: if it's less then the least tile(1000), we have to use raw data (1)
        if scale <= self.min_tile {
            next_results.extend(self.query_1(start, start + scale)?);
        } else {
            // otherwise, let's recurse
            let next_scale = scale / 10;
            for next_start in (start..(start + scale)).step_by(next_scale as usize) {
                next_results.push(self.get_tile_rec(next_scale, next_start)?);
            }
        }

        // Finally, we'll merge the results of each tile
        let mut merged = next_results.into_iter()
            .reduce(|mut a, b| {
                a.merge(&b);
                a
            }).unwrap_or_default();

        merged.t1 = start + scale;

        // Then, we'll insert our new sample into the database

        // if the end time of the interval is less than the latest time, we'll insert the new sample
        // meaning we'll only insert the new sample if we have a full interval
        if self.latest_ts >= start + scale {
            let mut stmt = self
                .conn
                .prepare(&format!("INSERT INTO samples_{scale} VALUES (?, ?, ?)"))?;
            stmt.execute(params![
                Duration::from_millis(start as u64),
                bincode::serialize(&merged.calltree).unwrap(),
                merged.n
            ])
            .unwrap();
        }

        // Finally, we'll return the merged result
        Ok(merged)
    }

    pub(crate) fn metadata(&self) -> Result<Metadata> {
        let toml_path = self.path.with_extension("toml");
        Metadata::open(&toml_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_db() -> Tail2DB {
        let current_dir = std::env::current_dir().unwrap().join("..");
        let file_path = "db/test.t2db";
        let path = current_dir.join(file_path);
        let parent = path.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();

        let mut db = Tail2DB::open(&path);
        let _ = db.insert(
            [100, 150, 950, 1000, 1050, 1900, 2150, 3001]
                .into_iter()
                .map(|ts| DbRow {
                    ts_ms: ts,
                    ct: UnsymbolizedCallTree::new(),
                    n: 1,
                })
                .collect(),
        );
        db
    }

    #[test]
    fn test_db_0() -> Result<()> {
        let db = init_db();

        let ret = db.range_query((0, 10_000)).unwrap();
        assert_eq!(ret.t0, 0);
        assert_eq!(ret.t1, 10_000);
        assert_eq!(ret.n, 8);
        Ok(())
    }

    #[test]
    fn test_db_1() -> Result<()> {
        let db = init_db();
        let ret = db.range_query((0, 1000)).unwrap();
        assert_eq!(ret.t0, 0);
        assert_eq!(ret.t1, 1_000);
        assert_eq!(ret.n, 3);
        Ok(())
    }

    #[test]
    fn test_db_2() -> Result<()> {
        let db = init_db();
        let ret = db.range_query((0, 300)).unwrap();
        assert_eq!(ret.t0, 0);
        assert_eq!(ret.t1, 300);
        assert_eq!(ret.n, 2);
        Ok(())
    }

    #[test]
    fn test_db_3() -> Result<()> {
        let db = init_db();
        let ret = db.range_query((1000, 2000)).unwrap();
        assert_eq!(ret.t0, 1000);
        assert_eq!(ret.t1, 2000);
        assert_eq!(ret.n, 3);

        Ok(())
    }

    #[test]
    fn test_bincode() {
        let bytes = bincode::serialize(&UnsymbolizedCallTree::new()).unwrap();
        dbg!(&bytes.len());
    }
}
