#![warn(missing_docs)]
use std::time::Duration;

use duckdb::params;
use duckdb::Config;
use duckdb::Connection;
use duckdb::OptionalExt;
use duckdb::Result;
use tail2::calltree::inner::CallTreeFrame;
use tail2::calltree::inner::CallTreeInner;
use tail2::calltree::CallTree;

use crate::tile;

pub struct DbRow {
    pub ts: i64,
    pub ct: CallTree,
    pub n: i32,
}

impl Eq for DbRow { }

impl PartialEq for DbRow {
    fn eq(&self, other: &Self) -> bool {
        self.ts == other.ts
    }
}

impl Ord for DbRow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialOrd for DbRow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.ts.partial_cmp(&other.ts)
    }
}

#[derive(Default)]
pub struct DbResponse {
    pub t0: i64,
    pub t1: i64,
    pub ct: CallTree,
    pub n: i32,
}

impl DbResponse {
    pub fn merge(mut self, other: &Self) -> Self {
        self.t0 = self.t0.min(other.t0);
        self.t1 = self.t0.max(other.t1);
        self.ct.merge(&other.ct);
        self.n += other.n;
        self
    }
}

pub struct Tail2DB {
    pub path: String,
    pub conn: Connection,
    last_ts: i64,
    /// order of magnitude augmented tree node for fast call tree merge
    scales: Vec<i64>,
}

impl Tail2DB {
    pub fn new(db_name: &str) -> Self {
        let path = format!("/home/g/tail2/db/{db_name}.t2db");
        let config = Config::default()
            .access_mode(duckdb::AccessMode::ReadWrite)
            .unwrap();
        let conn = Connection::open_with_flags(&path, config).unwrap();

        // 10^3 millis to 10^10
        let scales = (3..10).rev().map(|i| 10_i64.pow(i)).collect();

        let mut db = Self {
            path,
            conn,
            last_ts: 0,
            scales,
        };

        db.create_tables();

        db
    }

    fn create_tables(&mut self) {
        self.conn
            .execute_batch(&format!(include_str!("./sql/create_table.sql"), 1))
            .unwrap();
        for i in self.scales.iter() {
            self.conn
                .execute_batch(&format!(include_str!("./sql/create_table.sql"), i))
                .unwrap();
        }
    }

    /// Insert rows into samples_1. Data must be sorted by timestamp.
    pub fn insert(&mut self, mut data: Vec<DbRow>) -> Result<()> {
        data.sort_unstable();
        let mut app = self.conn.appender("samples_1").unwrap();
        for row in data {
            let ct_bytes = bincode::serialize(&row.ct).unwrap();
            app.append_row(params![
                Duration::from_millis(row.ts as u64),
                ct_bytes,
                row.n
            ])?;
        }

        Ok(())
    }

    /// Refresh the samples_XXXX augmentation tables
    pub(crate) fn refresh_cache(&mut self) -> Result<()> {
        let latest_ts: i64 = self
            .conn
            .query_row(
                "SELECT ts FROM samples_1 ORDER BY ts DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .map(|i: i64| i / 1000)?;

        self.refresh_range((self.last_ts, latest_ts))?;
        self.last_ts = latest_ts;

        Ok(())
    }

    // TODO: batch tiles into multiple rows per timescale
    /// Get the [`DbResponse`] object associated with the given range
    pub fn range_query(&mut self, range: (i64, i64)) -> Result<DbResponse> {
        let mut tiles = tile::tile(range, self.scales.as_slice());

        let mut trees = vec![];

        if tiles.is_empty() {
            trees.extend(self.query_1(range.0, range.1)?);
        } else {
            for (scale, start) in tiles {
                trees.push(self.populate_rec(scale, start)?);
            }
        }

        let merged = trees.iter().fold(DbResponse::default(), DbResponse::merge);

        Ok(merged)
    }

    fn refresh_range(&mut self, range: (i64, i64)) -> Result<()> {
        let tiles = tile::tile(range, self.scales.as_slice());

        for (scale, start) in tiles {
            self.populate_rec(scale, start)?;
        }

        Ok(())
    }

    /// query samples_1 the most granular table
    fn query_1(&mut self, t0: i64, t1: i64) -> Result<Vec<DbResponse>> {
        assert!(t1 - t0 < self.scales[0]);
        let mut ret = vec![];
        let mut stmt = self
            .conn
            .prepare("SELECT ts, ct, n FROM samples_1 WHERE ts >= (?) AND ts < (?)")?;
        let mut rows = stmt.query_map(
            [
                Duration::from_millis(t0 as u64),
                Duration::from_millis(t1 as u64),
            ],
            |row| Ok(DbRow {
                ts: row.get::<_, i64>(0)? / 1000,
                ct: bincode::deserialize(&row.get::<_, Vec<_>>(1)?).unwrap(),
                n: row.get(2)?
            }),
        )?;
        for row in rows {
            let row = row?;
            ret.push(DbResponse { t0, t1, ct: row.ct, n: row.n });
        }

        Ok(ret)
    }

    fn populate_rec(&mut self, scale: i64, start: i64) -> Result<DbResponse> {
        // dbg!((scale, start));
        let ret: Option<(Vec<u8>, i32)> = self
            .conn
            .query_row(
                &format!("SELECT ct, n FROM samples_{scale} WHERE ts = epoch_ms((?))"),
                [start],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((ct_bytes, n)) = ret {
            let ct = bincode::deserialize(&ct_bytes).unwrap();
            return Ok(DbResponse { t0: start, t1: start + scale, ct, n });
        }

        let mut next_results = vec![];
        if scale <= *self.scales.last().unwrap() {
            next_results.extend(self.query_1(start, start + scale)?);
        } else {
            let next_scale = scale / 10;
            for next_start in (start..(start + scale)).step_by(next_scale as usize) {
                next_results.push(self.populate_rec(next_scale, next_start)?);
            }
        }

        let merged = next_results
            .iter()
            .fold(DbResponse::default(), DbResponse::merge);

        let mut stmt = self
            .conn
            .prepare(&format!("INSERT INTO samples_{scale} VALUES (?, ?, ?)"))?;
        stmt.execute(params![
            Duration::from_millis(start as u64),
            bincode::serialize(&merged.ct).unwrap(),
            merged.n
        ])
        .unwrap();

        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_db() -> Tail2DB {
        let mut db = Tail2DB::new("test");
        db.insert(
            [100, 150, 950, 1000, 1050, 1900, 2150, 3001]
                .into_iter()
                .map(|ts| DbRow {
                    ts,
                    ct: CallTree::new(),
                    n: 1,
                })
                .collect(),
        )
        .unwrap();
        db
    }

    #[test]
    fn test_db_0() -> Result<()> {
        let mut db = init_db();

        let ret = db.range_query((0, 10_000)).unwrap();
        assert_eq!(ret.t0, 0);
        assert_eq!(ret.t1, 10_000);
        assert_eq!(ret.n, 8);
        Ok(())
    }

    #[test]
    fn test_db_1() -> Result<()> {
        let mut db = init_db();
        let ret = db.range_query((0, 1000)).unwrap();
        assert_eq!(ret.t0, 0);
        assert_eq!(ret.t1, 1_000);
        assert_eq!(ret.n, 3);
        Ok(())
    }

    #[test]
    fn test_db_2() -> Result<()> {
        let mut db = init_db();
        let ret = db.range_query((0, 300)).unwrap();
        assert_eq!(ret.t0, 0);
        assert_eq!(ret.t1, 300);
        assert_eq!(ret.n, 2);
        Ok(())
    }

    #[test]
    fn test_db_3() -> Result<()> {
        let mut db = init_db();
        let ret = db.range_query((1000, 2000)).unwrap();
        assert_eq!(ret.t0, 1000);
        assert_eq!(ret.t1, 2000);
        assert_eq!(ret.n, 3);

        Ok(())
    }
}
