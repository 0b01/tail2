use duckdb::Config;
use duckdb::Connection;
use duckdb::OptionalExt;
use duckdb::Result;
use duckdb::params;
use duckdb::types::Timestamp;
use tail2::calltree::CallTree;
use tail2::calltree::inner::CallTreeInner;
use tail2::calltree::inner::CallTreeFrame;

use crate::row::DbRow;
use crate::tile;
pub struct Tail2DB {
    pub path: String,
    pub conn: Connection,
    last_ts: i64,
    /// order of magnitude augmented tree node for fast call tree merge
    scales: Vec<i64>,
}

impl Tail2DB {
    pub fn new(db_name: &str) -> Self {
        let path = format!("/home/g/tail2/db/{}.t2db", db_name);
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
            .execute_batch(&format!(include_str!("./sql/create_table.sql"), 1)).unwrap();
        for i in self.scales.iter() {
            self.conn
                .execute_batch(&format!(include_str!("./sql/create_table.sql"), i)).unwrap();
        }
    }

    pub fn insert(&mut self, data: Vec<DbRow>) -> Result<()> {
        let mut app = self.conn.appender("samples_1").unwrap();
        for row in data {
            let ct_bytes = bincode::serialize(&row.ct).unwrap();
            app.append_row(params![Timestamp::Millisecond(row.ts), ct_bytes, row.n])?;
        }

        app.flush();

        Ok(())
    }

    pub(crate) fn refresh_cache(&mut self) -> Result<()> {
        let latest_ts: i64 = self.conn.query_row("SELECT ts FROM samples_1 ORDER BY ts DESC LIMIT 1", [], |r| r.get(0)).map(|i: i64| i / 1000)?;
        let range = (self.last_ts, latest_ts);
        self.refresh_range(range)?;
        self.last_ts = latest_ts;

        Ok(())
    }

    pub fn get_range(&mut self, range: (i64, i64)) -> Result<(CallTree, i32)> {
        let mut tiles = tile::tile(range, self.scales.as_slice());

        let mut trees = vec![];

        if tiles.is_empty() {
            trees.extend(self.query_1(range.0, range.1)?);
        } else {
            for (scale, start) in tiles {
                trees.push(self.populate_rec(scale, start)?);
            }
        }

        let merged = trees
            .iter()
            .fold((CallTreeInner::new(), 0),
                |mut acc, x| (acc.0.merge(&x.0), acc.1 + x.1));

        return Ok(merged);
    }

    fn refresh_range(&mut self, range: (i64, i64)) -> Result<()> {
        let tiles = tile::tile(range, self.scales.as_slice());

        for (scale, start) in tiles {
            self.populate_rec(scale, start)?;
        }

        Ok(())
    }

    /// query samples_1 the most granular table
    fn query_1(&mut self, t0: i64, t1: i64) -> Result<Vec<(CallTree, i32)>> {
        let mut ret = vec![];
        let mut stmt = self.conn.prepare("SELECT ct, n FROM samples_1 WHERE ts >= (?) AND ts < (?)")?;
        let mut rows = stmt.query_map([
            Timestamp::Millisecond(t0),
            Timestamp::Millisecond(t1)],
            |row| { Ok((row.get::<_, Vec<_>>(0)?, row.get(1)?))})?;
        while let Some(row) = rows.next() {
            let (ct_bytes, n) = row?;
            let ct = bincode::deserialize(&ct_bytes).unwrap();
            ret.push((ct, n));
        }

        Ok(ret)
    }

    fn populate_rec(&mut self, scale: i64, start: i64) -> Result<(CallTree, i32)> {
        // dbg!((scale, start));
        let ret: Option<(Vec<u8>, i32)> = self.conn.query_row(
            &format!("SELECT ct, n FROM samples_{} WHERE ts = epoch_ms((?))", scale),
            [start + scale],
            |row| Ok((row.get(0)?, row.get(1)?)) ).optional()?;

        if let Some((ct_bytes, n)) = ret {
            let ct = bincode::deserialize(&ct_bytes).unwrap();
            return Ok((ct, n));
        }

        let mut next_results = vec![];
        if scale <= *self.scales.last().unwrap() {
            next_results.extend(self.query_1(start, start + scale)?);
        } else {
            let next_scale = scale / 10;
            for next_start in (start..(start+scale)).step_by(next_scale as usize) {
                next_results.push(self.populate_rec(next_scale, next_start)?);
            }
        }

        let merged = next_results
            .iter()
            .fold((CallTreeInner::new(), 0),
                |mut acc, x| (acc.0.merge(&x.0), acc.1 + x.1));

        let mut stmt = self.conn.prepare(&format!("INSERT INTO samples_{} VALUES (?, ?, ?)", scale))?;
        stmt.execute(params![Timestamp::Millisecond(start + scale), bincode::serialize(&merged.0).unwrap(), merged.1]).unwrap();

        return Ok(merged);
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_db() -> Result<()> {
        let mut db = Tail2DB::new("test");
        db.insert([100, 150, 950, 1000, 1050, 1900, 2150, 3001].into_iter().map(|ts| DbRow {
            ts,
            ct: CallTree::new(),
            n: 1,
        }).collect()).unwrap();

        let ret = db.get_range((0, 10_000)).unwrap().1;
        assert_eq!(ret, 8);

        let ret = db.get_range((0, 1000)).unwrap().1;
        assert_eq!(ret, 3);

        let ret = db.get_range((0, 300)).unwrap().1;
        assert_eq!(ret, 2);

        let ret = db.get_range((1000, 2000)).unwrap().1;
        assert_eq!(ret, 3);

        Ok(())
    }
}
