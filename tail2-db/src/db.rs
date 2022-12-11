use duckdb::Config;
use duckdb::Connection;
use duckdb::OptionalExt;
use duckdb::Result;
use duckdb::params;
use duckdb::types::Timestamp;
use tail2::calltree::CallTree;
use tail2::calltree::inner::CallTreeInner;
use tail2::calltree::inner::CallTreeFrame;

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
            .execute_batch(&format!(include_str!("./sql/create_table.sql"), 1));
        for i in self.scales.iter() {
            self.conn
                .execute_batch(&format!(include_str!("./sql/create_table.sql"), i));
        }
    }

    pub(crate) fn insert(&mut self, data: &[i64]) {
        let mut app = self.conn.appender("samples_1").unwrap();
        for d in data {
            let ct = CallTree::new();
            let ct_bytes = bincode::serialize(&ct).unwrap();
            app.append_row(params![Timestamp::Millisecond(*d), ct_bytes, 1]).unwrap();
        }
        app.flush()
    }

    pub(crate) fn refresh_cache(&mut self) -> Result<()> {
        let latest_ts: i64 = self.conn.query_row("SELECT ts FROM samples_1 ORDER BY ts DESC LIMIT 1", [], |r| r.get(0)).map(|i: i64| i / 1000)?;
        let range = (self.last_ts, latest_ts);
        self.refresh_range(range)?;
        self.last_ts = latest_ts;

        Ok(())
    }

    fn refresh_range(&mut self, range: (i64, i64)) -> Result<()> {
        let tiles = tile::tile(range, self.scales.as_slice());

        for (scale, start) in tiles {
            let merged = self.populate(scale, start).unwrap();
        }

        Ok(())
    }

    fn populate(&mut self, scale: i64, start: i64) -> Result<(CallTree, i32)> {
        let ret: Option<(Vec<u8>, i32)> = self.conn.query_row(
            &format!("SELECT ct, n FROM samples_{} WHERE ts = (?)", scale),
            [start],
            |row| Ok((row.get(0)?, row.get(1)?)) ).optional()?;

        if let Some((ct_bytes, n)) = ret {
            let ct = bincode::deserialize(&ct_bytes).unwrap();
            return Ok((ct, n));
        }

        let mut next_results = vec![];
        if scale == *self.scales.last().unwrap() {
            let mut stmt = self.conn.prepare("SELECT ct, n FROM samples_1 WHERE ts >= (?) AND ts < (?)")?;
            let mut rows = stmt.query_map([Timestamp::Millisecond(start), Timestamp::Millisecond(start + scale)], |row| { Ok((row.get::<_, Vec<_>>(0)?, row.get(1)?))})?;
            while let Some(row) = rows.next() {
                let (ct_bytes, n) = row?;
                let ct = bincode::deserialize(&ct_bytes).unwrap();
                next_results.push((ct, n));
            }
        } else {
            let next_scale = scale / 10;
            for next_start in (start..(start+scale)).step_by(next_scale as usize) {
                next_results.push(self.populate(next_start, next_scale)?);
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
        db.insert(&[100, 150, 950, 1000, 1050, 1900, 2150, 3001]);
        db.refresh_cache().unwrap();
        Ok(())
    }
}
