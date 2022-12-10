use duckdb::Result;
use duckdb::Connection;

#[cfg(test)]
mod tests {

    use duckdb::{arrow::datatypes::TimeUnit, types::{ValueRef, Timestamp}};

    use super::*;
    #[test]
    fn test_db() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE foo(x TIMESTAMP)")?;

        {
            let mut app = db.appender("foo")?;
            app.append_row([Timestamp::Second(1)])?;
        }

        let val = db.query_row("SELECT x FROM foo", [], |row| <(i32,)>::try_from(row))?;
        assert_eq!(val, (1000000,));
        Ok(())
    }
}