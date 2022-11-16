use ruzstd::StreamingDecoder;
use sqlx::ConnectOptions;
use anyhow::Result;
use sqlx::sqlite::SqliteConnectOptions;
use std::{str::{FromStr, from_utf8}, fs::File, io::{BufReader, BufRead, Cursor, Read}};
use ar::Archive;

#[tokio::main]
async fn main() -> Result<()> {
    let mut lines = BufReader::new(File::open("out.list")?).lines();
    while let Some(Ok(url)) = lines.next() {

        let mut conn = SqliteConnectOptions::from_str("sqlite://syms.db")?.connect().await?;
        let complete = sqlx::query!("
            SELECT complete FROM url WHERE url = ?;
        ", url).fetch_one(&mut conn).await;

        if complete.is_ok() && complete.unwrap().complete.unwrap_or_default() > 0 {
            println!("skipping {}", url);
            continue;
        }

        sqlx::query!("
            INSERT INTO url(url, complete) VALUES(?, 1);
        ", url).execute(&mut conn).await.unwrap();

        fetch_url(&url).await.unwrap();
    }

    Ok(())
}

macro_rules! skip_fail {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                // dbg!(e);
                continue;
            }
        }
    };
}


async fn fetch_url(url: &str) -> Result<()> {
    dbg!(url);
    let response = reqwest::get(url).await?;
    let content = Cursor::new(response.bytes().await?);
    let mut archive = Archive::new(content);
    while let Some(entry_result) = archive.next_entry() {
        let mut entry = skip_fail!(entry_result);
        let fname = skip_fail!(from_utf8(entry.header().identifier())).to_owned();
        if fname != "data.tar.zst" { continue }
        let mut bytes = Vec::new();
        skip_fail!(entry.read_to_end(&mut bytes));

        let mut dec = skip_fail!(StreamingDecoder::new(Cursor::new(bytes)));
        let mut decoded = vec![];
        dec.read_to_end(&mut decoded).unwrap();

        let mut tar_archive = tar::Archive::new(Cursor::new(decoded));
        let entries = skip_fail!(tar_archive.entries());
        for entry in entries {
            let mut entry = skip_fail!(entry);
            let fname = skip_fail!(entry.path()).as_os_str().to_str().unwrap_or_default().to_owned();
            // dbg!(&fname);
            let mut bytes = vec![];
            entry.read_to_end(&mut bytes);
            let obj = skip_fail!(ElfObject::parse(&bytes));
            skip_fail!(process_file(url, &fname, obj).await);
        }
    }

    Ok(())
}

async fn process_file<'a, 'b, 'c>(url: &'a str, fname: &'b str, obj: ElfObject<'c>) -> Result<()> {
    let mut conn = SqliteConnectOptions::from_str("sqlite://syms.db")?.connect().await?;
    // conn.fetch::<u32>("INSERT INTO url(url) VALUES (?) RETURNING id").await.unwrap();
    let url_id = sqlx::query!("
        INSERT OR IGNORE INTO url(url, complete) VALUES (?, 0);
        SELECT id FROM url WHERE url = ?;
    ", url, url).fetch_one(&mut conn).await.unwrap().id;
    // dbg!((fname, url_id));

    let arch = obj.arch() as i32;
    let kind = obj.kind() as i32;
    let debug_id = obj.debug_id().to_string();

    let file_id = sqlx::query!("
        INSERT OR IGNORE INTO file(url_id, path, arch, kind, debug_id) VALUES (?, ?, ?, ?, ?);
        SELECT id FROM file WHERE PATH = ? AND url_id = ?;
    ", url_id, fname, arch, kind, debug_id, fname, url_id).fetch_one(&mut conn).await.unwrap().id;

    for sym in obj.symbol_map() {
        let offset = sym.address as i32;
        let symbol = sym.name().unwrap_or_default();
        let demangled = demangle(symbol).to_string();
        sqlx::query!("
            INSERT OR IGNORE INTO symbols(offset, symbol, demangled, file_id) VALUES (?, ?, ?, ?);
            SELECT id FROM symbols WHERE file_id = ? AND offset = ?
        ", offset, symbol, demangled, file_id, file_id, offset).fetch_one(&mut conn).await.unwrap().id;
    }

    sqlx::query!("
        UPDATE url SET complete = 1 WHERE url = ?;
    ", url).execute(&mut conn).await.unwrap();

    Ok(())
}
