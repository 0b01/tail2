use std::collections::HashMap;

use anyhow::Result;
use arrow_array::builder::StructBuilder;
use arrow_schema::{Field, DataType};

const S: u64 = 1_000;
const S10: u64 = 10 * S;
const M: u64 = 60 * S;
const M10: u64 = 10 * S;
const H: u64 = 60 * M;
const HD: u64 = 12 * H;
const D: u64 = 24 * H;
const W: u64 = 7 * H;
const MON: u64 = 4 * W;
macro_rules! lit_and_ms {
    ($lit:expr) => {
        (stringify!($lit), $lit)
    };
}
const SCALES: [(&'static str, u64); 9] = [
    lit_and_ms!(0),
    lit_and_ms!(S),
    lit_and_ms!(S10),
    lit_and_ms!(M),
    lit_and_ms!(M10),
    lit_and_ms!(H),
    lit_and_ms!(HD),
    lit_and_ms!(D),
    lit_and_ms!(W),
    lit_and_ms!(MON),
];

pub struct Database {
    pub name: String,
    builders: Vec<(u64, StructBuilder)>,
    lasts: Vec<(u64, i32)>,
}

impl Database {
    pub fn new(name: &str) -> Result<Self> {
        // create a struct array for each scale
        let builders = SCALES
            .map(|(t, interval)| {
                    let fields = vec![
                        Field::new("ts", DataType::Date64, false),
                        Field::new(&format!("ct_{}", t), DataType::Binary, true
                    )];
                    let builder = StructBuilder::from_fields(fields, 1024);
                    (interval, builder)
                })
            .into_iter()
            .collect();

        let lasts = SCALES
            .map(|(t, i)|(i, 0))
            .into_iter()
            .collect();
        Ok(Self {
            name: name.to_owned(),
            lasts,
            builders,
        })
    }

    pub fn insert(&mut self, ts: u64, call_tree: ()) {
        // check each scale, if time has passed, we calculate last
        for ((int, arr), (_, last)) in self.builders.iter().zip(self.lasts) {
            // if last 
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     #[tokio::test]
//     async fn test_db_new() {
//         Database::new("default").await.unwrap();
//     }
// }