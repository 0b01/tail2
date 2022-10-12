mod parade;
mod strategy;
mod config;

use crate::parade::{simulate};
use crate::config::Config;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;
use clap::Parser;
use rayon::prelude::*;

fn main() {
    let cfg = Config::parse();

    let mut wtr = BufWriter::with_capacity(1024, File::create(&cfg.output).unwrap());

    let scores = (0..cfg.iters).into_par_iter().map(|i|{
        let (parade, stats) = simulate(&cfg, i);
        (parade.final_score(), stats)
    }).collect::<Vec<_>>();

    for (score, stats) in scores {
        wtr.write_all(score.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",").as_bytes()).unwrap();
        wtr.write_all(",".as_bytes()).unwrap();
        wtr.write_all(stats.iter().map(|s| s.forced_taking.to_string()).collect::<Vec<_>>().join(",").as_bytes()).unwrap();
        wtr.write_all("\n".as_bytes()).unwrap();
    }

    wtr.flush().unwrap();
}
