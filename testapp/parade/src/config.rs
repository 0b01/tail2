use clap::Parser;
use serde::{Serialize, Deserialize};

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[clap(author, version, about, long_about = None)]
pub struct Config {
    /// number of suits
    #[clap(long, default_value_t = 6)]
    pub suits: u8,

    /// number of ranks per suit
    #[clap(long, default_value_t = 11)]
    pub ranks: u8,

    /// number of players
    #[clap(long, default_value_t = 2)]
    pub players: usize,

    /// output file
    #[clap(short, long, default_value = "output.csv")]
    pub output: String,

    /// initial parade length
    #[clap(long, default_value_t = 6)]
    pub initial_parade: usize,

    /// initial hand size
    #[clap(long, default_value_t = 5)]
    pub initial_hand_size: usize,

    /// number of iterations
    #[clap(short, long, default_value_t = 10000)]
    pub iters: usize,

    pub strats: Vec<usize>,
}
