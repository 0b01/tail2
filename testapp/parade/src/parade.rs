use rand::prelude::SliceRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::strategy::from_usize;
use crate::Config;
use rand_chacha::ChaCha8Rng;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Card {
    pub suit: u8,
    pub rank: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Deck {
    cards: Vec<Card>,
    remaining: usize,
}

impl Deck {
    pub fn new(cfg: &Config, seed: usize) -> Self {
        let mut cards = vec![];
        for suit in 0..cfg.suits {
            for rank in 0..cfg.ranks {
                cards.push(Card { suit, rank });
            }
        }

        let mut rng = ChaCha8Rng::seed_from_u64(seed as u64);
        cards.shuffle(&mut rng);

        Self {
            cards,
            remaining: (cfg.suits as usize) * (cfg.ranks as usize),
        }
    }

    pub fn draw(&mut self, n: usize) -> Option<Vec<Card>> {
        if n > self.remaining {
            return None;
        }

        let ret = self.cards.split_off(self.remaining - n);
        self.remaining -= n;
        Some(ret)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Parade {
    pub deck: Deck,
    pub parade: Vec<Card>,
    pub hands: Vec<Vec<Card>>,
    pub boards: Vec<Vec<Card>>,
    pub cfg: Config,
}

impl Parade {
    pub fn new(cfg: &Config, seed: usize) -> Self {
        let mut deck = Deck::new(cfg, seed);
        if deck.remaining < cfg.initial_parade + cfg.players * cfg.initial_hand_size {
            panic!("not enough cards in deck");
        }

        let parade = deck
            .draw(cfg.initial_parade)
            .expect("Unable to setup parade");
        let hands = (0..cfg.players)
            .map(|_| {
                deck.draw(cfg.initial_hand_size)
                    .expect("Unable to draw initial hand")
            })
            .collect();
        let boards = vec![vec![]; cfg.players];
        Self {
            deck,
            parade,
            hands,
            boards,
            cfg: cfg.clone(),
        }
    }

    pub fn add_to_end(&self, card: Card) -> Vec<Card> {
        self.parade
            .iter()
            .rev()
            .skip(card.rank as usize)
            .filter(|c| c.suit == card.suit || c.rank < card.rank)
            .copied()
            .collect()
    }

    pub fn commit(&mut self, player: usize, card_to_play: usize) -> Option<Vec<Card>> {
        let card = self.hands[player][card_to_play];

        // dbg!(card);
        // dbg!("before", &self.parade);
        let mut new_parade = vec![];
        let mut ejected = vec![];
        for (i, c) in self.parade.iter().rev().enumerate() {
            if i < card.rank as usize {
                new_parade.push(*c);
            } else if card.suit == c.suit || c.rank < card.rank {
                ejected.push(*c);
            } else {
                new_parade.push(*c);
            }
        }

        new_parade.reverse();
        new_parade.push(card);
        self.parade = new_parade;

        // dbg!("after", &self.parade, &ejected);

        self.hands[player].remove(card_to_play);
        self.hands[player].extend(self.deck.draw(1)?);
        self.boards[player].extend(ejected.clone());

        Some(ejected)
    }

    fn commit_end_game(&mut self) {
        for player in 0..self.cfg.players {
            self.boards[player].extend(&self.hands[player]);
        }

        self.hands.clear();
    }

    pub fn final_score(&self) -> Vec<usize> {
        let mut suits_count = vec![0_usize; self.cfg.suits as usize];
        for suit in 0..self.cfg.suits {
            let max_player_idx = self
                .boards
                .iter()
                .map(|b| b.iter().filter(|c| c.suit == suit).count())
                .enumerate()
                .min_by_key(|(_idx, count)| *count)
                .map(|(idx, _count)| idx)
                .unwrap();
            suits_count[suit as usize] = max_player_idx;
        }

        let mut ret = vec![0; self.cfg.players];
        (0..self.cfg.players).for_each(|player| {
            let mut score = 0;
            for suit in 0..self.cfg.suits {
                let cards_of_suit = self.boards[player].iter().filter(|c| c.suit == suit);
                score += if suits_count[suit as usize] == player {
                    cards_of_suit.count()
                } else {
                    cards_of_suit.map(|c| c.rank as usize).sum()
                };
            }
            ret[player] = score;
        });

        ret
    }
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub forced_taking: u32,
}

pub fn simulate(cfg: &Config, seed: usize) -> (Parade, Vec<Stats>) {
    let mut parade = Parade::new(cfg, seed);
    let mut stats: Vec<Stats> = vec![Default::default(); cfg.players];
    let strats = match cfg.strats.len() {
        0 => (0..cfg.players).map(|_| from_usize(&0)).collect(),
        1 => (0..cfg.players)
            .map(|_| from_usize(&cfg.strats[0]))
            .collect(),
        _ => cfg.strats.iter().map(from_usize).collect::<Vec<_>>(),
    };

    'outer: while parade.deck.remaining > 0 {
        for player in 0..cfg.players {
            if !strats[player].can_avoid_card(&parade, player) {
                stats[player].forced_taking += 1;
            }

            let card_to_play = strats[player].play(&parade, player);
            if parade.commit(player, card_to_play).is_none() {
                parade.commit_end_game();
                break 'outer;
            }
        }
    }

    (parade, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parade() {
        let cfg = Config {
            suits: 6,
            ranks: 11,
            players: 2,
            initial_parade: 6,
            initial_hand_size: 5,
            strats: vec![],
            output: "".to_owned(),
            iters: 1,
        };

        let mut parade = Parade::new(&cfg, 0);
        parade.parade = vec![
            Card { suit: 0, rank: 0 },
            Card { suit: 1, rank: 0 },
            Card { suit: 2, rank: 0 },
        ];
        parade.hands[0][0] = Card { suit: 0, rank: 1 };
        dbg!(&parade.parade);
        parade.commit(0, 0);
        dbg!(&parade.parade);
    }
}
