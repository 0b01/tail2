use crate::parade::Parade;

pub fn from_usize(s: &usize) -> Box<dyn Strategy> {
    match s {
        0 => Box::new(crate::strategy::FirstCard) as Box<dyn Strategy>,
        1 => Box::new(crate::strategy::TakeMin) as Box<dyn Strategy>,
        2 => Box::new(crate::strategy::TakeSmallCardsVoluntarily) as Box<dyn Strategy>,
        _ => Box::new(crate::strategy::TakeMin) as Box<dyn Strategy>,
    }
}

pub trait Strategy {
    fn play(&self, game: &Parade, player: usize) -> usize;
    fn can_avoid_card(&self, parade: &Parade, player: usize) -> bool {
        let hand = &parade.hands[player];
        hand.iter().any(|c| parade.add_to_end(*c).is_empty())
    }
}

pub struct FirstCard;
impl Strategy for FirstCard {
    fn play(&self, _parade: &Parade, _player: usize) -> usize {
        0
    }
}

pub struct TakeMin;
impl Strategy for TakeMin {
    fn play(&self, parade: &Parade, player: usize) -> usize {
        let hand = &parade.hands[player];
        hand.iter()
            .enumerate()
            .min_by_key(|(_, c)| {
                parade
                    .add_to_end(**c)
                    .iter()
                    .map(|c| c.rank as i32)
                    .sum::<i32>()
            })
            .map(|(idx, _)| idx)
            .unwrap()
    }
}

pub struct TakeSmallCardsVoluntarily;
impl Strategy for TakeSmallCardsVoluntarily {
    fn play(&self, parade: &Parade, player: usize) -> usize {
        let hand = &parade.hands[player];
        hand.iter()
            .enumerate()
            .min_by_key(|(_, c)| {
                let ejected = parade.add_to_end(**c);
                if ejected.iter().all(|c| c.rank < 2) {
                    -10000
                } else {
                    ejected.iter().map(|c| c.rank as i32).sum::<i32>()
                }
            })
            .map(|(idx, _)| idx)
            .unwrap()
    }
}
