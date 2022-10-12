mod parade;
mod config;
mod strategy;
use crate::parade::Parade;
use config::Config;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn parade_new() -> JsValue {
    let cfg = Config {
        suits: 6,
        ranks: 11,
        players: 2,
        initial_parade: 6,
        output: "".to_owned(),
        initial_hand_size: 5,
        iters: 0,
        strats: vec![],
    };

    let parade = Parade::new(&cfg, 0);
    JsValue::from_serde(&parade).unwrap()
}

#[wasm_bindgen]
pub fn parade_play(parade: JsValue, card_to_play: usize) -> Vec<JsValue> {
    let mut parade = parade.into_serde::<Parade>().unwrap();
    let ejected = parade.commit(0, card_to_play).unwrap();
    let new_parade = JsValue::from_serde(&parade).unwrap();
    let ejected = JsValue::from_serde(&ejected).unwrap();
    vec![new_parade, ejected]
}

#[wasm_bindgen]
pub fn parade_opponent_play(parade: JsValue) -> Vec<JsValue> {
    let strat = strategy::from_usize(&2_usize);
    let mut parade = parade.into_serde::<Parade>().unwrap();
    let card_to_play = strat.play(&parade, 1);
    let card_played = JsValue::from_serde(&parade.hands[1][card_to_play]).unwrap();
    let ejected = parade.commit(1, card_to_play).unwrap();
    let new_parade = JsValue::from_serde(&parade).unwrap();
    let ejected = JsValue::from_serde(&ejected).unwrap();
    vec![new_parade, ejected, card_played]
}

#[wasm_bindgen]
pub fn parade_test_card(parade: JsValue, i: usize) -> JsValue {
    let parade = parade.into_serde::<Parade>().unwrap();
    let cards = parade.add_to_end(parade.hands[0][i]);
    JsValue::from_serde(&cards).unwrap()
}