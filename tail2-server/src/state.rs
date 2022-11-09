use std::sync::{Arc, Mutex};

use tail2::{calltree::frames::CallTree, dto::FrameDto};

pub struct CurrentCallTree {
   pub ct: Arc<Mutex<CallTree<FrameDto>>>,
}

impl CurrentCallTree {
    pub fn new() -> Self {
        let ct = CallTree::new();
        Self {
            ct: Arc::new(Mutex::new(ct)),
        }
    }
}