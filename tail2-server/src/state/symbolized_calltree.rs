use std::sync::Arc;

use tail2::{calltree::CallTree, symbolication::elf::SymbolCache, Mergeable, dto::{build_mixed_frames, StackBatchDto}};
use tokio::sync::{Mutex, Notify};

#[derive(Clone)]
pub struct SymbolizedCallTree {
    pub calltree: Arc<Mutex<CallTree>>,
    pub symbols: Arc<Mutex<SymbolCache>>,
}

impl SymbolizedCallTree {
    pub fn new() -> Self {
        let calltree = Arc::new(Mutex::new(CallTree::new()));
        // let _changed = Arc::new(Notify::new());
        let symbols = Arc::new(Mutex::new(SymbolCache::new()));
        Self { calltree, symbols }
    }
}

impl Default for SymbolizedCallTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolizedCallTree {
    pub fn add_stacks(&self, batch: StackBatchDto, notify: Arc<Notify>) {
        let ct_ = Arc::clone(&self.calltree);
        let syms = Arc::clone(&self.symbols);
        tokio::spawn(async move {
            let mut ct = CallTree::new();
            for stack in batch.stacks {
                let mixed_stack = build_mixed_frames(stack, &syms, &batch.modules).await;
                ct.merge(&CallTree::from_stack(&mixed_stack));
            }
            // info!("{:#?}", ct.root.debug_pretty_print(&ct.arena));
            ct_.lock().await.merge(&ct);
            notify.notify_one();
        });
    }
}