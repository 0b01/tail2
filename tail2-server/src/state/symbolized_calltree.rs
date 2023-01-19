use std::sync::Arc;

use tail2::{calltree::CallTree, symbolication::elf::SymbolCache, Mergeable, dto::{StackBatchDto, ModuleMap}};
use tokio::sync::Notify;

pub struct SymbolizedCallTree {
    pub calltree: CallTree,
    pub modules: ModuleMap,
    pub symbols: SymbolCache,
}

impl SymbolizedCallTree {
    pub fn new() -> Self {
        let calltree = CallTree::new();
        let symbols = SymbolCache::new();
        let modules = ModuleMap::new();
        Self { calltree, symbols, modules }
    }
}

impl Default for SymbolizedCallTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolizedCallTree {
    pub fn add_stacks(&mut self, batch: StackBatchDto, notify: Arc<Notify>) {
        for stack in batch.stacks {
            let unsym = stack.mix(&batch.modules, &mut self.modules);
            let sym = unsym
                .into_iter()
                .map(|i| i.symbolize(&mut self.symbols, &mut self.modules))
                .collect::<Vec<_>>();
            let ct = CallTree::from_frames(&sym);
            self.calltree.merge(&ct);
        }
        notify.notify_one();
    }
}