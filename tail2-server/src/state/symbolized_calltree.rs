

use tail2::{calltree::{CallTree, UnsymbolizedCallTree}, symbolication::elf::SymbolCache, Mergeable, dto::{StackBatchDto, ModuleMap}};


pub struct SymbolizedCallTree {
    pub calltree: CallTree,
    pub modules: ModuleMap,
}

impl SymbolizedCallTree {
    pub fn new() -> Self {
        let calltree = CallTree::new();
        let modules = ModuleMap::new();
        Self { calltree, modules }
    }
}

impl Default for SymbolizedCallTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolizedCallTree {
    pub fn add_stack_batch(&mut self, batch: StackBatchDto, symbols: &mut SymbolCache) {
        for stack in batch.stacks {
            let unsym = stack.mix(&batch.modules, &mut self.modules);
            let ct = UnsymbolizedCallTree::from_frames(&unsym);

            let ct = ct.symbolize(symbols, &mut self.modules);

            self.calltree.merge(&ct);
        }
    }
}