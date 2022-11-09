use indextree::{Arena, NodeId};

pub struct CallTree<T> where T : Default {
    arena: Arena<(T, usize)>,
    root: NodeId,
}

impl<T> CallTree<T> {
    pub fn new() -> Self {
        let arena = &mut Arena::new();
        let root = arena.new_node(Default::default());
        Self {
            arena,
            root,
        }
    }

    pub fn from_stack(&mut self, stack: T) {
        let mut prev = self.root;
        for f in stack {
            let new_node = self.arena.new_node(f);
            prev.append((new_node, 1), &mut self.arena);
            prev = new_node;
        }
    }

    pub fn merge(&mut self, other: &mut CallTree<T>) {
        let mut stack = Vec::new();
        stack.push((self.root, other.root));
        while !stack.is_empty() {
            let (my_curr, other_curr) = stack.pop();

        }
    }
} 

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_merge() {
        let mut ct1 = CallTree::new();
        ct1.from_stack(vec!["a", "b", "c"]);

        let mut ct2 = CallTree::new();
        ct2.from_stack(vec!["a", "b", "c"]);

        ct1.merge(&mut ct2);

        dbg!(ct1);
    }
}