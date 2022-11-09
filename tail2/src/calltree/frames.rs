use indextree::{Arena, NodeId};

#[derive(Copy, Default, Eq, Clone, PartialEq)]
pub struct CallTreeFrame {
}

pub struct CallTree<T: Copy + Default + Eq> {
    pub arena: Arena<(T, usize)>,
    pub root: NodeId,
}

impl<T: Copy + Default + Eq> CallTree<T> {
    pub fn new() -> Self {
        let mut arena = Arena::new();
        let root = arena.new_node(Default::default());
        Self {
            arena,
            root,
        }
    }

    /// create a new call tree from stack
    pub fn from_stack(stack: &[T]) -> Self {
        let mut tree = Self::new();
        let mut prev = tree.root;
        for f in stack {
            let new_node = tree.arena.new_node((*f, 1));
            prev.append(new_node, &mut tree.arena);
            prev = new_node;
        }

        tree
    }

    /// merge two trees
    /// TODO: better perf
    pub fn merge(&mut self, other: &CallTree<T>) {
        let mut stack = Vec::new();
        stack.push((self.root, other.root));
        while !stack.is_empty() {
            let Some((my_curr, other_curr)) = stack.pop() else { continue };
            let my_children = my_curr.children(&mut self.arena).collect::<Vec<_>>();
            let other_children = other_curr.children(&other.arena).collect::<Vec<_>>();
            for other_child in other_children {
                let (other_value, other_samples) = *other.arena.get(other_child).unwrap().get();
                let mut found = false;
                for my_child in &my_children {
                    let (my_value, my_samples) = self.arena.get_mut(*my_child).unwrap().get_mut();
                    if *my_value == other_value {
                        found = true;
                        *my_samples += other_samples;
                        stack.push((*my_child, other_child));
                        continue;
                    }
                }

                if !found {
                    let new_node = self.arena.new_node((other_value, other_samples));
                    my_curr.append(new_node, &mut self.arena);
                    stack.push((new_node, other_child));
                }
            }
        }
    }
} 

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_merge() {
        let mut ct1 = CallTree::from_stack(&[0, 1, 2]);
        let ct2 = CallTree::from_stack(&[5, 6]);
        ct1.merge(&ct2);
        dbg!(ct1.root.debug_pretty_print(&ct1.arena));
    }
}