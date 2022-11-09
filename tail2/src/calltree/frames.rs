use indextree::{Arena, NodeId};
use serde::Serialize;

#[derive(Serialize, Debug, Copy, Default, Eq, Clone, PartialEq)]
pub struct CallTreeFrame<T> where T: Copy + Default + Eq + Serialize {
    pub item: T,
    pub total_samples: usize,
    pub self_samples: usize,
}

pub struct CallTree<T: Copy + Default + Eq + Serialize> {
    pub arena: Arena<CallTreeFrame<T>>,
    pub root: NodeId,
}

impl<T: Copy + Default + Eq + Serialize> CallTree<T> {
    pub fn new() -> Self {
        let mut arena = Arena::new();
        let root = arena.new_node(Default::default());
        Self { arena, root }
    }

    /// create a new call tree from stack
    pub fn from_stack(stack: &[T]) -> Self {
        let mut tree = Self::new();
        let mut prev = tree.root;
        for (i, f) in stack.iter().enumerate() {
            let is_last = i == (stack.len() - 1);
            let self_samples = if is_last { 1 } else { 0 };
            let new_node = tree.arena.new_node(CallTreeFrame{ item: *f, total_samples: 1, self_samples });
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
                let other_frame = *other.arena.get(other_child).unwrap().get();
                let mut found = false;
                for my_child in &my_children {
                    let my_frame = self.arena.get_mut(*my_child).unwrap().get_mut();
                    if my_frame.item == other_frame.item {
                        found = true;
                        my_frame.total_samples += other_frame.total_samples;
                        my_frame.self_samples += other_frame.self_samples;
                        stack.push((*my_child, other_child));
                        continue;
                    }
                }

                if !found {
                    let new_node = self.arena.new_node(other_frame);
                    my_curr.append(new_node, &mut self.arena);
                    stack.push((new_node, other_child));
                }
            }
        }
    }
}

pub mod serialize {
    use super::*;
    use serde::{Serialize, Serializer, ser::SerializeSeq};

    /// Convenience wrapper struct for serializing a node and its descendants.
    #[derive(Serialize)]
    pub struct Node<'a, T: Serialize> {
        #[serde(flatten)]
        data: &'a T,
        #[serde(skip_serializing_if = "Option::is_none")]
        children: Option<SiblingNodes<'a, T>>,
    }

    impl<'a, T: Serialize> Node<'a, T> {
        pub fn new(id: NodeId, arena: &'a Arena<T>) -> Self {
            let node = &arena[id];
            Node {
                data: &node.get(),
                children: node
                    .first_child()
                    .map(|first| SiblingNodes::new(first, arena)),
            }
        }
    }

    /// Convenience wrapper struct for serializing a node and its siblings.
    pub struct SiblingNodes<'a, T: Serialize> {
        first: NodeId,
        arena: &'a Arena<T>,
    }

    impl<'a, T: Serialize> SiblingNodes<'a, T> {
        pub fn new(id: NodeId, arena: &'a Arena<T>) -> Self {
            SiblingNodes { first: id, arena }
        }
    }

    impl<T: Serialize> Serialize for SiblingNodes<'_, T> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(None)?;
            for node in self.first.following_siblings(&self.arena) {
                seq.serialize_element(&Node::new(node, &self.arena))?;
            }
            seq.end()
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
