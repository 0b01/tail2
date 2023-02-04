use indextree::{Arena, NodeId, NodeEdge};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use super::traits::Mergeable;

#[derive(Serialize, Deserialize, Debug, Clone, Default, Eq, PartialEq)]
pub struct CallTreeFrame<T>
where
    T: Clone + Default + Eq + Serialize + Debug,
{
    pub item: T,
    pub total_samples: u64,
    pub self_samples: u64,
}

impl<T> CallTreeFrame<T> 
    where
        T: Clone + Default + Eq + Serialize + Debug
{
    pub fn map<N>(self, f: &mut impl FnMut(T) -> N) -> CallTreeFrame<N>
        where
            N: Clone + Default + Eq + Serialize + Debug
    {
        CallTreeFrame {
            item: f(self.item),
            total_samples: self.total_samples,
            self_samples: self.self_samples,
        }
    }

    pub fn new(item: T, total_samples: u64, self_samples: u64) -> Self {
        Self {
            item,
            total_samples,
            self_samples,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CallTreeInner<T: Clone + Default + Eq + Serialize + Debug> {
    pub arena: Arena<CallTreeFrame<T>>,
    pub root: NodeId,
}

impl<T: Clone + Default + Eq + Serialize + Debug> Default for CallTreeInner<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Default + Eq + Serialize + Debug> CallTreeInner<T> {
    pub fn new() -> Self {
        let mut arena = Arena::new();
        let root = arena.new_node(Default::default());
        Self { arena, root }
    }

    /// create a new call tree from frames
    pub fn from_frames(frames: &[T]) -> Self {
        let mut tree = Self::new();
        let mut prev = tree.root;
        for (i, f) in frames.iter().enumerate() {
            let is_last = i == (frames.len() - 1);
            let self_samples = if is_last { 1 } else { 0 };
            let new_node = tree.arena.new_node(CallTreeFrame {
                item: f.clone(),
                total_samples: 1,
                self_samples,
            });
            prev.append(new_node, &mut tree.arena);
            prev = new_node;
        }

        tree
    }

    /// map from type T to type N
    pub fn map<N>(self, mut f: impl FnMut(T) -> N) -> CallTreeInner<N>
    where
        N: Clone + Default + Eq + Serialize + Debug,
    {
        let arena = self.arena.map(|i|i.map(&mut f));
        CallTreeInner {
            arena,
            root: self.root,
        }
    }

    /// filter call tree, go through every node, if they match f, then add them into the tree, reparent if necessary
    pub fn filter(&self, f: impl Fn(&T) -> bool) -> Self {
        let mut new_tree = Self::new();
        let mut new_parent_stack = vec![(self.root, new_tree.root)];
        let mut traverse = self.root.traverse(&self.arena).skip(1); // skip root

        while let Some(edge) = traverse.next() {
            match edge {
                NodeEdge::Start(node_id) => {
                    let node = self.arena.get(node_id).unwrap();
                    if f(&node.get().item) {
                        let new_node_id = new_tree.arena.new_node(node.get().clone());
                        new_parent_stack.last().unwrap().1.append(new_node_id, &mut new_tree.arena);
                        new_parent_stack.push((node_id, new_node_id));
                    }
                }
                NodeEdge::End(node_id) => {
                    if node_id == new_parent_stack.last().unwrap().0 {
                        let (_, new_node) = new_parent_stack.pop().unwrap();

                        // if new node has no children, set self = total
                        if new_node.children(&new_tree.arena).count() == 0 {
                            let data = new_tree.arena.get_mut(new_node).unwrap().get_mut();
                            data.self_samples = data.total_samples;
                        }
                    }
                }
            }
        }

        new_tree
    }
}

impl<T: Clone + Default + Eq + Serialize + Debug> Mergeable for CallTreeInner<T> {
    /// merge two trees
    /// TODO: skip this merge, add merge_frames functions directly
    /// TODO: better perf
    fn merge(&mut self, other: &CallTreeInner<T>) -> &Self {
        let mut stack = Vec::new();
        stack.push((self.root, other.root));
        while !stack.is_empty() {
            let Some((my_curr, other_curr)) = stack.pop() else { continue };
            let my_children = my_curr.children(&self.arena).collect::<Vec<_>>();
            let other_children = other_curr.children(&other.arena).collect::<Vec<_>>();
            for other_child in other_children {
                let other_frame = other.arena.get(other_child).unwrap().get().clone();
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

        self
    }
}

pub mod serialize {
    use super::*;
    use serde::{ser::SerializeSeq, Serialize, Serializer};

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
            let data = &node.get();
            Node {
                data,
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
            for node in self.first.following_siblings(self.arena) {
                seq.serialize_element(&Node::new(node, self.arena))?;
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
        let mut ct1 = CallTreeInner::from_frames(&[0, 1, 2]);
        let ct2 = CallTreeInner::from_frames(&[5, 6]);
        ct1.merge(&ct2);

        assert_eq!(ct1.root.children(&ct1.arena).count(), 2);

        assert_eq!(ct1.arena.get(
            ct1.root.children(&ct1.arena).nth(0).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(0, 1, 0));

        assert_eq!(ct1.arena.get(
            ct1.root
                .children(&ct1.arena).nth(0).unwrap()
                .children(&ct1.arena).nth(0).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(1, 1, 0));

        assert_eq!(ct1.arena.get(
            ct1.root
                .children(&ct1.arena).nth(0).unwrap()
                .children(&ct1.arena).nth(0).unwrap()
                .children(&ct1.arena).nth(0).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(2, 1, 1));

        assert_eq!(ct1.arena.get(
            ct1.root.children(&ct1.arena).nth(1).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(5, 1, 0));

        assert_eq!(ct1.arena.get(
            ct1.root
                .children(&ct1.arena).nth(1).unwrap()
                .children(&ct1.arena).nth(0).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(6, 1, 1));
    }

    #[test]
    fn test_filter() {
        let ct1 = CallTreeInner::from_frames(&[1, 2, 3, 4, 5]);
        let filtered = ct1.filter(|&n| n % 2 == 0);

        assert_eq!(filtered.arena.get(
            ct1.root.children(&ct1.arena).nth(0).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(2, 1, 0));

        assert_eq!(filtered.arena.get(
            ct1.root
                .children(&ct1.arena).nth(0).unwrap()
                .children(&ct1.arena).nth(0).unwrap()
        ).unwrap().get(), &CallTreeFrame::new(4, 1, 1));
    }
}
