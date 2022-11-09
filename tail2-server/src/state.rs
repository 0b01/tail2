use tail2::{calltree::frames::CallTree, dto::FrameDto};

pub struct CurrentCallTree {
    pub ct: CallTree<FrameDto>,
}

impl CurrentCallTree {
    pub fn new() -> Self {
        let ct = CallTree::from_stack(&[FrameDto {..Default::default()}]);
        Self {
            ct,
        }
    }
}